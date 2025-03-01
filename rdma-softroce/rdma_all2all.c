/***************************************************************************
 * rdma_all2all_full.c
 *
 * A "full" all-to-all RDMA Send/Recv example: each rank both posts receives
 * for messages from all other ranks AND sends a message to all other ranks.
 *
 * Compile:
 *    gcc -Wall -o rdma_all2all_full rdma_all2all_full.c -l ibverbs
 *
 * Usage (on each node):
 *    ./rdma_all2all_full <my_rank> <N>
 *
 * For example, with 3 nodes:
 *    # Node 0 at IP 192.168.1.153
 *    ./rdma_all2all_full 0 3
 *    # Node 1 at IP 192.168.1.212
 *    ./rdma_all2all_full 1 3
 *    # Node 2 at IP 192.168.1.154
 *    ./rdma_all2all_full 2 3
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <infiniband/verbs.h>

#define MAX_NODES       16
#define TCP_PORT        12345     // out-of-band TCP port
#define TEST_MSG_SIZE   64        // size of test message

// Fill in real IPs for your nodes' ranks:
static const char *ip_list[MAX_NODES] = {
    "192.168.1.153", // rank 0
    "192.168.1.212", // rank 1
    "192.168.1.154", // rank 2
    // ...
};

struct qp_info {
    uint32_t qp_num;
    uint16_t lid;      // For IB. 0 if RoCE
    uint8_t  gid[16];  // GID for RoCE or global IB
    uint32_t rkey;     // Remote key
    uint64_t vaddr;    // Remote virtual addr
};

struct peer_conn {
    int sockfd;
    struct ibv_qp *qp;
};

//--------------------------------------------------------------------------
// create_listen_socket: opens a TCP socket and listens on TCP_PORT
//--------------------------------------------------------------------------
static int create_listen_socket(void)
{
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        exit(1);
    }
    int optval = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_port        = htons(TCP_PORT);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        exit(1);
    }
    if (listen(listen_fd, 8) < 0) {
        perror("listen");
        exit(1);
    }
    return listen_fd;
}

//--------------------------------------------------------------------------
// accept_connection: accept a single incoming TCP connection
//--------------------------------------------------------------------------
static int accept_connection(int listen_fd)
{
    struct sockaddr_in cli_addr;
    socklen_t clilen = sizeof(cli_addr);
    int newfd = accept(listen_fd, (struct sockaddr *)&cli_addr, &clilen);
    if (newfd < 0) {
        perror("accept");
        exit(1);
    }
    return newfd;
}

//--------------------------------------------------------------------------
// connect_to_peer: connect via TCP to the given IP on TCP_PORT
//--------------------------------------------------------------------------
static int connect_to_peer(const char *ip_str)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(TCP_PORT);

    if (inet_pton(AF_INET, ip_str, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(1);
    }
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        exit(1);
    }
    return sockfd;
}

//--------------------------------------------------------------------------
// tcp_sendn / tcp_recvn: send/recv exactly 'len' bytes via the socket
//--------------------------------------------------------------------------
static int tcp_sendn(int sockfd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = send(sockfd, p, remaining, 0);
        if (n <= 0) {
            return -1;
        }
        p += n;
        remaining -= n;
    }
    return 0;
}

static int tcp_recvn(int sockfd, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = recv(sockfd, p, remaining, MSG_WAITALL);
        if (n <= 0) {
            return -1;
        }
        p += n;
        remaining -= n;
    }
    return 0;
}

//--------------------------------------------------------------------------
// setup_rdma_qp_for_peer: create QP, exchange info, go INIT->RTR->RTS
//--------------------------------------------------------------------------
static struct ibv_qp* setup_rdma_qp_for_peer(
    int sockfd,
    struct ibv_context *ctx,
    struct ibv_pd *pd,
    struct ibv_cq *cq,
    struct ibv_mr *mr,
    uint8_t port_num,
    int gid_index
)
{
    // 1) Create QP
    struct ibv_qp_init_attr qp_init_attr = {
        .send_cq = cq,
        .recv_cq = cq,
        .cap = {
            .max_send_wr = 8,
            .max_recv_wr = 8,
            .max_send_sge = 1,
            .max_recv_sge = 1,
        },
        .qp_type = IBV_QPT_RC,
        .sq_sig_all = 1
    };
    struct ibv_qp *qp = ibv_create_qp(pd, &qp_init_attr);
    if (!qp) {
        perror("ibv_create_qp");
        exit(1);
    }

    // 2) QP: RESET -> INIT
    {
        struct ibv_qp_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.qp_state        = IBV_QPS_INIT;
        attr.port_num        = port_num;
        attr.pkey_index      = 0;
        attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE |
                               IBV_ACCESS_REMOTE_READ  |
                               IBV_ACCESS_REMOTE_WRITE;

        int flags = IBV_QP_STATE | IBV_QP_PORT | IBV_QP_PKEY_INDEX | IBV_QP_ACCESS_FLAGS;
        if (ibv_modify_qp(qp, &attr, flags)) {
            perror("modify QP to INIT");
            exit(1);
        }
    }

    // 3) Exchange local/remote QP info via socket
    struct qp_info local_qpinfo, remote_qpinfo;
    memset(&local_qpinfo, 0, sizeof(local_qpinfo));
    memset(&remote_qpinfo, 0, sizeof(remote_qpinfo));

    // Check if link_layer == Ethernet -> RoCE
    struct ibv_port_attr port_attr;
    if (ibv_query_port(ctx, port_num, &port_attr)) {
        perror("ibv_query_port");
        exit(1);
    }
    int is_roce = (port_attr.link_layer == IBV_LINK_LAYER_ETHERNET);

    // Query local GID
    union ibv_gid my_gid;
    memset(&my_gid, 0, sizeof(my_gid));
    if (ibv_query_gid(ctx, port_num, gid_index, &my_gid)) {
        perror("ibv_query_gid");
        exit(1);
    }

    local_qpinfo.qp_num = qp->qp_num;
    local_qpinfo.rkey   = mr->rkey;
    local_qpinfo.vaddr  = (uintptr_t)mr->addr;
    if (is_roce) {
        local_qpinfo.lid = 0;
    } else {
        local_qpinfo.lid = port_attr.lid;
    }
    memcpy(local_qpinfo.gid, my_gid.raw, 16);

    // Send local info
    if (tcp_sendn(sockfd, &local_qpinfo, sizeof(local_qpinfo)) < 0) {
        fprintf(stderr, "tcp_sendn failed\n");
        exit(1);
    }
    // Receive remote info
    if (tcp_recvn(sockfd, &remote_qpinfo, sizeof(remote_qpinfo)) < 0) {
        fprintf(stderr, "tcp_recvn failed\n");
        exit(1);
    }

    // 4) QP: INIT -> RTR
    {
        struct ibv_qp_attr attr;
        memset(&attr, 0, sizeof(attr));

        attr.qp_state           = IBV_QPS_RTR;
        attr.path_mtu           = IBV_MTU_256;
        attr.dest_qp_num        = remote_qpinfo.qp_num;
        attr.rq_psn             = 0;
        attr.max_dest_rd_atomic = 1;
        attr.min_rnr_timer      = 12;

        attr.ah_attr.port_num      = port_num;
        attr.ah_attr.sl            = 0;
        attr.ah_attr.src_path_bits = 0;

        if (is_roce) {
            attr.ah_attr.is_global = 1;
            attr.ah_attr.dlid      = 0;
            memcpy(attr.ah_attr.grh.dgid.raw, remote_qpinfo.gid, 16);
            attr.ah_attr.grh.sgid_index = gid_index;
            attr.ah_attr.grh.hop_limit  = 64;
        } else {
            attr.ah_attr.is_global = 0;
            attr.ah_attr.dlid      = remote_qpinfo.lid;
        }

        int flags = IBV_QP_STATE      | IBV_QP_AV       | IBV_QP_PATH_MTU   |
                    IBV_QP_DEST_QPN   | IBV_QP_RQ_PSN   | IBV_QP_MAX_DEST_RD_ATOMIC |
                    IBV_QP_MIN_RNR_TIMER;

        if (ibv_modify_qp(qp, &attr, flags)) {
            perror("modify QP to RTR");
            exit(1);
        }
    }

    // 5) QP: RTR -> RTS
    {
        struct ibv_qp_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.qp_state      = IBV_QPS_RTS;
        attr.sq_psn        = 0;
        attr.timeout       = 14;
        attr.retry_cnt     = 7;
        attr.rnr_retry     = 7;
        attr.max_rd_atomic = 1;

        int flags = IBV_QP_STATE | IBV_QP_SQ_PSN | IBV_QP_TIMEOUT |
                    IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC;

        if (ibv_modify_qp(qp, &attr, flags)) {
            perror("modify QP to RTS");
            exit(1);
        }
    }

    return qp; // ready to send/receive
}

//--------------------------------------------------------------------------
// main: all-to-all among ranks [0..N-1], each rank sends to every other rank
//--------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <my_rank> <N>\n", argv[0]);
        return 1;
    }
    int my_rank = atoi(argv[1]);
    int N       = atoi(argv[2]);
    if (my_rank < 0 || my_rank >= N) {
        fprintf(stderr, "Invalid rank %d for N=%d\n", my_rank, N);
        return 1;
    }

    printf("Running FULL all-to-all RDMA. My rank=%d, N=%d\n", my_rank, N);

    // 1) Open RDMA device, PD, CQ
    int num_devs = 0;
    struct ibv_device **dev_list = ibv_get_device_list(&num_devs);
    if (!dev_list || num_devs == 0) {
        fprintf(stderr, "No RDMA devices found.\n");
        return 1;
    }
    // Just pick first device
    struct ibv_context *ctx = ibv_open_device(dev_list[0]);
    ibv_free_device_list(dev_list);
    if (!ctx) {
        fprintf(stderr, "ibv_open_device failed.\n");
        return 1;
    }
    struct ibv_pd *pd = ibv_alloc_pd(ctx);
    if (!pd) {
        perror("ibv_alloc_pd");
        return 1;
    }
    struct ibv_cq *cq = ibv_create_cq(ctx, 64, NULL, NULL, 0);
    if (!cq) {
        perror("ibv_create_cq");
        return 1;
    }

    // 2) Register memory
    char *buf = malloc(TEST_MSG_SIZE);
    memset(buf, 0, TEST_MSG_SIZE);
    struct ibv_mr *mr = ibv_reg_mr(pd, buf, TEST_MSG_SIZE,
                                   IBV_ACCESS_LOCAL_WRITE |
                                   IBV_ACCESS_REMOTE_WRITE |
                                   IBV_ACCESS_REMOTE_READ);
    if (!mr) {
        perror("ibv_reg_mr");
        return 1;
    }
    printf("Rank %d: allocated test buffer at %p\n", my_rank, buf);

    // 3) Create a listening socket for peers with rank < my_rank
    int listen_fd = create_listen_socket();

    // We'll store the QP/sock info for each peer
    struct peer_conn peers[MAX_NODES];
    memset(peers, 0, sizeof(peers));

    // 4) Connect QPs
    uint8_t port_num = 1;   // typically 1 for RoCE or IB
    int gid_index    = 1;   // or 0, depending on which GID is valid

    for (int i = 0; i < N; i++) {
        if (i == my_rank) continue;
        int sockfd;
        if (i < my_rank) {
            // accept from lower rank
            sockfd = accept_connection(listen_fd);
            printf("Rank %d: accepted connection from rank %d\n", my_rank, i);
        } else {
            // connect to higher rank
            sockfd = connect_to_peer(ip_list[i]);
            printf("Rank %d: connected to rank %d (%s)\n", my_rank, i, ip_list[i]);
        }
        struct ibv_qp *qp = setup_rdma_qp_for_peer(sockfd, ctx, pd, cq, mr, port_num, gid_index);
        peers[i].sockfd = sockfd;
        peers[i].qp     = qp;
    }

    //--------------------------------------------------------------------------
    // 5) Post (N-1) receives on EVERY rank
    //    Each rank expects 1 message from each other rank.
    //--------------------------------------------------------------------------
    for (int i = 0; i < N; i++) {
        if (i == my_rank) continue;
        if (!peers[i].qp) continue;

        // For demonstration, we post exactly 1 receive for each peer
        struct ibv_sge sg;
        memset(&sg, 0, sizeof(sg));
        sg.addr   = (uintptr_t)buf;
        sg.length = TEST_MSG_SIZE;
        sg.lkey   = mr->lkey;

        struct ibv_recv_wr rr, *bad_rr = NULL;
        memset(&rr, 0, sizeof(rr));
        rr.wr_id   = (uint64_t)i;  // store peer index in wr_id
        rr.sg_list = &sg;
        rr.num_sge = 1;

        if (ibv_post_recv(peers[i].qp, &rr, &bad_rr)) {
            perror("ibv_post_recv");
        } else {
            printf("Rank %d: posted RECV from peer %d\n", my_rank, i);
        }
    }

    //--------------------------------------------------------------------------
    // 6) Wait a bit, then EVERY rank sends (N-1) messages
    //--------------------------------------------------------------------------
    sleep(3); // let peers post receives
    for (int i = 0; i < N; i++) {
        if (i == my_rank) continue;
        if (!peers[i].qp) continue;

        snprintf(buf, TEST_MSG_SIZE, "Hello from rank %d -> rank %d", my_rank, i);

        struct ibv_sge sg;
        memset(&sg, 0, sizeof(sg));
        sg.addr   = (uintptr_t)buf;
        sg.length = TEST_MSG_SIZE;
        sg.lkey   = mr->lkey;

        struct ibv_send_wr wr, *bad_wr = NULL;
        memset(&wr, 0, sizeof(wr));
        wr.wr_id      = 100 + i; // arbitrary
        wr.opcode     = IBV_WR_SEND;
        wr.sg_list    = &sg;
        wr.num_sge    = 1;
        wr.send_flags = IBV_SEND_SIGNALED;

        if (ibv_post_send(peers[i].qp, &wr, &bad_wr)) {
            perror("ibv_post_send");
        } else {
            printf("Rank %d: posted SEND to rank %d\n", my_rank, i);
        }
    }

    //--------------------------------------------------------------------------
    // 7) Poll completions until we've received (N-1) messages
    //--------------------------------------------------------------------------
    int num_recvs_needed = N - 1;  // 1 message from each other rank
    int num_recvs_done   = 0;

    while (num_recvs_done < num_recvs_needed) {
        struct ibv_wc wc;
        int ne = ibv_poll_cq(cq, 1, &wc);
        if (ne < 0) {
            fprintf(stderr, "Error polling CQ\n");
            break;
        } else if (ne == 0) {
            // no completions
            continue;
        } else {
            if (wc.status != IBV_WC_SUCCESS) {
                fprintf(stderr, "CQ error: %s\n", ibv_wc_status_str(wc.status));
                break;
            }
            if (wc.opcode == IBV_WC_RECV) {
                printf("Rank %d: RECV from wr_id=%lu => '%s'\n",
                       my_rank, wc.wr_id, buf);
                num_recvs_done++;
            } else if (wc.opcode == IBV_WC_SEND) {
                // If you also care about send completions, handle it here
                printf("Rank %d: SEND completed wr_id=%lu\n", my_rank, wc.wr_id);
            } else {
                printf("Rank %d: got completion opcode=%d\n", my_rank, wc.opcode);
            }
        }
    }

    // Cleanup
    close(listen_fd);
    for (int i = 0; i < N; i++) {
        if (i == my_rank) continue;
        if (peers[i].qp) {
            ibv_destroy_qp(peers[i].qp);
        }
        if (peers[i].sockfd > 0) {
            close(peers[i].sockfd);
        }
    }
    ibv_dereg_mr(mr);
    free(buf);
    ibv_destroy_cq(cq);
    ibv_dealloc_pd(pd);
    ibv_close_device(ctx);

    printf("Rank %d: All-to-all RDMA done.\n", my_rank);
    return 0;
}