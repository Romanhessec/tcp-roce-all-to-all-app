#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <infiniband/verbs.h>  // Verbs header on Ubuntu

#define TEST_MSG_SIZE 64

// Simple struct to hold QP info needed for connection.
struct qp_info {
    uint32_t qp_num;
    uint16_t lid;      // For IB only; if RoCE, typically 0
    uint8_t  gid[16];  // GID for RoCE or global IB
    uint32_t rkey;     // Remote key
    uint64_t vaddr;    // Remote virtual address
};

// Utility function to send/receive data via a TCP socket
static int tcp_send(int sockfd, const void *buf, size_t len) {
    return send(sockfd, buf, len, 0);
}
static int tcp_recv(int sockfd, void *buf, size_t len) {
    return recv(sockfd, buf, len, MSG_WAITALL);
}

// A helper to pick an RDMA device by name or fallback to the first device
// 'dev_name' can be NULL to pick the first device from the list.
static struct ibv_context *open_device_by_name(const char *dev_name) {
    struct ibv_device **dev_list = NULL;
    struct ibv_device *found_dev = NULL;
    struct ibv_context *ctx = NULL;
    int num_devs = 0;

    dev_list = ibv_get_device_list(&num_devs);
    if (!dev_list || num_devs == 0) {
        fprintf(stderr, "No RDMA devices found.\n");
        goto out;
    }

    printf("[DEBUG] Found %d devices.\n", num_devs);
    for (int i = 0; i < num_devs; i++) {
        const char *name = ibv_get_device_name(dev_list[i]);
        printf("[DEBUG] Device #%d name = %s\n", i, name);

        if (dev_name) {
            // If we have a specific device name to match
            if (strcmp(name, dev_name) == 0) {
                found_dev = dev_list[i];
                break;
            }
        } else {
            // No specific name requested: pick first device in the list
            found_dev = dev_list[0];
            break;
        }
    }
    if (!found_dev) {
        fprintf(stderr, "Requested device %s not found.\n", dev_name ? dev_name : "(none)");
        goto out;
    }

    ctx = ibv_open_device(found_dev);
    if (!ctx) {
        perror("ibv_open_device");
        goto out;
    }

out:
    if (dev_list) ibv_free_device_list(dev_list);
    return ctx;
}

// Bring QP from INIT -> RTR -> RTS
static int modify_qp_to_rtr(struct ibv_qp *qp,
                            int is_roce,
                            uint8_t port_num,
                            uint8_t gid_index,
                            uint32_t remote_qpn,
                            uint8_t *remote_gid,
                            uint16_t remote_lid)
{
    // INIT -> RTR
    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.qp_state           = IBV_QPS_RTR;
    attr.path_mtu           = IBV_MTU_256; // example
    attr.dest_qp_num        = remote_qpn;
    attr.rq_psn             = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer      = 12;

    // Common AH attributes
    attr.ah_attr.port_num      = port_num;
    attr.ah_attr.sl            = 0;
    attr.ah_attr.src_path_bits = 0;

    if (is_roce) {
        // RoCE: Must use global route
        attr.ah_attr.is_global  = 1;
        attr.ah_attr.dlid       = 0; // LID unused in RoCE
        memcpy(attr.ah_attr.grh.dgid.raw, remote_gid, 16);
        attr.ah_attr.grh.sgid_index = gid_index;
        attr.ah_attr.grh.hop_limit  = 64;
    } else {
        // InfiniBand
        attr.ah_attr.is_global = 0;
        attr.ah_attr.dlid      = remote_lid;
    }

    int flags = IBV_QP_STATE      | IBV_QP_AV       | IBV_QP_PATH_MTU   |
                IBV_QP_DEST_QPN   | IBV_QP_RQ_PSN   | IBV_QP_MAX_DEST_RD_ATOMIC |
                IBV_QP_MIN_RNR_TIMER;

    printf("[DEBUG] >>> modify_qp_to_rtr: IBV_QPS_RTR\n");
    printf("[DEBUG]     is_global=%d dlid=%u sgid_index=%d\n",
           attr.ah_attr.is_global, attr.ah_attr.dlid,
           attr.ah_attr.grh.sgid_index);
    printf("[DEBUG]     remote_qpn=%u\n", remote_qpn);

    if (ibv_modify_qp(qp, &attr, flags)) {
        perror("Failed to modify QP to RTR");
        return -1;
    }

    // RTR -> RTS
    memset(&attr, 0, sizeof(attr));
    attr.qp_state      = IBV_QPS_RTS;
    attr.sq_psn        = 0;
    attr.timeout       = 14;
    attr.retry_cnt     = 7;
    attr.rnr_retry     = 7;
    attr.max_rd_atomic = 1;

    flags = IBV_QP_STATE     | IBV_QP_SQ_PSN    | IBV_QP_TIMEOUT  |
            IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC;

    printf("[DEBUG] >>> modify_qp_to_rts: IBV_QPS_RTS\n");
    if (ibv_modify_qp(qp, &attr, flags)) {
        perror("Failed to modify QP to RTS");
        return -1;
    }
    return 0;
}

static void print_gid(const char *prefix, uint8_t gid[16]) {
    printf("%s", prefix);
    for (int i = 0; i < 16; i++) {
        printf("%02x", gid[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    int is_server = 0;
    char *server_ip = NULL;
    int tcp_port = 12345;
    // We'll let user optionally choose a device name or GID index, if desired
    const char *dev_name = NULL;
    int gid_index = 0; // default to 0, can be changed
    int opt;

    while ((opt = getopt(argc, argv, "sc:p:d:g:")) != -1) {
        switch (opt) {
        case 's':
            is_server = 1;
            break;
        case 'c':
            server_ip = optarg;
            break;
        case 'p':
            tcp_port = atoi(optarg);
            break;
        case 'd':
            dev_name = optarg;
            break;
        case 'g':
            gid_index = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s [-s|-c <server_ip>] -p <port> [-d <dev_name>] [-g <gid_index>]\n", argv[0]);
            return 1;
        }
    }

    if (!is_server && !server_ip) {
        fprintf(stderr, "Client mode requires -c <server_ip>\n");
        return 1;
    }

    printf("[DEBUG] Mode: %s\n", (is_server ? "Server" : "Client"));
    printf("[DEBUG] TCP port: %d\n", tcp_port);
    printf("[DEBUG] Device name: %s (NULL means pick first)\n", dev_name ? dev_name : "(none)");
    printf("[DEBUG] GID index: %d\n", gid_index);

    // -----------------------------------------------------------------
    // 1. Create TCP socket for out-of-band exchange
    // -----------------------------------------------------------------
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }
    if (is_server) {
        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(tcp_port);

        if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("bind");
            return 1;
        }
        listen(sockfd, 1);
        printf("[DEBUG] Server listening on port %d...\n", tcp_port);

        struct sockaddr_in client_addr;
        socklen_t clen = sizeof(client_addr);
        int newfd = accept(sockfd, (struct sockaddr *)&client_addr, &clen);
        if (newfd < 0) {
            perror("accept");
            return 1;
        }
        close(sockfd);
        sockfd = newfd;
        printf("[DEBUG] Client connected.\n");
    } else {
        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(tcp_port);
        inet_pton(AF_INET, server_ip, &serv_addr.sin_addr);

        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("connect");
            return 1;
        }
        printf("[DEBUG] Connected to server.\n");
    }

    // -----------------------------------------------------------------
    // 2. Open RDMA device
    // -----------------------------------------------------------------
    // We'll always pick port_num=1 for example, but we debug-print if that is valid
    uint8_t port_num = 1;
    struct ibv_context *ctx = open_device_by_name(dev_name);
    if (!ctx) {
        fprintf(stderr, "[ERROR] Failed to open RDMA device.\n");
        return 1;
    }
    printf("[DEBUG] Successfully opened device: %s\n",
           ibv_get_device_name(ctx->device));

    // Query port
    struct ibv_port_attr port_attr;
    if (ibv_query_port(ctx, port_num, &port_attr)) {
        perror("ibv_query_port");
        return 1;
    }
    printf("[DEBUG] port_num=%u state=%d max_mtu=%d active_mtu=%d lid=%u link_layer=%d\n",
           port_num, port_attr.state, port_attr.max_mtu,
           port_attr.active_mtu, port_attr.lid, port_attr.link_layer);

    int is_roce = (port_attr.link_layer == IBV_LINK_LAYER_ETHERNET);
    printf("[DEBUG] is_roce=%d\n", is_roce);

    // -----------------------------------------------------------------
    // 3. Create PD, CQ, QP
    // -----------------------------------------------------------------
    struct ibv_pd *pd = ibv_alloc_pd(ctx);
    if (!pd) {
        perror("ibv_alloc_pd");
        return 1;
    }
    struct ibv_cq *cq = ibv_create_cq(ctx, 16, NULL, NULL, 0);
    if (!cq) {
        perror("ibv_create_cq");
        return 1;
    }
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
        .sq_sig_all = 1,
    };
    struct ibv_qp *qp = ibv_create_qp(pd, &qp_init_attr);
    if (!qp) {
        perror("ibv_create_qp");
        return 1;
    }
    printf("[DEBUG] Created QP #%u\n", qp->qp_num);

    // -----------------------------------------------------------------
    // 4. Register MR
    // -----------------------------------------------------------------
    char *buf = malloc(TEST_MSG_SIZE);
    memset(buf, 0, TEST_MSG_SIZE);
    struct ibv_mr *mr = ibv_reg_mr(pd, buf, TEST_MSG_SIZE,
                                   IBV_ACCESS_LOCAL_WRITE  |
                                   IBV_ACCESS_REMOTE_WRITE |
                                   IBV_ACCESS_REMOTE_READ);
    if (!mr) {
        perror("ibv_reg_mr");
        return 1;
    }
    printf("[DEBUG] Registered MR: lkey=0x%x rkey=0x%x buf_ptr=%p\n", mr->lkey, mr->rkey, (void*)buf);

    // QP: RESET -> INIT
    {
        struct ibv_qp_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.qp_state        = IBV_QPS_INIT;
        attr.port_num        = port_num;
        attr.pkey_index      = 0;
        attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE |
                               IBV_ACCESS_REMOTE_READ |
                               IBV_ACCESS_REMOTE_WRITE;
        int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT |
                    IBV_QP_ACCESS_FLAGS;
        printf("[DEBUG] >>> modify_qp: IBV_QPS_INIT\n");
        if (ibv_modify_qp(qp, &attr, flags)) {
            perror("Failed to modify QP to INIT");
            return 1;
        }
    }

    // -----------------------------------------------------------------
    // 5. Prepare local QP info and exchange with peer
    // -----------------------------------------------------------------
    struct qp_info local_qpinfo, remote_qpinfo;
    memset(&local_qpinfo, 0, sizeof(local_qpinfo));
    memset(&remote_qpinfo, 0, sizeof(remote_qpinfo));

    // Grab local GID
    union ibv_gid my_gid;
    memset(&my_gid, 0, sizeof(my_gid));
    if (ibv_query_gid(ctx, port_num, gid_index, &my_gid)) {
        perror("ibv_query_gid");
        return 1;
    }

    local_qpinfo.qp_num = qp->qp_num;
    local_qpinfo.rkey   = mr->rkey;
    local_qpinfo.vaddr  = (uintptr_t)buf;
    if (is_roce) {
        local_qpinfo.lid = 0; // LID not used in RoCE
    } else {
        local_qpinfo.lid = port_attr.lid;
    }
    memcpy(local_qpinfo.gid, my_gid.raw, 16);

    printf("[DEBUG] Local QP info:\n");
    printf("        qp_num=%u lid=%u rkey=0x%x vaddr=0x%lx\n",
           local_qpinfo.qp_num, local_qpinfo.lid,
           local_qpinfo.rkey, (unsigned long)local_qpinfo.vaddr);
    print_gid("        GID=", local_qpinfo.gid);

    // Send local info to peer
    if (tcp_send(sockfd, &local_qpinfo, sizeof(local_qpinfo)) != sizeof(local_qpinfo)) {
        fprintf(stderr, "[ERROR] Failed to send local QP info\n");
        return 1;
    }

    // Receive remote info
    if (tcp_recv(sockfd, &remote_qpinfo, sizeof(remote_qpinfo)) != sizeof(remote_qpinfo)) {
        fprintf(stderr, "[ERROR] Failed to receive remote QP info\n");
        return 1;
    }
    printf("[DEBUG] Received remote QP info:\n");
    printf("        qp_num=%u lid=%u rkey=0x%x vaddr=0x%lx\n",
           remote_qpinfo.qp_num, remote_qpinfo.lid,
           remote_qpinfo.rkey, (unsigned long)remote_qpinfo.vaddr);
    print_gid("        GID=", remote_qpinfo.gid);

    // -----------------------------------------------------------------
    // 6. Bring QP -> RTR -> RTS
    // -----------------------------------------------------------------
    if (modify_qp_to_rtr(qp,
                         is_roce,
                         port_num,
                         gid_index, // pass in the GID index we used
                         remote_qpinfo.qp_num,
                         remote_qpinfo.gid,
                         remote_qpinfo.lid)) {
        fprintf(stderr, "[ERROR] Failed to bring QP to RTR/RTS\n");
        goto cleanup;
    }
    printf("[DEBUG] QP #%u is now RTS.\n", qp->qp_num);

    // -----------------------------------------------------------------
    // 7. Post a receive on this side; if client, do a send
    // -----------------------------------------------------------------
    struct ibv_sge sg;
    struct ibv_recv_wr rr, *bad_rr = NULL;
    struct ibv_send_wr sr, *bad_sr = NULL;
    struct ibv_wc wc;

    memset(&sg, 0, sizeof(sg));
    sg.addr   = (uintptr_t)buf;
    sg.length = TEST_MSG_SIZE;
    sg.lkey   = mr->lkey;

    memset(&rr, 0, sizeof(rr));
    rr.wr_id = 1;
    rr.sg_list = &sg;
    rr.num_sge = 1;
    if (ibv_post_recv(qp, &rr, &bad_rr)) {
        perror("ibv_post_recv");
        goto cleanup;
    }
    printf("[DEBUG] Posted receive.\n");

    // If we are client, do a send
    if (!is_server) {
        snprintf(buf, TEST_MSG_SIZE, "Hello RDMA!");
        memset(&sr, 0, sizeof(sr));
        sr.wr_id      = 2;
        sr.opcode     = IBV_WR_SEND;
        sr.sg_list    = &sg;
        sr.num_sge    = 1;
        sr.send_flags = IBV_SEND_SIGNALED;

        if (ibv_post_send(qp, &sr, &bad_sr)) {
            perror("ibv_post_send");
            goto cleanup;
        }
        printf("[DEBUG] Client posted send.\n");
    }

    // -----------------------------------------------------------------
    // 8. Poll for completions
    // -----------------------------------------------------------------
    int num_completions = 0;
    while (num_completions < 1) {
        int ne = ibv_poll_cq(cq, 1, &wc);
        if (ne < 0) {
            fprintf(stderr, "[ERROR] ibv_poll_cq error\n");
            goto cleanup;
        } else if (ne == 0) {
            continue; // No completions yet
        } else {
            if (wc.status != IBV_WC_SUCCESS) {
                fprintf(stderr, "[ERROR] WC status: %s\n", ibv_wc_status_str(wc.status));
                goto cleanup;
            }
            if (wc.opcode == IBV_WC_RECV) {
                printf("[DEBUG] Received message: %s\n", buf);
            } else if (wc.opcode == IBV_WC_SEND) {
                printf("[DEBUG] Send completed.\n");
            }
            num_completions++;
        }
    }

    printf("[DEBUG] RDMA P2P demo finished successfully.\n");

cleanup:
    if (qp) ibv_destroy_qp(qp);
    if (cq) ibv_destroy_cq(cq);
    if (mr) ibv_dereg_mr(mr);
    if (pd) ibv_dealloc_pd(pd);
    if (ctx) ibv_close_device(ctx);
    if (sockfd >= 0) close(sockfd);
    if (buf) free(buf);
    return 0;
}