from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import Link, Intf, TCLink
from mininet.topo import Topo
from mininet.util import dumpNodeConnections

import logging
import os
import json
import sys

class LeafSpine(Topo):
    """
    Class for Leaf-Spine Topology.
    """
    SpineSwitchList = []
    LeafSwitchList = []
    HostList = []

    def __init__(self, num_spine=2, num_leaf=2, hosts_per_leaf=2):
        """
        Initialize Leaf-Spine topology.
        :param num_spine: Number of spine switches.
        :param num_leaf: Number of leaf switches.
        :param hosts_per_leaf: Number of hosts per leaf switch.
        """
        self.num_spine = num_spine
        self.num_leaf = num_leaf
        self.hosts_per_leaf = hosts_per_leaf
        self.num_hosts = num_leaf * hosts_per_leaf

        # Initialize Topo
        Topo.__init__(self)

    def createNodes(self):
        """Create Spine, Leaf switches and Hosts."""
        self.createSpineSwitches(self.num_spine)
        self.createLeafSwitches(self.num_leaf)
        self.createHosts(self.num_hosts)

    def createSpineSwitches(self, number):
        """Create spine switches."""
        for i in range(1, number + 1):
            self.SpineSwitchList.append(self.addSwitch(f"s{i}"))

    def createLeafSwitches(self, number):
        """Create leaf switches."""
        for i in range(1, number + 1):
            self.LeafSwitchList.append(self.addSwitch(f"l{i}"))

    def createHosts(self, number):
        """Create hosts connected to leaf switches."""
        for i in range(1, number + 1):
            if (i < 10):
                self.HostList.append(self.addHost(f"h0{i}"))
            else:
                self.HostList.append(self.addHost(f"h{i}"))
                
    def createLinks(self, bw_spine_leaf=10, bw_leaf_host=10):
        """Create links between spine and leaf switches and between leaf switches and hosts."""
        # Connect each leaf switch to all spine switches
        for leaf in self.LeafSwitchList:
            for spine in self.SpineSwitchList:
                self.addLink(leaf, spine, bw=bw_spine_leaf)

        # Connect each leaf switch to its hosts
        host_index = 0
        for leaf in self.LeafSwitchList:
            for _ in range(self.hosts_per_leaf):
                self.addLink(leaf, self.HostList[host_index], bw=bw_leaf_host)
                host_index += 1

    def set_ovs_protocol_13(self):
        """Set OpenFlow 1.3 for all switches."""
        self._set_ovs_protocol_13(self.SpineSwitchList)
        self._set_ovs_protocol_13(self.LeafSwitchList)

    def _set_ovs_protocol_13(self, switch_list):
        for switch in switch_list:
            cmd = f"sudo ovs-vsctl set bridge {switch} protocols=OpenFlow13"
            os.system(cmd)

def set_host_ip(net, topo):
    hostlist = []
    ips = {}
    for k in range(len(topo.HostList)):
            hostlist.append(net.get(topo.HostList[k]))

    host_index = 0
    for i in range(len(topo.LeafSwitchList)):
        for j in range(topo.hosts_per_leaf):
            hostlist[host_index].setIP("10.%d.0.%d" % (i + 1, j + 1))
            ips[hostlist[host_index].name] = "10.%d.0.%d" % (i + 1, j + 1)
            # print("Setting up ip %s for host %s" % (("10.%d.0.%d" % (i + 1, j + 1)), hostlist[host_index].name))
            host_index += 1

    with open('config.json', 'w') as config_file:
        json.dump(ips, config_file, indent=4)

def install_leaf_rules(net, topo):
    """
    Install proactive flow entries for leaf switches in a leaf-spine topology.
    """
    for sw in topo.LeafSwitchList:
        # Downstream: Forward to servers
        for i in range(1, topo.hosts_per_leaf + 1):
            # print("switch %s: 10.%d.0.%d" % (sw, int(sw[-1:]), i))
            cmd = "ovs-ofctl add-flow %s -O OpenFlow13 \
                'table=0,idle_timeout=0,hard_timeout=0,priority=40,arp, \
                nw_dst=10.%d.0.%d,actions=output:%d'" % (sw, int(sw[-1:]), i, i + 2)
            # print(cmd)
            os.system(cmd)
            cmd = "ovs-ofctl add-flow %s -O OpenFlow13 \
                'table=0,idle_timeout=0,hard_timeout=0,priority=40,ip, \
                nw_dst=10.%d.0.%d,actions=output:%d'" % (sw, int(sw[-1:]), i, i + 2)
            os.system(cmd)

        # Upstream: Forward to spine switches (load balance across spines)
        cmd = "ovs-ofctl add-group %s -O OpenFlow13 \
			'group_id=1,type=select,bucket=output:1,bucket=output:2'" % sw
        os.system(cmd)

        # Add default rules to use the group for upstream traffic
        cmd = "ovs-ofctl add-flow %s -O OpenFlow13 \
            'table=0,priority=10,arp,actions=group:1'" % sw
        os.system(cmd)
        cmd = "ovs-ofctl add-flow %s -O OpenFlow13 \
            'table=0,priority=10,ip,actions=group:1'" % sw
        os.system(cmd)

def install_spine_rules(net, topo):
    """
    Install proactive flow entries for spine switches in a leaf-spine topology.
    """
    for sw in topo.SpineSwitchList:
        leaf_ports = range(1, len(topo.LeafSwitchList) + 1)  # Ports connecting to leaf switches
        for leaf_id, port in enumerate(leaf_ports, start=1):
            cmd = "ovs-ofctl add-flow %s -O OpenFlow13 \
                'table=0,idle_timeout=0,hard_timeout=0,priority=10,arp, \
                nw_dst=10.%d.0.0/16,actions=output:%d'" % (sw, leaf_id, port)
            os.system(cmd)
            cmd = "ovs-ofctl add-flow %s -O OpenFlow13 \
                'table=0,idle_timeout=0,hard_timeout=0,priority=10,ip, \
                nw_dst=10.%d.0.0/16,actions=output:%d'" % (sw, leaf_id, port)
            os.system(cmd)

def createTopo(ip="192.168.56.101", port=6653):
	"""
		Create network topology and run the Mininet.
	"""
	# Create Topo.
	topo = LeafSpine(2, 8, 4)
	topo.createNodes()
	topo.createLinks()

	# Start Mininet.
	CONTROLLER_IP = ip
	CONTROLLER_PORT = port
	net = Mininet(topo=topo, link=TCLink, controller=None, autoSetMacs=True)
	net.addController(
		'controller', controller=RemoteController,
		ip=CONTROLLER_IP, port=CONTROLLER_PORT)
	net.start()

	# Set OVS's protocol as OF13.
	topo.set_ovs_protocol_13()
	# Set hosts IP addresses.
	set_host_ip(net, topo)
	install_leaf_rules(net, topo)
	install_spine_rules(net, topo)

	for host in net.hosts:
		host.cmd(f"python3 tcp_app.py {host.name} {sys.argv[1]} &")

	CLI(net)
	net.stop()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python fattree.py <mptcp_enabled>")
        sys.exit(1)

    setLogLevel('info')

    if os.getuid() != 0:
        logging.debug("You are NOT root")
    elif os.getuid() == 0:
        createTopo()
