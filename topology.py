from mininet.topo import Topo
from mininet.cli import CLI
from mininet.net import Mininet

class MyTopo(Topo):
	def build(self):
		# spine switches
		spine1 = self.addSwitch('s1')
		# spine2 = self.addSwitch('s2')

		# leaf switches
		for i in range(8):
			leaf_switch = self.addSwitch(f"l{i + 1}")

			for j in range(4):
				host = self.addHost(f"h{j + 1}l{i + 1}")
				self.addLink(host, leaf_switch)

			self.addLink(leaf_switch, spine1)
			# self.addLink(leaf_switch, spine2)

def add_hash_based_flows(net):
	spine1 = net.get("s1")
	spine2 = net.get("s2")
	print(f"Ports for {spine1.name}: {spine1.ports}")
	print(f"Ports for {spine2.name}: {spine2.ports}")

	for i in range(8):
		leaf = net.get(f"l{i + 1}")
		print(f"Ports for {leaf.name}: {leaf.ports}")

		connections_to_spine1 = leaf.connectionsTo(spine1)
		connections_to_spine2 = leaf.connectionsTo(spine2)

		print(connections_to_spine1, connections_to_spine2)

		leaf_to_spine1_port = leaf.ports[connections_to_spine1[0][0]]
		leaf_to_spine2_port = leaf.ports[connections_to_spine2[0][0]]

		print(leaf_to_spine1_port, leaf_to_spine2_port)

		for j in range(4):
			host = net.get(f"h{j + 1}l{i + 1}")
			host_ip = f"10.0.{i + 1}.{j + 1}"
			host.cmd(f'ifconfig {host.name}-eth0 {host_ip}/24 up')

			# Calculate hash and add rules
			hash_value = hash((host_ip, "destination_ip_placeholder")) % 2
			if hash_value == 0:
				leaf.cmd(f'ovs-ofctl add-flow {leaf.name} ip,nw_dst={host_ip},actions=output:{leaf_to_spine1_port}')  # To spine1
			else:
				leaf.cmd(f'ovs-ofctl add-flow {leaf.name} ip,nw_dst={host_ip},actions=output:{leaf_to_spine2_port}')  # To spine1


topo = MyTopo()
net = Mininet(topo=topo)
net.start()

# add_hash_based_flows(net)

CLI(net)
net.stop()