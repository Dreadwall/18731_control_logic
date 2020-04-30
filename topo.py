import sys

from mininet.topo import Topo
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller, RemoteController

class StarterTopo( Topo ):
    def __init__( self, num_servers ):
        Topo.__init__( self )

        s1 = self.addSwitch( 's1' )

        for i in range(0, num_servers):
            h = self.addHost("h" + str(i) )
            self.addLink( h, s1 )

        c1 = self.addHost( 'c1' )
        self.addLink( c1, s1 )

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("sudo python topo.py <num servers>")
        exit(-1)

    num_servers = int(sys.argv[1])
    print("starting topo with " + str(num_servers) + " weak servers")

    net = Mininet( topo=StarterTopo(num_servers) )

    net.start()

    for i in range(0, num_servers):
        h = net.get("h" + str(i))
        h.cmd("python server.py 8080 &") 

    c1 = net.get('c1')
    c1.cmd("python3 control.py > hello.txt")

    CLI(net)
    net.stop()
