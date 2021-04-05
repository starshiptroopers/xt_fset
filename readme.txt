This is the kernel module and extension for xtables (iptables)
Provide the ability to manipulate kernel IPSET (add or delete elements) with IP address grabbed from customizable offset in network packet
Can use to remotelly add or remove IP address to/from ipset

Practical use case: To signal the remote router to change traffic or route policy for specific hosts without using well known routing protocols (e.g. ospf)

             ---> internet link 1 -------------->--------------
            |                                                  |
host1 <-> router A <-> router B <-> internet link 2 <----> 128.128.128.128


For example, router A has default route to router B. We need to change the routing at router A when router B lost the entire internet link or some routes for several internet hosts.

Let's assume,for some reasons router B lost the route to the internet host 128.128.128.128, 
 and began to reject traffic directed from host1 to 128.128.128.128 with replying icmp packet type "network-unreachable".

the FSET module running at router A can catch ICMP "network-unreachable" packets and put the IP addresses stored in this ICMP packet into the kernel ipset

Another more general application: you can control the router A kernel ipsets (add or remove some ip-addresses into the ipset) remotely by sending ICMP pakets.


USAGE:

Load the module into the kernel, create the ipset, than add the iptables rule for intercepting and directing the ICMP trafic to the FSET module

iptables -I FORWARD -p icmp --icmp-type network-unreachable -j FSET --add-set detour --offset 44

Due to this rule router will catch the ICMP packet with type "network-unreachable", get the IP address from icmp packet at offset 44, and add it into ipset with name "detour"

And you can have specific routing rules for ipset "detour" (see source routing policy documentation)


You can use any types on ICMP packets and define the offset where ip address is stored inside the packet

use --del-set option to del ip address from the ipset

Testing example:

1. Place the kernel module into autoload or load it by hands: 
      insmod xt_FSET.ko
2. place the iptables control library libxt_FSET.so into iptables library folder for example: 
      cp libxt_FSET.so /usr/lib/x86_64-linux-gnu/xtables
3. create ipset with command: 
      create test-ipset hash:ip family inet hashsize 2048 maxelem 65536
4. add iptables firewall rule for catching icmp packets and send it to FSET processing
      iptables -I INPUT -p icmp --icmp-type echo-request -j FSET --add-set test-ipset --offset 44 --log
5. check the ipset dump:
      ipset list test-ipset
    you will see an empty ipset
6. try to ping this host from another machine with this command:
    ping xx.xx.xx.xx -p 02020203
7. check the ipset dump again:
      ipset list test-ipset
   you will see one record in ipset
	Number of entries: 1
	Members:
	2.2.2.3
8. check the kernel messages with dmesg:
    dmesg
   you will see the message: FSET: 2.2.2.3 has been added to ipset


Copyright © Cherviakov Aleksandr, 2019
