# xt_fset

xt_fset is the kernel module and iptables extension (plugin) to linux kernel netfilter subsystem allows you manipulate linux kernel ipsets (add or remove some ip-addresses into the ipset) remotely by sending the control ICMP packets.

The plugin was created as part of the study of the linux kernel netfilter subsystem and looking for the solution for real task: to signal the remote router to change traffic or route policy for specific hosts without using well known routing protocols (e.g. ospf)

For example, we have the network configuration:

                ---> Internet link 2 -------------->--------------
               |                                                  |
    Host1 <-> Router A <-> Router B <-> Internet link 1 <----> 128.128.128.128

For example, router A has default route to router B and the backup "Internet Link 2". We need router A to route the traffic addressed to 128.128.128.128 into the backup uplink when router B lost the route to 128.128.128.128.

Let's assume,for some reasons router B lost the route to the internet host 128.128.128.128,
 and began to reject traffic directed from Host1 to 128.128.128.128 with replying icmp packet type "network-unreachable".
The xt_fset module running at router A can catch ICMP "network-unreachable" packets and put the IP addresses located in this ICMP packet into the kernel ipset which is routed to the backup uplink.

Another more general application: you can control the router A kernel ipsets (add or remove some ip-addresses into the ipset) remotely by sending ICMP packets.

# USAGE:

Load the module into the kernel, create the ipset, than add the iptables rule for intercepting and directing the ICMP trafic to the FSET module

iptables -I FORWARD -p icmp --icmp-type network-unreachable -j FSET --add-set detour --offset 44

Due to this rule router will catch the ICMP packet with type "network-unreachable", get the IP address from icmp packet at offset 44, and add it into ipset with name "detour"

You can have specific routing rules for ipset "detour" (see source routing policy documentation)

You can use any types on ICMP packets and define the offset where ip address is stored inside the packet.
Use --del-set option to del ip address from the ipset

Some ICMP packets is automaticly generated by linux network susbsystem, for example when some host is unreachable, the unreachable host's IP located at offset 44 inside the ICMP "host-unreachable" packet.

Also you can genererate your own ICMP packets to control xt_fset. 
Use the "ping" console command: ping -p XXXXXXXX - where XXXXXXXX is the payload which will be added into the ICMP echo request packets

# Test example

Testing example:

```
1. Place the kernel module to the autoload folder or load it by hands:.
      insmod xt_FSET.ko
2. Place the iptables control library libxt_FSET.so into iptables library folder for example:
      cp libxt_FSET.so /usr/lib/x86_64-linux-gnu/xtables
3. Create ipset with command:.
      create test-ipset hash:ip family inet hashsize 2048 maxelem 65536
4. Add iptables rule for catching icmp packets and send it to FSET processing
      iptables -I INPUT -p icmp --icmp-type echo-request -j FSET --add-set test-ipset --offset 44 --log
5. Check the ipset dump:
      ipset list test-ipset
    you will see an empty ipset
6. Ping this host from another machine with the command:
    ping xx.xx.xx.xx -p 02020203
7. Check the ipset dump again:
      ipset list test-ipset
   you will see one record in ipset
Number of entries: 1
Members:
2.2.2.3
8. check the kernel messages with dmesg:
    dmesg
   you will see the message: FSET: 2.2.2.3 has been added to ipset
```

# Kernel module signing

Since kernel 4.0, some server and desktop Linux distro activated the kernel module signing feature. 
You can't load the third-party precompiled kernel module into the kernel without signing the module with keys stored in your kernel's keys storage. 
See signing.txt how to create the keys, import them into the kernel storage and build and sign xt_fset module

# OpenWRT

This module has been developed to work at the low-performance OpenWRT routers. You can build the module for OpenWRT with the Makefile located in the openwrt directory. 

# Important note

I'm not a linux kernel developer and C developer now although I have some linux kernel developing background many years ago. Therefore, the code may not be clean and optimal enough. 
