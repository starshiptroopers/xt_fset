#!/bin/bash

MODULE_NAME="xt_FSET.ko"
ALREADY_LOADED=`lsmod | grep $MODULE_NAME`

#catch all icmp echo request packets and grab the first data payload bytes as ipset address
IPTABLES_TEST1_RULE1="OUTPUT -p icmp --icmp-type echo-request -j FSET --add-set test --offset 44 --log"
#IPTABLES_TEST1_RULE2="INPUT -p icmp -s 192.168.3.10 -j REJECT --reject-with icmp-admin-prohibited"

sudo iptables -D ${IPTABLES_TEST1_RULE1}
#sudo iptables -D INPUT -p icmp -s 192.168.3.10 -j REJECT --reject-with icmp-admin-prohibited

if [ "$ALREADY_LOADED" = "" ]; then
    sudo rmmod "$MODULE_NAME"
fi
sudo insmod "$MODULE_NAME"

sudo iptables -I ${IPTABLES_TEST1_RULE1}
#sudo iptables -I INPUT -p icmp -s 192.168.3.10 -j REJECT --reject-with icmp-admin-prohibited
