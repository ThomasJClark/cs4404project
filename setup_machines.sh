#!/bin/bash

# The victim
scp $GOPATH/bin/aitf-client* root@10.4.32.1:/root/
ssh root@10.4.32.1 << EOF
    echo y | apt-get install libnetfilter-queue1
    route add -host 10.4.32.3/32 gw 10.4.32.2
    route add -host 10.4.32.2 eth0
    route add -host 10.10.128.116/32 eth0
    route del -net 10.0.0.0/8
    iptables -A INPUT -s 10.4.32.0/24 -j NFQUEUE --queue-num 0
EOF

# The victim's gateway
scp $GOPATH/bin/aitf-router* root@10.4.32.2:/root/
ssh root@10.4.32.2 << EOF
    echo y | apt-get install libnetfilter-queue1
    route add -host 10.4.32.1 eth0
    route add -host 10.4.32.3 eth0
    route add -host 10.10.128.116/32 eth0
    route del -net 10.0.0.0/8
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl -w net.ipv4.conf.eth0.send_redirects=0
    iptables -A FORWARD -d 10.4.32.1,10.4.32.3 -j NFQUEUE --queue-num 0
EOF

# The attacker
scp $GOPATH/bin/aitf-client* root@10.4.32.3:/root/
ssh root@10.4.32.3 << EOF
    echo y | apt-get install libnetfilter-queue1
    route add -host 10.4.32.1/32 gw 10.4.32.2
    route add -host 10.4.32.2 eth0
    route add -host 10.10.128.116/32 eth0
    route del -net 10.0.0.0/8
    iptables -A INPUT -s 10.4.32.0/24 -j NFQUEUE --queue-num 0
EOF