#!/bin/bash

# The victim
scp $GOPATH/bin/aitf-client* root@10.4.32.1:/root/
ssh root@10.4.32.1 << EOF
    route add -host 10.4.32.2/32 eth0
    route add -host 10.4.32.3/32 gw 10.4.32.2
    route add -host 10.4.32.4/32 gw 10.4.32.2
    route add -host 10.10.128.116/32 eth0
    route del -net 10.0.0.0/8
    iptables -A INPUT -s 10.4.32.0/24 -j NFQUEUE --queue-num 0
    iptables -A INPUT -p icmp -j NFQUEUE --queue-num 0
    echo '10.4.32.1 victim' >> /etc/hosts
    echo '10.4.32.2 victim-router' >> /etc/hosts
    echo '10.4.32.3 attacker-router' >> /etc/hosts
    echo '10.4.32.4 attacker' >> /etc/hosts
EOF

# The victim's gateway
scp $GOPATH/bin/aitf-router* root@10.4.32.2:/root/
ssh root@10.4.32.2 << EOF
    route add -host 10.4.32.1/32 eth0
    route add -host 10.4.32.3/32 eth0
    route add -host 10.4.32.4/32 gw 10.4.32.3
    route add -host 10.10.128.116/32 eth0
    route del -net 10.0.0.0/8
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl -w net.ipv4.conf.eth0.send_redirects=0
    iptables -A FORWARD -d 10.4.32.1,10.4.32.4 -j NFQUEUE --queue-num 0
    echo '10.4.32.1 victim' >> /etc/hosts
    echo '10.4.32.2 victim-router' >> /etc/hosts
    echo '10.4.32.3 attacker-router' >> /etc/hosts
    echo '10.4.32.4 attacker' >> /etc/hosts
EOF

# The attacker's gateway
scp $GOPATH/bin/aitf-router* root@10.4.32.3:/root/
ssh root@10.4.32.3 << EOF
    route add -host 10.4.32.2/32 eth0
    route add -host 10.4.32.4/32 eth0
    route add -host 10.4.32.1/32 gw 10.4.32.2
    route add -host 10.10.128.116/32 eth0
    route del -net 10.0.0.0/8
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl -w net.ipv4.conf.eth0.send_redirects=0
    iptables -A FORWARD -d 10.4.32.1,10.4.32.4 -j NFQUEUE --queue-num 0
    echo '10.4.32.1 victim' >> /etc/hosts
    echo '10.4.32.2 victim-router' >> /etc/hosts
    echo '10.4.32.3 attacker-router' >> /etc/hosts
    echo '10.4.32.4 attacker' >> /etc/hosts
EOF

# The attacker
scp $GOPATH/bin/aitf-client* root@10.4.32.4:/root/
ssh root@10.4.32.4 << EOF
    route add -host 10.4.32.3/32 eth0
    route add -host 10.4.32.1/32 gw 10.4.32.3
    route add -host 10.4.32.2/32 gw 10.4.32.3
    route add -host 10.10.128.116/32 eth0
    route del -net 10.0.0.0/8
    iptables -A INPUT -s 10.4.32.0/24 -j NFQUEUE --queue-num 0
    echo '10.4.32.1 victim' >> /etc/hosts
    echo '10.4.32.2 victim-router' >> /etc/hosts
    echo '10.4.32.3 attacker-router' >> /etc/hosts
    echo '10.4.32.4 attacker' >> /etc/hosts
EOF
