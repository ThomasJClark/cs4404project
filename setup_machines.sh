#!/bin/bash

# The victim
ssh root@10.4.32.1 << EOF
    echo '10.4.32.1 victim' >> /etc/hosts
    echo '10.4.32.2 victim-router' >> /etc/hosts
    echo '10.4.32.3 attacker-router' >> /etc/hosts
    echo '10.4.32.4 attacker' >> /etc/hosts
    route add -host victim-router/32 eth0
    route add -host attacker-router/32 gw victim-router
    route add -host attacker/32 gw victim-router
    route add -host 10.10.128.116/32 eth0
    route del -net 10.0.0.0/8
    iptables -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -A INPUT -s 10.4.32.0/24 -j NFQUEUE --queue-num 0
    sort -u /etc/hosts -o /etc/hosts
EOF

# The victim's gateway
ssh root@10.4.32.2 << EOF
    echo '10.4.32.1 victim' >> /etc/hosts
    echo '10.4.32.2 victim-router' >> /etc/hosts
    echo '10.4.32.3 attacker-router' >> /etc/hosts
    echo '10.4.32.4 attacker' >> /etc/hosts
    route add -host victim/32 eth0
    route add -host attacker-router/32 eth0
    route add -host attacker/32 gw attacker-router
    route add -host 10.10.128.116/32 eth0
    route del -net 10.0.0.0/8
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl -w net.ipv4.conf.eth0.send_redirects=0
    iptables -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -A FORWARD -d victim,attacker -j NFQUEUE --queue-num 0
    sort -u /etc/hosts -o /etc/hosts
EOF

# The attacker's gateway
ssh root@10.4.32.3 << EOF
    echo '10.4.32.1 victim' >> /etc/hosts
    echo '10.4.32.2 victim-router' >> /etc/hosts
    echo '10.4.32.3 attacker-router' >> /etc/hosts
    echo '10.4.32.4 attacker' >> /etc/hosts
    route add -host victim-router/32 eth0
    route add -host attacker/32 eth0
    route add -host victim/32 gw victim-router
    route add -host 10.10.128.116/32 eth0
    route del -net 10.0.0.0/8
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl -w net.ipv4.conf.eth0.send_redirects=0
    iptables -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -A FORWARD -d victim,attacker -j NFQUEUE --queue-num 0
    sort -u /etc/hosts -o /etc/hosts
EOF

# The attacker
ssh root@10.4.32.4 << EOF
    echo '10.4.32.1 victim' >> /etc/hosts
    echo '10.4.32.2 victim-router' >> /etc/hosts
    echo '10.4.32.3 attacker-router' >> /etc/hosts
    echo '10.4.32.4 attacker' >> /etc/hosts
    route add -host attacker-router/32 eth0
    route add -host victim/32 gw attacker-router
    route add -host victim-router/32 gw attacker-router
    route add -host 10.10.128.116/32 eth0
    route del -net 10.0.0.0/8
    iptables -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -A INPUT -s 10.4.32.0/24 -j NFQUEUE --queue-num 0
    sort -u /etc/hosts -o /etc/hosts
EOF
