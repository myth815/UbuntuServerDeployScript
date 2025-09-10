# 创建高性能网络配置
sudo tee /etc/sysctl.d/99-high-performance.conf << EOF
# BBR拥塞控制
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP优化
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# 连接优化
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 6

# 端口范围和TIME_WAIT
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 262144

# 安全设置
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_unprivileged_port_start = 443

# 文件系统优化
fs.file-max = 1048576
EOF

# 应用配置
sudo sysctl -p /etc/sysctl.d/99-high-performance.conf
