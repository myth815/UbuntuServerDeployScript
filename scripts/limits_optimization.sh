# 系统级设置
sudo tee -a /etc/security/limits.conf << EOF
# 高性能代理服务器优化
* soft nofile 65536
* hard nofile 1048576
* soft nproc 32768
* hard nproc 65536
EOF

# SystemD默认设置
sudo mkdir -p /etc/systemd/system.conf.d
sudo tee /etc/systemd/system.conf.d/limits.conf << EOF
[Manager]
DefaultLimitNOFILE=65536:1048576
DefaultLimitNPROC=32768:65536
DefaultLimitMEMLOCK=134217728:268435456
EOF

sudo systemctl daemon-reload
