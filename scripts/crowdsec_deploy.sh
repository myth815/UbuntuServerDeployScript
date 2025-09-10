# CrowdSec 修复版安装脚本
(
echo "=== CrowdSec 修复版安装脚本 ==="

# 1. 检查当前状态
echo "1. 检查当前安装状态..."
if command -v cscli >/dev/null 2>&1; then
    echo "✅ CrowdSec已安装，版本: $(cscli version | head -1)"
else
    echo "❌ CrowdSec未安装，开始安装..."
    
    # 手动添加仓库
    echo "1.1 添加官方仓库..."
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
    
    # 更新并安装
    echo "1.2 安装CrowdSec主程序..."
    sudo apt update
    sudo apt install crowdsec -y
    
    # 验证安装
    if command -v cscli >/dev/null 2>&1; then
        echo "✅ CrowdSec安装成功"
        sleep 3
    else
        echo "❌ CrowdSec安装失败"
        exit 1
    fi
fi

# 2. 检查并安装防火墙bouncer
echo "2. 检查防火墙bouncer..."
if dpkg -l | grep -q crowdsec-firewall-bouncer; then
    echo "✅ 防火墙bouncer已安装"
else
    echo "2.1 安装防火墙bouncer..."
    sudo apt install crowdsec-firewall-bouncer-iptables -y
fi

# 3. 创建API密钥
echo "3. 配置API密钥..."
if sudo cscli bouncers list | grep -q firewall-bouncer; then
    echo "✅ API密钥已存在"
else
    echo "3.1 创建API密钥..."
    sudo cscli bouncers add firewall-bouncer
fi

# 4. 启动防火墙bouncer
echo "4. 启动防火墙bouncer..."
sudo systemctl enable crowdsec-firewall-bouncer
sudo systemctl start crowdsec-firewall-bouncer

# 5. 安装SSH保护
echo "5. 安装SSH保护..."
sudo cscli collections install crowdsecurity/sshd --force

# 6. 配置封禁策略
echo "6. 配置封禁策略..."
if [[ -f /etc/crowdsec/profiles.yaml ]]; then
    sudo cp /etc/crowdsec/profiles.yaml /etc/crowdsec/profiles.yaml.backup
fi

sudo tee /etc/crowdsec/profiles.yaml > /dev/null << 'EOF'
name: default_ip_remediation
debug: false
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
  - type: ban
    duration: 6h
on_success: break
EOF

# 7. 创建管理工具
echo "7. 创建管理工具..."
sudo tee /usr/local/bin/unban > /dev/null << 'EOF'
#!/bin/bash
if [[ $# -eq 0 ]]; then
    echo "用法: unban <IP地址>"
    echo "当前封禁列表:"
    cscli decisions list
    exit 1
fi
cscli decisions delete --ip $1
echo "已解封 $1"
EOF

sudo chmod +x /usr/local/bin/unban

# 8. 重启服务
echo "8. 重启服务..."
sudo systemctl restart crowdsec
sleep 5

# 9. 最终验证
echo "9. 最终验证..."
echo "=== 服务状态 ==="
echo "CrowdSec: $(sudo systemctl is-active crowdsec)"
echo "防火墙Bouncer: $(sudo systemctl is-active crowdsec-firewall-bouncer)"

echo ""
echo "=== 安装验证 ==="
echo "CrowdSec版本: $(cscli version | head -1)"
echo "SSH保护: $(sudo cscli collections list | grep sshd || echo '需要检查')"

echo ""
echo "=== 当前状态 ==="
sudo cscli bouncers list
sudo cscli decisions list | head -3

if sudo systemctl is-active --quiet crowdsec; then
    echo ""
    echo "🎉 安装成功！"
    echo "📋 常用命令："
    echo "  sudo cscli decisions list    # 查看封禁"
    echo "  sudo unban <IP>             # 解封IP"
    echo "  sudo cscli metrics          # 查看统计"
else
    echo "❌ 安装仍有问题，请检查日志："
    echo "sudo journalctl -u crowdsec --no-pager -n 20"
fi
)
