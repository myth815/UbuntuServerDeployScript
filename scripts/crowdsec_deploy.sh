# CrowdSec 完整部署脚本 - 从零到完成
(
echo "=== CrowdSec 完整部署 仅针对SSH加固 (安装+优化) ==="

# 1. 官方一键安装
echo "1. 安装CrowdSec..."
curl -s https://install.crowdsec.net | sudo sh

# 等待安装完成
sleep 5

# 2. 安装防火墙bouncer
echo "2. 安装防火墙bouncer..."
sudo apt install crowdsec-firewall-bouncer-iptables -y
sudo cscli bouncers add firewall-bouncer
sudo systemctl enable crowdsec-firewall-bouncer
sudo systemctl start crowdsec-firewall-bouncer

# 3. 优化SSH保护
echo "3. 优化SSH保护..."
sudo cscli collections install crowdsecurity/sshd --force

# 4. 设置6小时封禁
echo "4. 设置封禁时间..."
sudo cp /etc/crowdsec/profiles.yaml /etc/crowdsec/profiles.yaml.backup
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

# 5. 创建解封命令
echo "5. 创建解封工具..."
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

# 6. 重启服务应用配置
echo "6. 重启服务..."
sudo systemctl restart crowdsec
sleep 3

# 7. 验证安装
echo "7. 验证安装..."
if sudo systemctl is-active --quiet crowdsec; then
    echo "✅ CrowdSec服务：正常"
else
    echo "❌ CrowdSec服务：异常"
    exit 1
fi

if sudo systemctl is-active --quiet crowdsec-firewall-bouncer; then
    echo "✅ 防火墙bouncer：正常"
else
    echo "⚠️  防火墙bouncer：需检查"
fi

echo ""
echo "=== 🎉 部署完成！==="
echo "✅ CrowdSec已安装并优化"
echo "✅ SSH暴力破解保护已启用"
echo "✅ 封禁时间：6小时"
echo "✅ 防火墙自动阻断已启用"
echo ""
echo "📋 常用命令："
echo "sudo cscli decisions list    # 查看封禁列表"
echo "sudo unban <IP>             # 解封IP"
echo "sudo cscli metrics          # 查看统计"
echo "sudo systemctl status crowdsec  # 查看服务状态"
echo ""
echo "🔍 查看实时攻击："
echo "sudo tail -f /var/log/auth.log | grep 'Failed password'"
)
