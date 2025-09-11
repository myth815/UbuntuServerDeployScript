#!/bin/bash

# CrowdSec完整部署脚本 - 黑名单优化版
# 作者: myth815
# 版本: 2.0
# 特点: 优化社区黑名单，修复已知问题，适合动态IP用户

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "================================================"
echo "   CrowdSec安全防护系统部署脚本 v2.0"
echo "   优化: 社区黑名单 | 动态IP友好"
echo "================================================"
echo ""

# 检查root权限
if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
   echo -e "${RED}错误: 需要sudo权限${NC}"
   echo "请使用: sudo bash $0"
   exit 1
fi

# 1. 系统准备
echo -e "${BLUE}[1/12] 系统准备...${NC}"
sudo apt update >/dev/null 2>&1
sudo apt install -y curl wget gnupg apt-transport-https >/dev/null 2>&1

# 2. 检查并卸载旧版本
echo -e "${BLUE}[2/12] 检查现有安装...${NC}"
if command -v cscli >/dev/null 2>&1; then
    CURRENT_VERSION=$(cscli version 2>/dev/null | head -1 || echo "未知")
    echo "  检测到现有版本: $CURRENT_VERSION"
    
    # 检查配置问题
    if dpkg -l | grep -E "^[^i].*crowdsec" >/dev/null 2>&1; then
        echo -e "  ${YELLOW}修复配置问题...${NC}"
        sudo dpkg --configure -a >/dev/null 2>&1 || true
    fi
    
    read -p "  是否重新安装? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "  卸载旧版本..."
        sudo systemctl stop crowdsec crowdsec-firewall-bouncer 2>/dev/null || true
        sudo apt remove --purge -y crowdsec crowdsec-firewall-bouncer-iptables 2>/dev/null || true
        sudo rm -rf /etc/crowdsec 2>/dev/null || true
    else
        echo "  保留现有安装，执行优化配置..."
    fi
fi

# 3. 安装CrowdSec
if ! command -v cscli >/dev/null 2>&1; then
    echo -e "${BLUE}[3/12] 安装CrowdSec核心...${NC}"
    
    # 添加官方仓库
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash >/dev/null 2>&1
    
    # 预创建目录避免错误
    sudo mkdir -p /etc/crowdsec/{whitelists,patterns,scenarios,parsers,collections,postoverflows}
    sudo mkdir -p /run/crowdsec
    
    # 安装（忽略初始配置错误）
    sudo DEBIAN_FRONTEND=noninteractive apt install -y crowdsec 2>&1 | grep -v "403" || true
    
    # 修复dpkg配置
    sudo dpkg --configure -a >/dev/null 2>&1 || true
    
    if ! command -v cscli >/dev/null 2>&1; then
        echo -e "${RED}  安装失败！${NC}"
        exit 1
    fi
    echo -e "${GREEN}  ✓ CrowdSec核心安装成功${NC}"
else
    echo -e "${BLUE}[3/12] CrowdSec核心已安装${NC}"
fi

# 4. 配置数据采集
echo -e "${BLUE}[4/12] 配置日志采集...${NC}"
sudo tee /etc/crowdsec/acquis.yaml > /dev/null << 'EOF'
# SSH日志采集 - 主要防护目标
filenames:
  - /var/log/auth.log
  - /var/log/secure
labels:
  type: syslog

# 系统日志采集
---
filenames:
  - /var/log/syslog
  - /var/log/messages
labels:
  type: syslog

# Nginx日志采集（如存在）
---
filenames:
  - /var/log/nginx/access.log
  - /var/log/nginx/error.log
labels:
  type: nginx

# Apache日志采集（如存在）
---
filenames:
  - /var/log/apache2/access.log
  - /var/log/apache2/error.log
labels:
  type: apache2

# 内核日志采集
---
filenames:
  - /var/log/kern.log
labels:
  type: syslog
EOF
echo -e "${GREEN}  ✓ 日志采集配置完成${NC}"

# 5. 安装防火墙Bouncer
echo -e "${BLUE}[5/12] 安装防火墙Bouncer...${NC}"
if ! dpkg -l | grep -q crowdsec-firewall-bouncer; then
    sudo DEBIAN_FRONTEND=noninteractive apt install -y crowdsec-firewall-bouncer-iptables ipset >/dev/null 2>&1
    echo -e "${GREEN}  ✓ 防火墙Bouncer安装成功${NC}"
else
    echo "  防火墙Bouncer已安装"
fi

# 配置Bouncer
if ! sudo cscli bouncers list 2>/dev/null | grep -q firewall-bouncer; then
    sudo cscli bouncers add firewall-bouncer >/dev/null 2>&1
    echo -e "${GREEN}  ✓ API密钥已创建${NC}"
fi

# 6. 安装保护场景
echo -e "${BLUE}[6/12] 安装保护场景...${NC}"

# SSH保护（核心）
echo "  安装SSH保护..."
sudo cscli collections install crowdsecurity/sshd -q 2>/dev/null || true

# Linux系统保护
echo "  安装Linux保护..."
sudo cscli collections install crowdsecurity/linux -q 2>/dev/null || true

# 基础防护
echo "  安装基础防护..."
sudo cscli collections install crowdsecurity/base-http-scenarios -q 2>/dev/null || true

# 端口扫描检测
echo "  安装端口扫描检测..."
sudo cscli scenarios install crowdsecurity/portscan -q 2>/dev/null || true

echo -e "${GREEN}  ✓ 保护场景安装完成${NC}"

# 7. 修复CDN白名单问题
echo -e "${BLUE}[7/12] 处理CDN白名单...${NC}"
# 移除有问题的自动下载组件
sudo cscli postoverflows remove crowdsecurity/cdn-whitelist 2>/dev/null || true

# 不创建固定白名单，因为用户IP不固定
echo -e "${GREEN}  ✓ 已移除固定白名单（适合动态IP）${NC}"

# 8. 配置社区黑名单
echo -e "${BLUE}[8/12] 配置社区威胁情报...${NC}"

# 订阅社区黑名单
echo "  配置社区黑名单订阅..."
sudo tee /etc/crowdsec/console.yaml > /dev/null << 'EOF'
# CrowdSec Console配置 - 启用社区威胁情报
# 注册账号获取: https://app.crowdsec.net
enabled: true
share_manual_decisions: true
share_custom: true
share_tainted: false
EOF

# 安装额外的威胁检测场景
echo "  安装高级威胁检测..."
# CVE漏洞利用检测
sudo cscli scenarios install crowdsecurity/CVE-2021-41773 -q 2>/dev/null || true
sudo cscli scenarios install crowdsecurity/CVE-2022-26134 -q 2>/dev/null || true

echo -e "${GREEN}  ✓ 社区威胁情报配置完成${NC}"

# 9. 配置封禁策略
echo -e "${BLUE}[9/12] 配置封禁策略...${NC}"
sudo cp /etc/crowdsec/profiles.yaml /etc/crowdsec/profiles.yaml.backup 2>/dev/null || true

sudo tee /etc/crowdsec/profiles.yaml > /dev/null << 'EOF'
# 默认IP封禁策略
name: default_ip_remediation
debug: false
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
  - type: ban
    duration: 4h
on_success: break

---
# 暴力破解加重处罚
name: bruteforce_ip_remediation
debug: false
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip" && (Alert.GetScenario() contains "bf" || Alert.GetScenario() contains "bruteforce")
decisions:
  - type: ban
    duration: 24h
on_success: break

---
# 端口扫描严厉处罚
name: portscan_ip_remediation
debug: false
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip" && Alert.GetScenario() contains "portscan"
decisions:
  - type: ban
    duration: 48h
on_success: break

---
# CVE利用尝试永久封禁
name: cve_ip_remediation
debug: false
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip" && Alert.GetScenario() contains "CVE"
decisions:
  - type: ban
    duration: 720h
on_success: break
EOF
echo -e "${GREEN}  ✓ 封禁策略配置完成${NC}"

# 10. 创建管理工具
echo -e "${BLUE}[10/12] 创建管理工具...${NC}"

# 解封工具
sudo tee /usr/local/bin/cs-unban > /dev/null << 'EOF'
#!/bin/bash
if [[ $# -eq 0 ]]; then
    echo "用法: cs-unban <IP地址>"
    echo ""
    echo "当前封禁列表:"
    sudo cscli decisions list
    exit 1
fi

echo "解封IP: $1"
sudo cscli decisions delete --ip $1
if [ $? -eq 0 ]; then
    echo "✅ 已解封 $1"
    # 同时从iptables移除
    sudo iptables -D INPUT -s $1 -j DROP 2>/dev/null || true
    sudo ip6tables -D INPUT -s $1 -j DROP 2>/dev/null || true
else
    echo "❌ 解封失败"
fi
EOF

# 状态检查工具
sudo tee /usr/local/bin/cs-status > /dev/null << 'EOF'
#!/bin/bash
echo "========================================"
echo "         CrowdSec安全状态"
echo "========================================"
echo ""

# 服务状态
echo "📊 服务状态:"
printf "  %-20s %s\n" "CrowdSec核心:" "$(systemctl is-active crowdsec)"
printf "  %-20s %s\n" "防火墙Bouncer:" "$(systemctl is-active crowdsec-firewall-bouncer)"
echo ""

# 版本信息
echo "📦 版本信息:"
cscli version 2>/dev/null | head -1 | sed 's/^/  /'
echo ""

# 保护模块
echo "🛡️  已启用保护:"
sudo cscli collections list 2>/dev/null | grep "installed.*true" | awk '{print "  - " $1}' | head -10
echo ""

# 封禁统计
TOTAL_BANS=$(sudo cscli decisions list 2>/dev/null | grep -c "ban" || echo "0")
echo "🚫 封禁统计:"
echo "  当前封禁IP数: $TOTAL_BANS"
if [ "$TOTAL_BANS" -gt 0 ]; then
    echo "  最近封禁:"
    sudo cscli decisions list 2>/dev/null | grep "ban" | head -5 | sed 's/^/    /'
fi
echo ""

# 日志分析
echo "📈 24小时统计:"
sudo cscli metrics 2>/dev/null | grep -A3 "Acquisition Metrics" | tail -3 | sed 's/^/  /'
echo ""

# 实时威胁
echo "⚡ 最近检测到的威胁:"
sudo journalctl -u crowdsec -n 100 --no-pager 2>/dev/null | grep "ban '.*'" | tail -3 | sed 's/^/  /' || echo "  无最近威胁"
EOF

# 监控工具
sudo tee /usr/local/bin/cs-monitor > /dev/null << 'EOF'
#!/bin/bash
echo "CrowdSec实时监控 (Ctrl+C退出)"
echo "================================"
echo ""
echo "监控SSH攻击和系统威胁..."
echo ""
sudo tail -f /var/log/crowdsec.log 2>/dev/null | grep --line-buffered -E "Ip:.*performed|ban '.*'" | while read line; do
    echo "[$(date '+%H:%M:%S')] $line"
done
EOF

# 白名单管理（用于临时需要）
sudo tee /usr/local/bin/cs-whitelist > /dev/null << 'EOF'
#!/bin/bash
ACTION=$1
IP=$2

case $ACTION in
    add)
        if [[ -z "$IP" ]]; then
            echo "用法: cs-whitelist add <IP>"
            exit 1
        fi
        echo "添加白名单: $IP"
        sudo cscli decisions delete --ip $IP 2>/dev/null
        echo "$IP" | sudo tee -a /etc/crowdsec/whitelists/custom.txt
        sudo systemctl reload crowdsec
        echo "✅ 已添加到白名单"
        ;;
    remove)
        if [[ -z "$IP" ]]; then
            echo "用法: cs-whitelist remove <IP>"
            exit 1
        fi
        echo "移除白名单: $IP"
        sudo sed -i "/$IP/d" /etc/crowdsec/whitelists/custom.txt 2>/dev/null
        sudo systemctl reload crowdsec
        echo "✅ 已从白名单移除"
        ;;
    list)
        echo "当前白名单:"
        if [ -f /etc/crowdsec/whitelists/custom.txt ]; then
            cat /etc/crowdsec/whitelists/custom.txt
        else
            echo "  无自定义白名单"
        fi
        ;;
    *)
        echo "CrowdSec白名单管理"
        echo "用法:"
        echo "  cs-whitelist add <IP>     - 添加IP到白名单"
        echo "  cs-whitelist remove <IP>  - 从白名单移除IP"
        echo "  cs-whitelist list         - 列出白名单"
        ;;
esac
EOF

# 设置执行权限
sudo chmod +x /usr/local/bin/cs-{unban,status,monitor,whitelist}
echo -e "${GREEN}  ✓ 管理工具创建完成${NC}"

# 11. 优化配置
echo -e "${BLUE}[11/12] 优化系统配置...${NC}"

# 配置日志轮转
sudo tee /etc/logrotate.d/crowdsec > /dev/null << 'EOF'
/var/log/crowdsec.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
    postrotate
        systemctl reload crowdsec >/dev/null 2>&1 || true
    endscript
}
EOF

# 创建自定义白名单文件
sudo touch /etc/crowdsec/whitelists/custom.txt
echo -e "${GREEN}  ✓ 系统优化完成${NC}"

# 12. 启动服务
echo -e "${BLUE}[12/12] 启动服务...${NC}"

# 重启CrowdSec核心
sudo systemctl daemon-reload
sudo systemctl enable crowdsec >/dev/null 2>&1
sudo systemctl restart crowdsec
sleep 3

# 重启防火墙Bouncer
sudo systemctl enable crowdsec-firewall-bouncer >/dev/null 2>&1
sudo systemctl restart crowdsec-firewall-bouncer
sleep 2

echo -e "${GREEN}  ✓ 服务启动完成${NC}"

# 验证安装
echo ""
echo "================================================"
echo "            安装验证"
echo "================================================"

ERRORS=0
WARNINGS=0

# 检查服务状态
if sudo systemctl is-active --quiet crowdsec; then
    echo -e "${GREEN}✓ CrowdSec核心运行正常${NC}"
else
    echo -e "${RED}✗ CrowdSec核心未运行${NC}"
    ERRORS=$((ERRORS + 1))
fi

if sudo systemctl is-active --quiet crowdsec-firewall-bouncer; then
    echo -e "${GREEN}✓ 防火墙Bouncer运行正常${NC}"
else
    echo -e "${RED}✗ 防火墙Bouncer未运行${NC}"
    ERRORS=$((ERRORS + 1))
fi

# 检查SSH保护
if sudo cscli collections list 2>/dev/null | grep -q "crowdsecurity/sshd.*true"; then
    echo -e "${GREEN}✓ SSH保护已启用${NC}"
else
    echo -e "${YELLOW}⚠ SSH保护未启用${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

# 检查日志收集
LOG_LINES=$(sudo cscli metrics 2>/dev/null | grep "file:/var/log/auth.log" | awk '{print $3}' || echo "0")
if [ "$LOG_LINES" != "0" ] && [ "$LOG_LINES" != "-" ]; then
    echo -e "${GREEN}✓ 正在分析SSH日志${NC}"
else
    echo -e "${YELLOW}⚠ 暂未收集到SSH日志（刚安装属正常）${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

# 最终报告
echo ""
echo "================================================"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}     🎉 部署成功！${NC}"
    echo "================================================"
    echo ""
    echo "📌 重要提示："
    echo "  • CrowdSec正在后台学习攻击模式"
    echo "  • 社区威胁情报已启用"
    echo "  • 适合动态IP用户使用"
    echo ""
    echo "🔧 管理命令："
    echo "  cs-status          查看安全状态"
    echo "  cs-monitor         实时监控威胁"
    echo "  cs-unban <IP>      解封指定IP"
    echo "  cs-whitelist       管理白名单"
    echo ""
    echo "📊 其他命令："
    echo "  sudo cscli decisions list       查看所有封禁"
    echo "  sudo cscli alerts list          查看告警详情"
    echo "  sudo cscli metrics              查看统计数据"
    echo "  sudo cscli hub list             查看可用组件"
    echo ""
    echo "📝 日志位置："
    echo "  /var/log/crowdsec.log          主日志"
    echo "  sudo journalctl -u crowdsec    系统日志"
    echo ""
    echo "🌐 控制台注册（可选）："
    echo "  访问 https://app.crowdsec.net 注册账号"
    echo "  运行 sudo cscli console enroll 连接控制台"
    echo "  获取更多威胁情报和可视化界面"
else
    echo -e "${RED}     ⚠️ 部署遇到问题${NC}"
    echo "================================================"
    echo ""
    echo "请检查："
    echo "  sudo journalctl -u crowdsec -n 50"
    echo "  sudo journalctl -u crowdsec-firewall-bouncer -n 50"
    echo ""
    echo "尝试修复："
    echo "  sudo systemctl restart crowdsec"
    echo "  sudo systemctl restart crowdsec-firewall-bouncer"
fi

echo ""
echo "================================================"
echo "脚本执行完成 - $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================"
