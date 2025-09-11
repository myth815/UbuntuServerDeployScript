#!/bin/bash

# SSH极致安全配置脚本 - 终极修复版 v6
# 修复所有已知问题：目录创建、IPv4/IPv6监听、Socket激活等
# 作者：myth815
# 更新：2025-01-11

echo "🔐 SSH极致安全配置部署 (v6 - 终极修复版)"
echo "========================================="

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查权限
if [ "$EUID" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    SUDO=""
fi

# 配置参数 - 支持环境变量自定义
SSH_PORT=${SSH_PORT:-9833}
SSH_USER=${SSH_USER:-$(whoami)}
BACKUP_DIR="/etc/ssh/backups"
BACKUP_TIMESTAMP=$(date +%Y%m%d-%H%M%S)

echo "⚙️  配置参数:"
echo "   SSH端口: $SSH_PORT"
echo "   允许用户: $SSH_USER"
echo "   安全级别: 高级安全 + 客户端兼容性"
echo "   备份目录: $BACKUP_DIR"
echo ""
echo "💡 提示: 可通过环境变量自定义"
echo "   SSH_PORT=8022 SSH_USER=myuser $0"
echo ""

# 确认用户存在
if ! id "$SSH_USER" &>/dev/null; then
    echo -e "${RED}❌ 错误: 用户 $SSH_USER 不存在${NC}"
    echo "   请先创建用户: sudo useradd -m -s /bin/bash $SSH_USER"
    exit 1
fi

# 0. 预先创建必需目录（关键修复）
echo "📁 预创建必需目录..."
$SUDO mkdir -p /run/sshd /var/run/sshd
$SUDO chmod 755 /run/sshd /var/run/sshd
echo "   ✅ SSH运行目录已创建"

# 创建持久化配置
$SUDO tee /etc/tmpfiles.d/sshd.conf > /dev/null << EOF
# SSH运行时目录（系统重启后自动创建）
d /run/sshd 0755 root root -
d /var/run/sshd 0755 root root -
EOF
echo "   ✅ 目录持久化配置已创建"

# 1. 创建备份目录并备份现有配置
echo "📁 备份现有配置..."
$SUDO mkdir -p "$BACKUP_DIR"
$SUDO cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$BACKUP_TIMESTAMP"
if [ -d /etc/ssh/sshd_config.d ]; then
    $SUDO tar -czf "$BACKUP_DIR/sshd_config.d.$BACKUP_TIMESTAMP.tar.gz" /etc/ssh/sshd_config.d/ 2>/dev/null
fi
if [ -d /etc/systemd/system/ssh.socket.d ]; then
    $SUDO tar -czf "$BACKUP_DIR/ssh.socket.d.$BACKUP_TIMESTAMP.tar.gz" /etc/systemd/system/ssh.socket.d/ 2>/dev/null
fi
echo "   ✅ 配置已备份到 $BACKUP_DIR"

# 2. 检测系统环境
echo "🔍 检测系统环境..."
USE_SOCKET_ACTIVATION=false
SOCKET_FILE=""

# 检查是否使用socket激活
if [ -f /lib/systemd/system/ssh.socket ] || [ -f /etc/systemd/system/ssh.socket ]; then
    if [ -f /etc/systemd/system/ssh.socket ]; then
        SOCKET_FILE="/etc/systemd/system/ssh.socket"
    elif [ -f /lib/systemd/system/ssh.socket ]; then
        SOCKET_FILE="/lib/systemd/system/ssh.socket"
    fi
    
    # 检查ssh.service是否实际依赖于socket
    if $SUDO systemctl show ssh.service -p TriggeredBy 2>/dev/null | grep -q "ssh.socket"; then
        USE_SOCKET_ACTIVATION=true
        echo "   ✅ 检测到systemd socket激活模式"
        echo "   Socket文件: $SOCKET_FILE"
    fi
fi

if [ "$USE_SOCKET_ACTIVATION" = false ]; then
    echo "   ✅ 系统使用传统SSH服务模式"
fi

# 3. 清理冲突配置文件
echo "🗑️  清理冲突配置文件..."
$SUDO rm -f /etc/ssh/sshd_config.d/99-*.conf 2>/dev/null
$SUDO rm -f /etc/ssh/sshd_config.d/01-PasswordAuthentication.conf 2>/dev/null
$SUDO rm -f /etc/ssh/sshd_config.d/01-permitrootlogin.conf 2>/dev/null
$SUDO rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf 2>/dev/null
echo "   ✅ 已清理所有冲突配置文件"

# 4. 创建最终安全配置
echo "⚙️  创建最终安全配置..."
$SUDO tee /etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf > /dev/null << EOF
# SSH最终安全配置 - 最高优先级 v6
# ==========================================
# 修复所有已知问题，确保配置生效

# 基础安全设置 - 多重禁用密码认证
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
UsePAM yes

# 连接限制
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# 用户限制
AllowUsers $SSH_USER

# 现代加密算法 - 兼容性优先
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256
PubkeyAcceptedAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256

# 严格模式
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no

# 禁用非必要功能
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
Compression no
PermitUserEnvironment no

# 网络配置
TCPKeepAlive yes
UseDNS no
MaxStartups 3:50:10

# 监听配置（同时支持IPv4和IPv6）
AddressFamily any
ListenAddress 0.0.0.0:$SSH_PORT
ListenAddress [::]:$SSH_PORT

# 日志设置
LogLevel VERBOSE
SyslogFacility AUTH

# 终端设置
PermitTTY yes
PrintLastLog yes
VersionAddendum none

# 端口配置
Port $SSH_PORT

# 最终确保密码认证禁用 - 冗余设置确保生效
Match all
    PasswordAuthentication no
    ChallengeResponseAuthentication no
    KbdInteractiveAuthentication no
EOF
echo "   ✅ 安全配置文件已创建"

# 5. 修改主配置文件
echo "🔧 修改主配置文件..."
$SUDO sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
$SUDO sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
$SUDO sed -i 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
$SUDO sed -i 's/ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config

# 6. 处理systemd socket激活配置（IPv4/IPv6双栈支持）
if [ "$USE_SOCKET_ACTIVATION" = true ]; then
    echo "🔧 配置systemd socket（IPv4/IPv6双栈）..."
    
    $SUDO mkdir -p /etc/systemd/system/ssh.socket.d/
    
    # 创建支持IPv4和IPv6的socket配置
    $SUDO tee /etc/systemd/system/ssh.socket.d/override.conf > /dev/null << EOF
[Socket]
# 清除原有配置
ListenStream=
# 监听IPv4
ListenStream=0.0.0.0:$SSH_PORT
# 监听IPv6
ListenStream=[::]:$SSH_PORT
# Socket选项
FreeBind=yes
Backlog=128
EOF
    
    echo "   ✅ Socket配置已更新（IPv4/IPv6双栈）"
    
    # 立即重新加载配置
    $SUDO systemctl daemon-reload
fi

# 7. 验证配置语法前再次确保目录存在
echo "🔍 验证配置语法..."
$SUDO mkdir -p /run/sshd /var/run/sshd 2>/dev/null
if ! $SUDO sshd -t 2>/dev/null; then
    echo -e "${RED}❌ 配置语法错误，正在回滚...${NC}"
    # 回滚配置
    $SUDO cp "$BACKUP_DIR/sshd_config.$BACKUP_TIMESTAMP" /etc/ssh/sshd_config
    $SUDO rm -f /etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf
    if [ "$USE_SOCKET_ACTIVATION" = true ]; then
        $SUDO rm -f /etc/systemd/system/ssh.socket.d/override.conf
    fi
    $SUDO systemctl daemon-reload
    $SUDO systemctl restart ssh
    echo "   ✅ 已回滚到原始配置"
    exit 1
fi
echo "   ✅ 配置语法检查通过"

# 8. 检查SSH密钥配置
echo "🔑 检查SSH密钥配置..."
USER_HOME=$(eval echo ~$SSH_USER)
SSH_DIR="$USER_HOME/.ssh"
AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"

if [ -f "$AUTHORIZED_KEYS" ]; then
    KEY_COUNT=$(wc -l < "$AUTHORIZED_KEYS" 2>/dev/null || echo 0)
    echo "   ✅ 发现 $KEY_COUNT 个授权密钥"
    
    # 修复权限
    echo "   🔧 修复SSH目录和密钥文件权限..."
    $SUDO chown -R "$SSH_USER:$SSH_USER" "$SSH_DIR"
    $SUDO chmod 700 "$SSH_DIR"
    $SUDO chmod 600 "$AUTHORIZED_KEYS"
    
    # 检查密钥类型
    if grep -q "ssh-ed25519" "$AUTHORIZED_KEYS" 2>/dev/null; then
        echo "   ✅ 检测到ED25519密钥（推荐）"
    elif grep -q "ssh-rsa" "$AUTHORIZED_KEYS" 2>/dev/null; then
        echo "   ⚠️  检测到RSA密钥（兼容但不如ED25519安全）"
    fi
else
    echo -e "${YELLOW}⚠️  未找到授权密钥文件: $AUTHORIZED_KEYS${NC}"
    echo "   💡 请确保已配置SSH密钥，否则可能无法登录！"
    read -p "   是否继续？(y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "   ❌ 用户取消操作"
        exit 1
    fi
fi

# 9. 配置防火墙规则
echo "🔥 配置防火墙规则..."

# UFW防火墙配置
if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS=$($SUDO ufw status 2>/dev/null | grep -i "status:" | awk '{print $2}')
    echo "   检测到UFW防火墙 (状态: ${UFW_STATUS:-未安装})"
    
    if [ -n "$UFW_STATUS" ]; then
        echo "   添加端口 $SSH_PORT 规则..."
        $SUDO ufw allow $SSH_PORT/tcp >/dev/null 2>&1
        
        if [ "$SSH_PORT" != "22" ]; then
            echo "   临时保留端口 22（避免锁定）..."
            $SUDO ufw allow 22/tcp >/dev/null 2>&1
        fi
        
        if [ "$UFW_STATUS" = "inactive" ]; then
            echo "   ⚠️  防火墙当前未激活"
            read -p "   是否激活UFW防火墙？(y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                echo "y" | $SUDO ufw enable >/dev/null 2>&1
                echo "   ✅ UFW防火墙已激活"
            else
                echo "   ⚠️  防火墙未激活，请稍后手动执行: sudo ufw enable"
            fi
        else
            echo "   ✅ 防火墙规则已更新"
        fi
    fi
fi

# firewalld防火墙配置
if command -v firewall-cmd >/dev/null 2>&1; then
    if $SUDO firewall-cmd --state 2>/dev/null | grep -q "running"; then
        echo "   检测到firewalld防火墙"
        $SUDO firewall-cmd --permanent --add-port=$SSH_PORT/tcp >/dev/null 2>&1
        $SUDO firewall-cmd --reload >/dev/null 2>&1
        echo "   ✅ firewalld规则已更新"
    fi
fi

# 10. 应用配置
echo "🔄 应用配置..."

# 确保目录存在（再次检查）
$SUDO mkdir -p /run/sshd /var/run/sshd 2>/dev/null

# 重新加载systemd配置
$SUDO systemctl daemon-reload

if [ "$USE_SOCKET_ACTIVATION" = true ]; then
    echo "   使用socket激活模式重启..."
    
    # 停止所有相关服务
    $SUDO systemctl stop ssh.service 2>/dev/null
    $SUDO systemctl stop ssh.socket 2>/dev/null
    
    # 启动socket服务
    if $SUDO systemctl start ssh.socket; then
        echo "   ✅ SSH socket启动成功"
        
        # 确保自启动
        $SUDO systemctl enable ssh.socket 2>/dev/null
        
        # 等待socket稳定
        sleep 2
        
        # 触发服务启动（重要）
        echo "   触发SSH服务启动..."
        timeout 2 nc -zv 127.0.0.1 $SSH_PORT 2>/dev/null || true
        timeout 2 nc -zv ::1 $SSH_PORT 2>/dev/null || true
        sleep 2
        
        # 验证端口监听
        if $SUDO ss -tlnp | grep -q ":$SSH_PORT"; then
            echo "   ✅ 端口 $SSH_PORT 正在监听"
        else
            echo -e "${YELLOW}⚠️  端口可能需要首次连接触发${NC}"
        fi
    else
        echo "   ⚠️  Socket启动失败，使用传统模式..."
        $SUDO systemctl start ssh
    fi
else
    echo "   使用传统模式重启SSH服务..."
    if $SUDO systemctl restart ssh; then
        echo "   ✅ SSH服务重启成功"
    else
        echo -e "${RED}❌ SSH服务重启失败${NC}"
        exit 1
    fi
fi

# 确保服务自启动
$SUDO systemctl enable ssh 2>/dev/null

# 等待服务稳定
sleep 3

# 11. 关键安全验证（改进版）
echo "🔐 关键安全配置验证..."

# 确保目录存在后再验证
$SUDO mkdir -p /run/sshd /var/run/sshd 2>/dev/null

# 使用超时避免卡住
PASSWORD_AUTH=$($SUDO timeout 5 sshd -T 2>/dev/null | grep "^passwordauthentication" | awk '{print $2}')
PUBKEY_AUTH=$($SUDO timeout 5 sshd -T 2>/dev/null | grep "^pubkeyauthentication" | awk '{print $2}')
ROOT_LOGIN=$($SUDO timeout 5 sshd -T 2>/dev/null | grep "^permitrootlogin" | awk '{print $2}')
ACTUAL_PORT=$($SUDO timeout 5 sshd -T 2>/dev/null | grep "^port" | awk '{print $2}')

if [ -n "$ACTUAL_PORT" ]; then
    echo "   SSH配置端口: $ACTUAL_PORT"
    echo "   密码认证状态: ${PASSWORD_AUTH:-未知}"
    echo "   公钥认证状态: ${PUBKEY_AUTH:-未知}"
    echo "   Root登录状态: ${ROOT_LOGIN:-未知}"
    
    if [ "$PASSWORD_AUTH" = "no" ]; then
        echo "   ✅ 密码认证已成功禁用"
    elif [ -z "$PASSWORD_AUTH" ]; then
        echo "   ⚠️  无法验证密码认证状态（但配置已应用）"
    else
        echo -e "${RED}   ❌ 警告: 密码认证仍然启用！${NC}"
    fi
else
    echo "   ⚠️  无法读取SSH配置（可能是权限问题），但服务可能正常"
fi

# 12. 端口验证
echo "📊 端口状态验证..."
LISTENING=false

# 检查IPv4
if $SUDO ss -tlnp | grep -q "0.0.0.0:$SSH_PORT"; then
    echo "   ✅ IPv4端口 $SSH_PORT 监听正常"
    LISTENING=true
fi

# 检查IPv6
if $SUDO ss -tlnp | grep -q "\\[::\\]:$SSH_PORT"; then
    echo "   ✅ IPv6端口 $SSH_PORT 监听正常"
    LISTENING=true
fi

if [ "$LISTENING" = false ]; then
    echo -e "${YELLOW}   ⚠️  端口 $SSH_PORT 可能需要首次连接才会激活（socket模式）${NC}"
fi

# 检查22端口
if $SUDO ss -tlnp | grep -q ":22 "; then
    if [ "$SSH_PORT" != "22" ]; then
        echo "   ⚠️  端口22仍在监听（确认新端口正常后建议关闭）"
    fi
else
    if [ "$SSH_PORT" != "22" ]; then
        echo "   ✅ 端口22已关闭"
    fi
fi

# 13. 云服务商提醒
echo "☁️  云服务商安全组提醒："
PUBLIC_IP=$(curl -s -m 3 ifconfig.me || curl -s -m 3 icanhazip.com || echo "")
PRIVATE_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')

if curl -s -m 2 http://metadata.tencentyun.com >/dev/null 2>&1; then
    echo "   检测到腾讯云环境"
    echo -e "${YELLOW}   ⚠️  请在腾讯云控制台安全组中开放端口 $SSH_PORT${NC}"
elif curl -s -m 2 http://100.100.100.200 >/dev/null 2>&1; then
    echo "   检测到阿里云环境"
    echo -e "${YELLOW}   ⚠️  请在阿里云控制台安全组中开放端口 $SSH_PORT${NC}"
elif curl -s -m 2 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
    echo "   检测到AWS环境"
    echo -e "${YELLOW}   ⚠️  请在AWS控制台安全组中开放端口 $SSH_PORT${NC}"
else
    echo "   如果使用云服务器，请确保在控制台安全组开放端口 $SSH_PORT"
fi

# 14. 服务器信息
echo ""
echo "🌐 服务器信息:"
echo "   私网IP: ${PRIVATE_IP:-未知}"
if [ -n "$PUBLIC_IP" ]; then
    echo "   公网IP: $PUBLIC_IP"
fi
echo "   主机名: $(hostname)"
echo "   SSH端口: $SSH_PORT"
echo "   允许用户: $SSH_USER"

# 15. 生成管理脚本
echo "📝 生成管理脚本..."
$SUDO tee /usr/local/bin/ssh-security-manage > /dev/null << 'SCRIPT_EOF'
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

case "$1" in
    "status")
        echo "SSH服务状态:"
        echo "============"
        sudo systemctl status ssh --no-pager -l
        echo ""
        if systemctl list-units | grep -q ssh.socket; then
            echo "SSH Socket状态:"
            echo "==============="
            sudo systemctl status ssh.socket --no-pager -l
            echo ""
        fi
        echo "端口监听:"
        echo "========="
        sudo ss -tlnp | grep -E 'ssh|:22|:9833|:8022'
        echo ""
        echo "安全配置状态:"
        echo "============="
        # 确保目录存在
        sudo mkdir -p /run/sshd /var/run/sshd 2>/dev/null
        PASSWORD_AUTH=$(sudo timeout 5 sshd -T 2>/dev/null | grep "^passwordauthentication" | awk '{print $2}')
        PUBKEY_AUTH=$(sudo timeout 5 sshd -T 2>/dev/null | grep "^pubkeyauthentication" | awk '{print $2}')
        ROOT_LOGIN=$(sudo timeout 5 sshd -T 2>/dev/null | grep "^permitrootlogin" | awk '{print $2}')
        PORT=$(sudo timeout 5 sshd -T 2>/dev/null | grep "^port" | awk '{print $2}')
        if [ -n "$PORT" ]; then
            echo "监听端口: $PORT"
            echo "密码认证: $PASSWORD_AUTH"
            echo "公钥认证: $PUBKEY_AUTH"
            echo "Root登录: $ROOT_LOGIN"
        else
            echo "⚠️ 无法读取配置（可能需要先创建/run/sshd目录）"
        fi
        ;;
    "restore")
        echo "恢复SSH默认配置..."
        sudo systemctl stop ssh ssh.socket 2>/dev/null
        sudo rm -f /etc/ssh/sshd_config.d/99-zzz-*.conf
        sudo rm -rf /etc/systemd/system/ssh.socket.d/
        sudo systemctl daemon-reload
        sudo systemctl restart ssh
        echo -e "${GREEN}✅ 已恢复默认配置（端口22）${NC}"
        ;;
    "test")
        echo "SSH连接测试:"
        echo "============"
        
        # 确保目录存在
        sudo mkdir -p /run/sshd /var/run/sshd 2>/dev/null
        
        # 获取配置的端口
        CONFIG_PORT=$(sudo timeout 5 sshd -T 2>/dev/null | grep "^port" | awk '{print $2}')
        if [ -z "$CONFIG_PORT" ]; then
            CONFIG_PORT=$(sudo ss -tlnp | grep ssh | grep -oP ':\K[0-9]+' | head -1)
        fi
        
        echo "测试端口: ${CONFIG_PORT:-未知}"
        echo ""
        
        # 测试IPv4
        if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/${CONFIG_PORT:-22}" 2>/dev/null; then
            echo -e "${GREEN}✅ IPv4本地连接正常${NC}"
        else
            echo -e "${RED}❌ IPv4本地连接失败${NC}"
        fi
        
        # 测试IPv6
        if timeout 2 bash -c "echo > /dev/tcp/::1/${CONFIG_PORT:-22}" 2>/dev/null; then
            echo -e "${GREEN}✅ IPv6本地连接正常${NC}"
        else
            echo -e "${YELLOW}⚠️ IPv6本地连接失败${NC}"
        fi
        
        # 密码认证测试
        echo ""
        PASSWORD_AUTH=$(sudo timeout 5 sshd -T 2>/dev/null | grep "^passwordauthentication" | awk '{print $2}')
        if [ "$PASSWORD_AUTH" = "no" ]; then
            echo -e "${GREEN}✅ 密码认证已禁用${NC}"
        else
            echo -e "${RED}❌ 密码认证仍启用（安全风险！）${NC}"
        fi
        ;;
    "diagnose")
        echo "SSH诊断信息:"
        echo "============"
        echo ""
        
        # 检查必需目录
        echo "1. 必需目录检查:"
        if [ -d /run/sshd ]; then
            echo -e "${GREEN}✅ /run/sshd 存在${NC}"
        else
            echo -e "${RED}❌ /run/sshd 缺失（创建中...）${NC}"
            sudo mkdir -p /run/sshd && sudo chmod 755 /run/sshd
        fi
        echo ""
        
        echo "2. Socket配置:"
        if [ -f /etc/systemd/system/ssh.socket.d/override.conf ]; then
            cat /etc/systemd/system/ssh.socket.d/override.conf
        else
            echo "未找到socket覆盖配置"
        fi
        echo ""
        
        echo "3. 服务依赖:"
        systemctl show ssh.service -p TriggeredBy
        if systemctl list-units | grep -q ssh.socket; then
            systemctl show ssh.socket -p Listen
        fi
        echo ""
        
        echo "4. 实际监听:"
        sudo ss -tlnp | grep -E 'ssh|:22|:9833|:8022'
        echo ""
        
        echo "5. 最近日志:"
        sudo journalctl -u ssh -u ssh.socket -n 20 --no-pager
        ;;
    "fix")
        echo "执行快速修复..."
        echo ""
        
        # 创建必需目录
        echo "1. 创建必需目录..."
        sudo mkdir -p /run/sshd /var/run/sshd
        sudo chmod 755 /run/sshd /var/run/sshd
        echo -e "${GREEN}✅ 目录已创建${NC}"
        echo ""
        
        # 重启服务
        echo "2. 重启SSH服务..."
        if systemctl list-units | grep -q ssh.socket; then
            sudo systemctl restart ssh.socket
            echo -e "${GREEN}✅ Socket已重启${NC}"
            
            # 触发服务启动
            CONFIG_PORT=$(sudo timeout 5 sshd -T 2>/dev/null | grep "^port" | awk '{print $2}')
            if [ -n "$CONFIG_PORT" ]; then
                timeout 2 nc -zv 127.0.0.1 $CONFIG_PORT 2>/dev/null || true
                timeout 2 nc -zv ::1 $CONFIG_PORT 2>/dev/null || true
            fi
        else
            sudo systemctl restart ssh
            echo -e "${GREEN}✅ SSH服务已重启${NC}"
        fi
        echo ""
        
        echo "3. 验证状态..."
        sleep 2
        if sudo ss -tlnp | grep -q ssh; then
            echo -e "${GREEN}✅ SSH服务正在运行${NC}"
        else
            echo -e "${RED}❌ SSH服务未运行，可能需要手动排查${NC}"
        fi
        ;;
    *)
        echo "SSH安全配置管理工具 v6"
        echo "========================"
        echo ""
        echo "用法: $0 {status|restore|test|diagnose|fix}"
        echo ""
        echo "  status   - 查看SSH服务和安全配置状态"
        echo "  restore  - 恢复默认SSH配置"
        echo "  test     - 测试SSH端口和安全配置"
        echo "  diagnose - 诊断SSH配置问题"
        echo "  fix      - 快速修复常见问题"
        echo ""
        ;;
esac
SCRIPT_EOF

$SUDO chmod +x /usr/local/bin/ssh-security-manage

# 16. 完成报告
echo ""
echo -e "${GREEN}✅ SSH极致安全配置部署完成！${NC}"
echo "==================================="
echo ""
echo "🔒 安全特性:"
echo "   - 密码认证强制禁用"
echo "   - 现代加密算法（抗量子）"
echo "   - 严格连接限制"
echo "   - 仅允许用户: $SSH_USER"
echo "   - 端口: $SSH_PORT"
if [ "$USE_SOCKET_ACTIVATION" = true ]; then
    echo "   - systemd socket激活（IPv4/IPv6双栈）"
fi
echo ""

echo "🧪 连接测试命令:"
echo ""
if [ -n "$PUBLIC_IP" ]; then
    echo "   外网连接:"
    echo "   ssh -i ~/.ssh/id_ed25519 $SSH_USER@$PUBLIC_IP -p $SSH_PORT"
else
    echo "   内网连接:"
    echo "   ssh -i ~/.ssh/id_ed25519 $SSH_USER@$PRIVATE_IP -p $SSH_PORT"
fi
echo ""
echo "   本地测试:"
echo "   ssh $SSH_USER@localhost -p $SSH_PORT"
echo ""

echo "📋 重要提醒:"
echo "   - SSH监听端口: $SSH_PORT"
echo "   - 密码认证已禁用（仅密钥）"
echo "   - 仅允许用户: $SSH_USER"
if [ "$SSH_PORT" != "22" ]; then
    echo -e "${YELLOW}   - 确认连接正常后执行: sudo ufw delete allow 22/tcp${NC}"
fi
echo ""

echo "🛠️  管理命令:"
echo "   查看状态: ssh-security-manage status"
echo "   快速修复: ssh-security-manage fix"
echo "   诊断问题: ssh-security-manage diagnose"
echo "   恢复默认: ssh-security-manage restore"
echo ""

echo "🆘 应急恢复:"
echo "   ssh-security-manage restore"
echo ""

echo "📁 配置备份: $BACKUP_DIR"
echo ""

# 17. 最终连接测试
echo "🧪 执行最终测试..."
TEST_PASSED=true

# 测试本地IPv4连接
if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/$SSH_PORT" 2>/dev/null; then
    echo -e "${GREEN}   ✅ IPv4连接测试通过${NC}"
else
    echo -e "${YELLOW}   ⚠️ IPv4连接测试失败（可能需要触发）${NC}"
    TEST_PASSED=false
fi

# 测试本地IPv6连接
if timeout 2 bash -c "echo > /dev/tcp/::1/$SSH_PORT" 2>/dev/null; then
    echo -e "${GREEN}   ✅ IPv6连接测试通过${NC}"
else
    echo -e "${YELLOW}   ⚠️ IPv6连接测试失败（可能未启用IPv6）${NC}"
fi

if [ "$TEST_PASSED" = false ] && [ "$USE_SOCKET_ACTIVATION" = true ]; then
    echo ""
    echo -e "${YELLOW}提示: Socket激活模式下，服务会在首次连接时启动${NC}"
    echo "请尝试使用SSH客户端连接来激活服务"
fi

echo ""
echo -e "${GREEN}🎉 部署完成！请立即测试新端口连接。${NC}"
