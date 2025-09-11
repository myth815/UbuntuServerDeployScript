#!/bin/bash

# SSH极致安全配置脚本 - 完整修复版 v5
# 修复Socket激活端口配置、防火墙自动配置、回滚机制等所有已知问题
# 作者：myth815 (修复版)
# 更新：2025-01-11

echo "🔐 SSH极致安全配置部署 (v5 - 完整修复版)"
echo "========================================="

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
echo "   允许用户: $SSH_USER (当前执行用户)"
echo "   安全级别: 高级安全 + 客户端兼容性"
echo "   备份目录: $BACKUP_DIR"
echo ""
echo "💡 提示: 可通过环境变量自定义"
echo "   SSH_PORT=8022 SSH_USER=myuser $0"
echo ""

# 确认用户存在
if ! id "$SSH_USER" &>/dev/null; then
    echo "❌ 错误: 用户 $SSH_USER 不存在"
    echo "   请先创建用户: sudo useradd -m -s /bin/bash $SSH_USER"
    exit 1
fi

# 1. 创建备份目录并备份现有配置
echo "📁 备份现有配置..."
$SUDO mkdir -p "$BACKUP_DIR"
$SUDO cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$BACKUP_TIMESTAMP"
if [ -d /etc/ssh/sshd_config.d ]; then
    $SUDO tar -czf "$BACKUP_DIR/sshd_config.d.$BACKUP_TIMESTAMP.tar.gz" /etc/ssh/sshd_config.d/ 2>/dev/null
fi
# 备份socket配置（如果存在）
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

# 3. 彻底清理冲突配置文件
echo "🗑️  清理冲突配置文件..."
$SUDO rm -f /etc/ssh/sshd_config.d/99-*.conf 2>/dev/null
# 删除Ubuntu默认的冲突配置文件
$SUDO rm -f /etc/ssh/sshd_config.d/01-PasswordAuthentication.conf 2>/dev/null
$SUDO rm -f /etc/ssh/sshd_config.d/01-permitrootlogin.conf 2>/dev/null
$SUDO rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf 2>/dev/null
echo "   ✅ 已清理所有冲突配置文件"

# 4. 创建最终安全配置（最高优先级）
echo "⚙️  创建最终安全配置..."
$SUDO tee /etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf << EOF
# SSH最终安全配置 - 最高优先级 v5
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

# 5. 同时修改主配置文件确保无冲突
echo "🔧 修改主配置文件..."
$SUDO sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
$SUDO sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
$SUDO sed -i 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
$SUDO sed -i 's/ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config

# 6. 处理systemd socket激活配置（关键修复）
if [ "$USE_SOCKET_ACTIVATION" = true ]; then
    echo "🔧 配置systemd socket端口..."
    
    # 创建socket覆盖配置目录
    $SUDO mkdir -p /etc/systemd/system/ssh.socket.d/
    
    # 创建端口覆盖配置
    $SUDO tee /etc/systemd/system/ssh.socket.d/override.conf << EOF
[Socket]
# 清除原有的监听配置
ListenStream=
# 设置新的监听端口
ListenStream=$SSH_PORT
# 确保IPv6也监听（如果需要）
#ListenStream=[::]:$SSH_PORT
EOF
    
    echo "   ✅ Socket端口配置已更新为 $SSH_PORT"
    
    # 立即重新加载systemd配置
    $SUDO systemctl daemon-reload
    
    # 验证socket配置
    SOCKET_PORT=$($SUDO systemctl show ssh.socket -p Listen 2>/dev/null | grep -oE 'ListenStream=[0-9]+' | cut -d= -f2 | head -1)
    if [ "$SOCKET_PORT" = "$SSH_PORT" ]; then
        echo "   ✅ Socket配置验证成功"
    else
        echo "   ⚠️  Socket配置可能未生效，将在重启服务后再次验证"
    fi
fi

# 7. 创建必要目录
echo "📁 创建必要目录..."
$SUDO mkdir -p /run/sshd

# 8. 验证配置语法
echo "🔍 验证配置语法..."
if ! $SUDO sshd -t; then
    echo "   ❌ 配置语法错误，正在回滚..."
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

# 9. 检查SSH密钥配置
echo "🔑 检查SSH密钥配置..."
USER_HOME=$(eval echo ~$SSH_USER)
SSH_DIR="$USER_HOME/.ssh"
AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"

if [ -f "$AUTHORIZED_KEYS" ]; then
    KEY_COUNT=$(wc -l < "$AUTHORIZED_KEYS" 2>/dev/null || echo 0)
    echo "   ✅ 发现 $KEY_COUNT 个授权密钥"
    
    # 自动修复权限问题
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
    echo "   ⚠️  未找到授权密钥文件: $AUTHORIZED_KEYS"
    echo "   💡 请确保已配置SSH密钥，否则可能无法登录！"
    read -p "   是否继续？(y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "   ❌ 用户取消操作"
        exit 1
    fi
fi

# 10. 配置防火墙规则（新增）
echo "🔥 配置防火墙规则..."

# UFW防火墙配置
if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS=$($SUDO ufw status 2>/dev/null | grep -i "status:" | awk '{print $2}')
    echo "   检测到UFW防火墙 (状态: ${UFW_STATUS:-未安装})"
    
    if [ -n "$UFW_STATUS" ]; then
        # 添加新端口规则
        echo "   添加端口 $SSH_PORT 规则..."
        $SUDO ufw allow $SSH_PORT/tcp >/dev/null 2>&1
        
        # 如果更改了端口，临时保留22端口避免锁定
        if [ "$SSH_PORT" != "22" ]; then
            echo "   临时保留端口 22（避免锁定）..."
            $SUDO ufw allow 22/tcp >/dev/null 2>&1
        fi
        
        # 如果防火墙未激活，询问是否激活
        if [ "$UFW_STATUS" = "inactive" ]; then
            echo "   ⚠️  防火墙当前未激活"
            echo "   建议激活防火墙以提高安全性"
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

# 11. 应用配置
echo "🔄 应用配置..."

# 先重新加载systemd配置
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
        
        # 等待服务稳定
        sleep 3
        
        # 验证端口监听
        if $SUDO ss -tlnp | grep -q ":$SSH_PORT"; then
            echo "   ✅ 端口 $SSH_PORT 正在监听（socket模式）"
        else
            echo "   ❌ 端口 $SSH_PORT 未监听，尝试强制重启..."
            $SUDO systemctl restart ssh.socket
            sleep 2
            if ! $SUDO ss -tlnp | grep -q ":$SSH_PORT"; then
                echo "   ❌ Socket模式失败，切换到传统模式..."
                $SUDO systemctl stop ssh.socket
                $SUDO systemctl start ssh
            fi
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
        echo "   ❌ SSH服务重启失败"
        exit 1
    fi
fi

# 确保服务自启动
$SUDO systemctl enable ssh 2>/dev/null

# 等待服务完全启动
sleep 3

# 12. 关键安全验证
echo "🔐 关键安全配置验证..."
PASSWORD_AUTH=$($SUDO sshd -T 2>/dev/null | grep "^passwordauthentication" | awk '{print $2}')
PUBKEY_AUTH=$($SUDO sshd -T 2>/dev/null | grep "^pubkeyauthentication" | awk '{print $2}')
ROOT_LOGIN=$($SUDO sshd -T 2>/dev/null | grep "^permitrootlogin" | awk '{print $2}')
ACTUAL_PORT=$($SUDO sshd -T 2>/dev/null | grep "^port" | awk '{print $2}')

echo "   SSH配置端口: $ACTUAL_PORT"
echo "   密码认证状态: $PASSWORD_AUTH"
echo "   公钥认证状态: $PUBKEY_AUTH"
echo "   Root登录状态: $ROOT_LOGIN"

if [ "$PASSWORD_AUTH" = "no" ]; then
    echo "   ✅ 密码认证已成功禁用"
else
    echo "   ❌ 警告: 密码认证仍然启用！安全风险！"
fi

# 13. 端口验证
echo "📊 端口状态验证..."
if $SUDO ss -tlnp | grep -q ":$SSH_PORT"; then
    echo "   ✅ 端口 $SSH_PORT 监听正常"
else
    echo "   ❌ 端口 $SSH_PORT 未监听"
    echo "   尝试诊断问题..."
    
    if [ "$USE_SOCKET_ACTIVATION" = true ]; then
        echo "   Socket状态："
        $SUDO systemctl status ssh.socket --no-pager | head -5
    fi
    echo "   SSH服务状态："
    $SUDO systemctl status ssh --no-pager | head -5
fi

if $SUDO ss -tlnp | grep -q ":22"; then
    if [ "$SSH_PORT" != "22" ]; then
        echo "   ⚠️  端口22仍在监听（将在确认新端口正常后关闭）"
    fi
else
    if [ "$SSH_PORT" != "22" ]; then
        echo "   ✅ 端口22已关闭"
    fi
fi

# 14. 云服务商提醒
echo "☁️  云服务商安全组提醒："
PUBLIC_IP=$(curl -s -m 3 ifconfig.me || curl -s -m 3 icanhazip.com || echo "")
PRIVATE_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')

if curl -s -m 2 http://metadata.tencentyun.com >/dev/null 2>&1; then
    echo "   检测到腾讯云环境"
    echo "   ⚠️  请在腾讯云控制台安全组中开放端口 $SSH_PORT"
elif curl -s -m 2 http://100.100.100.200 >/dev/null 2>&1; then
    echo "   检测到阿里云环境"
    echo "   ⚠️  请在阿里云控制台安全组中开放端口 $SSH_PORT"
elif curl -s -m 2 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
    echo "   检测到AWS环境"
    echo "   ⚠️  请在AWS控制台安全组中开放端口 $SSH_PORT"
else
    echo "   如果使用云服务器，请确保在控制台安全组开放端口 $SSH_PORT"
fi

# 15. 获取服务器信息
echo ""
echo "🌐 服务器信息:"
echo "   私网IP: ${PRIVATE_IP:-未知}"
if [ -n "$PUBLIC_IP" ]; then
    echo "   公网IP: $PUBLIC_IP"
fi
echo "   主机名: $(hostname)"
echo "   SSH端口: $SSH_PORT"
echo "   允许用户: $SSH_USER"

# 16. 生成管理脚本
echo "📝 生成管理脚本..."
$SUDO tee /usr/local/bin/ssh-security-manage << 'SCRIPT_EOF' >/dev/null
#!/bin/bash
case "$1" in
    "status")
        echo "SSH服务状态:"
        sudo systemctl status ssh --no-pager -l
        echo ""
        if [ -f /lib/systemd/system/ssh.socket ]; then
            echo "SSH Socket状态:"
            sudo systemctl status ssh.socket --no-pager -l
            echo ""
        fi
        echo "端口监听:"
        sudo ss -tlnp | grep ssh
        echo ""
        echo "安全配置状态:"
        PASSWORD_AUTH=$(sudo sshd -T 2>/dev/null | grep "^passwordauthentication" | awk '{print $2}')
        PUBKEY_AUTH=$(sudo sshd -T 2>/dev/null | grep "^pubkeyauthentication" | awk '{print $2}')
        ROOT_LOGIN=$(sudo sshd -T 2>/dev/null | grep "^permitrootlogin" | awk '{print $2}')
        PORT=$(sudo sshd -T 2>/dev/null | grep "^port" | awk '{print $2}')
        echo "监听端口: $PORT"
        echo "密码认证: $PASSWORD_AUTH"
        echo "公钥认证: $PUBKEY_AUTH"
        echo "Root登录: $ROOT_LOGIN"
        ;;
    "restore")
        echo "恢复SSH默认配置..."
        sudo systemctl stop ssh ssh.socket 2>/dev/null
        sudo rm -f /etc/ssh/sshd_config.d/99-zzz-*.conf
        sudo rm -rf /etc/systemd/system/ssh.socket.d/
        sudo systemctl daemon-reload
        sudo systemctl restart ssh
        echo "✅ 已恢复默认配置（端口22）"
        ;;
    "test")
        echo "SSH连接和安全测试:"
        PORTS=$(sudo ss -tlnp | grep ssh | grep -oP ':\K[0-9]+' | sort -u)
        for PORT in $PORTS; do
            if timeout 3 bash -c "echo quit | telnet localhost $PORT" 2>/dev/null | grep -q "SSH-2.0"; then
                echo "端口 $PORT: ✅ 正常"
            else
                echo "端口 $PORT: ❌ 异常"
            fi
        done
        echo ""
        PASSWORD_AUTH=$(sudo sshd -T 2>/dev/null | grep "^passwordauthentication" | awk '{print $2}')
        if [ "$PASSWORD_AUTH" = "no" ]; then
            echo "密码认证: ✅ 已禁用"
        else
            echo "密码认证: ❌ 仍启用（安全风险！）"
        fi
        ;;
    "diagnose")
        echo "SSH诊断信息:"
        echo "=============="
        echo ""
        echo "1. Socket配置（如果使用）:"
        if [ -f /etc/systemd/system/ssh.socket.d/override.conf ]; then
            cat /etc/systemd/system/ssh.socket.d/override.conf
        else
            echo "未找到socket覆盖配置"
        fi
        echo ""
        echo "2. 服务依赖:"
        systemctl show ssh.service -p TriggeredBy
        if [ -f /lib/systemd/system/ssh.socket ]; then
            systemctl show ssh.socket -p Listen
        fi
        echo ""
        echo "3. 实际监听:"
        sudo ss -tlnp | grep -E 'ssh|:22|:9833'
        echo ""
        echo "4. 最近日志:"
        sudo journalctl -u ssh -u ssh.socket -n 20 --no-pager
        ;;
    *)
        echo "SSH安全配置管理工具 v5"
        echo "========================"
        echo ""
        echo "用法: $0 {status|restore|test|diagnose}"
        echo ""
        echo "  status   - 查看SSH服务和安全配置状态"
        echo "  restore  - 恢复默认SSH配置"
        echo "  test     - 测试SSH端口和安全配置"
        echo "  diagnose - 诊断SSH配置问题"
        echo ""
        ;;
esac
SCRIPT_EOF

$SUDO chmod +x /usr/local/bin/ssh-security-manage

# 17. 完成报告
echo ""
echo "✅ SSH极致安全配置部署完成！"
echo "==================================="
echo ""
echo "🔒 安全特性:"
echo "   - 密码认证强制禁用（多重保障）"
echo "   - 现代加密算法（抗量子 + 兼容fallback）"
echo "   - 多密钥类型支持"
echo "   - 严格连接限制"
echo "   - 仅允许指定用户: $SSH_USER"
if [ "$USE_SOCKET_ACTIVATION" = true ]; then
    echo "   - 使用systemd socket激活"
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
echo "   - SSH现在仅监听端口 $SSH_PORT"
echo "   - 密码认证已被强制禁用"
echo "   - 仅允许用户 $SSH_USER 登录"
if [ "$SSH_PORT" != "22" ]; then
    echo "   - 确认新端口连接正常后，执行: sudo ufw delete allow 22/tcp"
fi
echo ""

echo "🛠️  管理命令:"
echo "   查看状态: ssh-security-manage status"
echo "   诊断问题: ssh-security-manage diagnose"
echo "   恢复默认: ssh-security-manage restore"
echo ""

echo "🆘 应急恢复（如果连接失败）:"
echo "   1. 使用控制台或VNC访问"
echo "   2. 执行: ssh-security-manage restore"
echo "   或手动恢复:"
echo "   sudo systemctl stop ssh ssh.socket"
echo "   sudo rm /etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf"
echo "   sudo rm -rf /etc/systemd/system/ssh.socket.d/"
echo "   sudo systemctl daemon-reload && sudo systemctl restart ssh"
echo ""

echo "📁 配置备份位置: $BACKUP_DIR"
echo ""
echo "🎉 部署完成！建议立即测试新端口连接。"
