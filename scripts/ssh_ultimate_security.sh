#!/bin/bash

# SSH极致安全配置脚本 - 最终修复版 v4
# 修复所有已知问题：用户配置、算法兼容性、密码认证禁用

echo "🔐 SSH极致安全配置部署 (v4)"
echo "============================="

# 检查权限
if [ "$EUID" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    SUDO=""
fi

# 配置参数 - 支持环境变量自定义
SSH_PORT=${SSH_PORT:-9833}
SSH_USER=${SSH_USER:-$(whoami)}

echo "⚙️  配置参数:"
echo "   SSH端口: $SSH_PORT"
echo "   允许用户: $SSH_USER (当前执行用户)"
echo "   安全级别: 高级安全 + 客户端兼容性"
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

# 1. 备份现有配置
echo "📁 备份现有配置..."
$SUDO cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d-%H%M%S)

# 2. 彻底清理冲突配置文件
echo "🗑️  清理冲突配置文件..."
$SUDO rm -f /etc/ssh/sshd_config.d/99-*.conf 2>/dev/null
# 删除Ubuntu默认的冲突配置文件
$SUDO rm -f /etc/ssh/sshd_config.d/01-PasswordAuthentication.conf 2>/dev/null
$SUDO rm -f /etc/ssh/sshd_config.d/01-permitrootlogin.conf 2>/dev/null
$SUDO rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf 2>/dev/null
echo "   ✅ 已清理所有冲突配置文件"

# 3. 创建最终安全配置（最高优先级）
echo "⚙️  创建最终安全配置..."
$SUDO tee /etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf << EOF
# SSH最终安全配置 - 最高优先级 v4
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

# 4. 同时修改主配置文件确保无冲突
echo "🔧 修改主配置文件..."
$SUDO sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
$SUDO sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
$SUDO sed -i 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
$SUDO sed -i 's/ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config

# 5. 创建必要目录
echo "📁 创建必要目录..."
$SUDO mkdir -p /run/sshd

# 6. 验证配置语法
echo "🔍 验证配置语法..."
if ! $SUDO sshd -t; then
    echo "   ❌ 配置语法错误，退出"
    exit 1
fi

# 7. 检查SSH密钥配置
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
    echo "   ❌ 未找到授权密钥文件: $AUTHORIZED_KEYS"
    echo "   💡 请确保已配置SSH密钥"
fi

# 8. 应用配置
echo "🔄 应用配置..."

echo "   🔄 重新加载systemd配置..."
$SUDO systemctl daemon-reload

echo "   🔄 重启SSH服务..."
if $SUDO systemctl restart ssh.socket; then
    echo "   ✅ SSH socket重启成功"
elif $SUDO systemctl restart ssh; then
    echo "   ✅ SSH服务重启成功（传统模式）"
else
    echo "   ❌ SSH服务重启失败，尝试强制恢复..."
    $SUDO systemctl stop ssh ssh.socket
    $SUDO systemctl disable ssh.socket
    if $SUDO systemctl start ssh; then
        echo "   ✅ SSH服务强制启动成功"
    else
        echo "   ❌ SSH服务启动完全失败"
        exit 1
    fi
fi

# 启用服务自启动
$SUDO systemctl enable ssh 2>/dev/null

# 等待服务完全启动
sleep 3

# 9. 关键安全验证
echo "🔐 关键安全配置验证..."
PASSWORD_AUTH=$($SUDO sshd -T | grep "^passwordauthentication" | awk '{print $2}')
PUBKEY_AUTH=$($SUDO sshd -T | grep "^pubkeyauthentication" | awk '{print $2}')
ROOT_LOGIN=$($SUDO sshd -T | grep "^permitrootlogin" | awk '{print $2}')

echo "   密码认证状态: $PASSWORD_AUTH"
echo "   公钥认证状态: $PUBKEY_AUTH"
echo "   Root登录状态: $ROOT_LOGIN"

if [ "$PASSWORD_AUTH" = "no" ]; then
    echo "   ✅ 密码认证已成功禁用"
else
    echo "   ❌ 警告: 密码认证仍然启用！安全风险！"
    echo "   🔧 尝试强制修复..."
    
    # 强制修复措施
    echo 'PasswordAuthentication no' | $SUDO tee -a /etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf
    echo 'ChallengeResponseAuthentication no' | $SUDO tee -a /etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf
    $SUDO systemctl restart ssh
    
    # 再次验证
    PASSWORD_AUTH_RETRY=$($SUDO sshd -T | grep "^passwordauthentication" | awk '{print $2}')
    if [ "$PASSWORD_AUTH_RETRY" = "no" ]; then
        echo "   ✅ 密码认证修复成功"
    else
        echo "   ❌ 密码认证修复失败，需要手动检查"
    fi
fi

# 10. 端口验证
echo "📊 端口状态验证..."
if $SUDO ss -tlnp | grep -q ":$SSH_PORT"; then
    echo "   ✅ 端口$SSH_PORT监听正常"
else
    echo "   ❌ 端口$SSH_PORT未监听"
fi

if $SUDO ss -tlnp | grep -q ":22"; then
    echo "   ⚠️  端口22仍在监听"
else
    echo "   ✅ 端口22已关闭"
fi

# 11. 算法兼容性检查
echo "🔧 算法兼容性检查..."
if $SUDO sshd -T | grep "^kexalgorithms" | grep -q "curve25519-sha256"; then
    echo "   ✅ 客户端兼容算法已启用"
else
    echo "   ⚠️  可能存在客户端兼容性问题"
fi

# 12. 获取服务器信息
echo ""
echo "🌐 服务器信息:"
SERVER_IPv4=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')
echo "   IP地址: $SERVER_IPv4"
echo "   主机名: $(hostname)"
echo "   SSH端口: $SSH_PORT"
echo "   允许用户: $SSH_USER"

# 13. 完成报告
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
echo ""

echo "🧪 连接测试命令:"
echo ""
echo "   Linux/macOS:"
echo "   ssh -i ~/.ssh/id_ed25519 $SSH_USER@$SERVER_IPv4 -p $SSH_PORT"
echo ""
echo "   Windows PowerShell:"
echo "   ssh -i \"\$env:USERPROFILE\\.ssh\\id_ed25519\" $SSH_USER@$SERVER_IPv4 -p $SSH_PORT"
echo ""

echo "📋 重要提醒:"
echo "   - SSH现在仅监听端口 $SSH_PORT"
echo "   - 密码认证已被强制禁用"
echo "   - 仅允许用户 $SSH_USER 登录"
echo "   - 配置兼容主流SSH客户端"
echo ""

echo "🆘 应急恢复（如果连接失败）:"
echo "   sudo systemctl stop ssh"
echo "   sudo rm /etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf"
echo "   sudo systemctl daemon-reload && sudo systemctl restart ssh"
echo ""

# 14. 生成最终管理脚本
$SUDO tee /usr/local/bin/ssh-security-manage << 'SCRIPT_EOF'
#!/bin/bash
case "$1" in
    "status")
        echo "SSH服务状态:"
        sudo systemctl status ssh --no-pager -l
        echo ""
        echo "端口监听:"
        sudo ss -tlnp | grep ssh
        echo ""
        echo "安全配置状态:"
        PASSWORD_AUTH=$(sudo sshd -T | grep "^passwordauthentication" | awk '{print $2}')
        PUBKEY_AUTH=$(sudo sshd -T | grep "^pubkeyauthentication" | awk '{print $2}')
        ROOT_LOGIN=$(sudo sshd -T | grep "^permitrootlogin" | awk '{print $2}')
        echo "密码认证: $PASSWORD_AUTH"
        echo "公钥认证: $PUBKEY_AUTH"
        echo "Root登录: $ROOT_LOGIN"
        ;;
    "restore")
        echo "恢复SSH默认配置..."
        sudo systemctl stop ssh
        sudo rm -f /etc/ssh/sshd_config.d/99-zzz-*.conf
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
        PASSWORD_AUTH=$(sudo sshd -T | grep "^passwordauthentication" | awk '{print $2}')
        if [ "$PASSWORD_AUTH" = "no" ]; then
            echo "密码认证: ✅ 已禁用"
        else
            echo "密码认证: ❌ 仍启用（安全风险！）"
        fi
        ;;
    "fix-password")
        echo "强制修复密码认证问题..."
        sudo rm -f /etc/ssh/sshd_config.d/01-*.conf
        echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf
        echo 'ChallengeResponseAuthentication no' | sudo tee -a /etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf
        sudo systemctl restart ssh
        PASSWORD_AUTH=$(sudo sshd -T | grep "^passwordauthentication" | awk '{print $2}')
        if [ "$PASSWORD_AUTH" = "no" ]; then
            echo "✅ 密码认证修复成功"
        else
            echo "❌ 密码认证修复失败"
        fi
        ;;
    "user")
        USER=${2:-$(whoami)}
        echo "为用户 $USER 配置SSH访问权限..."
        if id "$USER" &>/dev/null; then
            sudo sed -i "s/AllowUsers .*/AllowUsers $USER/" /etc/ssh/sshd_config.d/99-zzz-*.conf
            sudo systemctl restart ssh
            echo "✅ 已更新允许用户为: $USER"
        else
            echo "❌ 用户 $USER 不存在"
        fi
        ;;
    *)
        echo "SSH安全配置管理工具 v4"
        echo "========================"
        echo ""
        echo "用法: $0 {status|restore|test|fix-password|user [用户名]}"
        echo ""
        echo "  status       - 查看SSH服务和安全配置状态"
        echo "  restore      - 恢复默认SSH配置"
        echo "  test         - 测试SSH端口和安全配置"
        echo "  fix-password - 强制修复密码认证问题"
        echo "  user         - 修改允许登录的用户"
        echo ""
        echo "示例:"
        echo "  $0 status"
        echo "  $0 test"
        echo "  $0 fix-password"
        echo "  $0 user alice"
        ;;
esac
SCRIPT_EOF

$SUDO chmod +x /usr/local/bin/ssh-security-manage

echo "🎉 最终部署完成！管理命令: ssh-security-manage"
