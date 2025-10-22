#!/bin/bash
set -euo pipefail

# SSH 极致安全配置脚本 - v6.3（安全扶梯版）
# 目标：
#  - 云防火墙为第一道防线（默认关闭 SSH，临时放通）
#  - SSH 仅密钥登录；root SSH 登录禁止
#  - 保留 PAM（sudo/passwd/su 正常）
#  - 首次部署启用“双端口扶梯”：同时监听 22 与新端口，避免锁死
#  - 提供一键移除 22 的管理命令
#
# 用法（推荐非 root 身份执行）：
#   SSH_USER=myuser SSH_PORT=9833 bash ./ssh_ultimate_security.sh
#
# 可选环境变量：
#   SSH_USER=<非root用户>        # 必须是非 root
#   SSH_PORT=<端口>              # 默认 9833
#   FORCE_SINGLE_PORT=1          # 仅使用新端口（不推荐首轮）
#
# 作者：myth815（基于 v6.1/6.2 修订）
# 日期：2025-01-11

echo "🔐 SSH 安全配置部署 (v6.3 - 安全扶梯版)"
echo "======================================="

# 颜色
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# 提权命令
if [ "${EUID:-$(id -u)}" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  SUDO=""
fi

# 参数与防呆
SSH_PORT="${SSH_PORT:-9833}"
SSH_USER="${SSH_USER:-$(whoami)}"
FORCE_SINGLE_PORT="${FORCE_SINGLE_PORT:-0}"
BACKUP_DIR="/etc/ssh/backups"
BACKUP_TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
MANAGED_TAG="# Managed-By: myth815-ssh-sec v6.3"

echo "⚙️  参数："
echo "   • SSH 端口 : $SSH_PORT"
echo "   • 允许用户 : $SSH_USER（root 禁止 SSH 登录）"
echo "   • 扶梯模式 : $([ "$FORCE_SINGLE_PORT" = "1" ] && echo 单端口 || echo 双端口_22+$SSH_PORT)"
echo "   • 备份目录 : $BACKUP_DIR"
echo ""

# 用户校验
if ! id "$SSH_USER" &>/dev/null; then
  echo -e "${RED}❌ 用户不存在：$SSH_USER${NC}"
  echo "   请先创建：sudo useradd -m -s /bin/bash $SSH_USER"
  exit 1
fi
if [ "$SSH_USER" = "root" ]; then
  echo -e "${RED}❌ SSH_USER 解析为 'root'，为避免 AllowUsers root + 禁止 root 登录 导致自锁，脚本退出。${NC}"
  echo "   正确用法示例：SSH_USER=myuser SSH_PORT=$SSH_PORT bash $0"
  exit 2
fi

# 运行目录
echo "📁 准备运行目录..."
$SUDO mkdir -p /run/sshd /var/run/sshd
$SUDO chmod 755 /run/sshd /var/run/sshd
$SUDO tee /etc/tmpfiles.d/sshd.conf >/dev/null <<EOF
d /run/sshd 0755 root root -
d /var/run/sshd 0755 root root -
EOF
echo "   ✅ /run/sshd ready"

# 备份
echo "🗄️  备份配置..."
$SUDO mkdir -p "$BACKUP_DIR"
[ -f /etc/ssh/sshd_config ] && $SUDO cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$BACKUP_TIMESTAMP"
[ -d /etc/ssh/sshd_config.d ] && $SUDO tar -czf "$BACKUP_DIR/sshd_config.d.$BACKUP_TIMESTAMP.tgz" -C /etc/ssh sshd_config.d 2>/dev/null || true
[ -d /etc/systemd/system/ssh.socket.d ] && $SUDO tar -czf "$BACKUP_DIR/ssh.socket.d.$BACKUP_TIMESTAMP.tgz" -C /etc/systemd/system ssh.socket.d 2>/dev/null || true
echo "   ✅ 已备份至 $BACKUP_DIR"

# 检测 systemd socket 激活
echo "🔍 检测 systemd socket 激活..."
USE_SOCKET=false
if [ -f /lib/systemd/system/ssh.socket ] || [ -f /etc/systemd/system/ssh.socket ]; then
  if $SUDO systemctl show ssh.service -p TriggeredBy 2>/dev/null | grep -q "ssh.socket"; then
    USE_SOCKET=true
    echo "   ✅ 已启用 socket 激活"
  else
    echo "   ℹ️  非 socket 激活模式"
  fi
else
  echo "   ℹ️  未发现 ssh.socket"
fi

# 清理冲突配置
echo "🧹 清理冲突配置..."
$SUDO rm -f /etc/ssh/sshd_config.d/99-*.conf 2>/dev/null || true
$SUDO rm -f /etc/ssh/sshd_config.d/01-PasswordAuthentication.conf 2>/dev/null || true
$SUDO rm -f /etc/ssh/sshd_config.d/01-permitrootlogin.conf 2>/dev/null || true
$SUDO rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf 2>/dev/null || true
echo "   ✅ 冲突配置已清理"

# 生成最终配置（仅密钥；root 禁止；保留 PAM；扶梯模式）
echo "⚙️  写入最终配置（/etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf）..."
$SUDO tee /etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf >/dev/null <<EOF
$MANAGED_TAG
# SSH 安全配置 v6.3（root 禁止登录；仅密钥；PAM 保留；扶梯模式）
# ———— 首次部署建议云防火墙暂时放通 22 与 $SSH_PORT，确认后再关闭 22 —— #

# 认证策略
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
PermitEmptyPasswords no

# 仅允许指定用户（root 不在列）
AllowUsers $SSH_USER

# 连接限制
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# 加密与算法
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
Compression no
PermitUserEnvironment no

# 网络
TCPKeepAlive yes
UseDNS no
MaxStartups 3:50:10
AddressFamily any
ListenAddress 0.0.0.0:$SSH_PORT
ListenAddress [::]:$SSH_PORT
$( [ "$FORCE_SINGLE_PORT" = "1" ] && echo "Port $SSH_PORT" || printf "Port 22\nPort %s" "$SSH_PORT" )

# 日志
LogLevel VERBOSE
SyslogFacility AUTH
EOF
echo "   ✅ 写入完成"

# 同步主配置（保持关键项一致）
echo "🛠️  同步主配置..."
$SUDO sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config || true
$SUDO sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config || true
$SUDO sed -i 's/^#\?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config || true
$SUDO sed -i 's/^#\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config || true
$SUDO sed -i 's/^#\?UsePAM .*/UsePAM yes/' /etc/ssh/sshd_config || true

# socket 激活覆盖（扶梯模式下双端口）
if [ "$USE_SOCKET" = true ]; then
  echo "🧩 配置 ssh.socket 覆盖..."
  $SUDO mkdir -p /etc/systemd/system/ssh.socket.d/
  if [ "$FORCE_SINGLE_PORT" = "1" ]; then
    $SUDO tee /etc/systemd/system/ssh.socket.d/override.conf >/dev/null <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:$SSH_PORT
ListenStream=[::]:$SSH_PORT
FreeBind=yes
Backlog=128
EOF
  else
    $SUDO tee /etc/systemd/system/ssh.socket.d/override.conf >/dev/null <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:22
ListenStream=[::]:22
ListenStream=0.0.0.0:$SSH_PORT
ListenStream=[::]:$SSH_PORT
FreeBind=yes
Backlog=128
EOF
  fi
  $SUDO systemctl daemon-reload
  echo "   ✅ socket 覆盖完成"
fi

# 语法检查
echo "🔎 校验配置语法..."
$SUDO mkdir -p /run/sshd /var/run/sshd 2>/dev/null
if ! $SUDO sshd -t 2>/dev/null; then
  echo -e "${RED}❌ 语法错误，回滚中...${NC}"
  [ -f "$BACKUP_DIR/sshd_config.$BACKUP_TIMESTAMP" ] && $SUDO cp "$BACKUP_DIR/sshd_config.$BACKUP_TIMESTAMP" /etc/ssh/sshd_config
  $SUDO rm -f /etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf
  [ -f /etc/systemd/system/ssh.socket.d/override.conf ] && $SUDO rm -f /etc/systemd/system/ssh.socket.d/override.conf
  $SUDO systemctl daemon-reload
  $SUDO systemctl restart ssh || true
  echo "   ✅ 已回滚"
  exit 1
fi
echo "   ✅ 语法检查通过"

# 密钥检查
echo "🔑 检查 $SSH_USER 的密钥..."
USER_HOME="$(eval echo ~$SSH_USER)"
SSH_DIR="$USER_HOME/.ssh"
AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"
if [ -f "$AUTHORIZED_KEYS" ]; then
  KEY_COUNT="$(wc -l < "$AUTHORIZED_KEYS" 2>/dev/null || echo 0)"
  echo "   ✅ 授权密钥：$KEY_COUNT 行"
  $SUDO chown -R "$SSH_USER:$SSH_USER" "$SSH_DIR"
  $SUDO chmod 700 "$SSH_DIR"
  $SUDO chmod 600 "$AUTHORIZED_KEYS"
else
  echo -e "${YELLOW}⚠️  未找到授权密钥文件：$AUTHORIZED_KEYS${NC}"
  echo "   请先写入公钥，再在云防火墙放通新端口！"
fi

# 本地防火墙（仅加规则，不强制启用）
echo "🧯 更新本地防火墙规则（可选）..."
if command -v ufw >/dev/null 2>&1; then
  $SUDO ufw allow "$SSH_PORT"/tcp >/dev/null 2>&1 || true
  [ "$FORCE_SINGLE_PORT" != "1" ] && $SUDO ufw allow 22/tcp >/dev/null 2>&1 || true
  echo "   ✅ UFW 已添加允许规则（未强制 enable）"
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  if $SUDO firewall-cmd --state 2>/dev/null | grep -q running; then
    $SUDO firewall-cmd --permanent --add-port="$SSH_PORT"/tcp >/dev/null 2>&1 || true
    [ "$FORCE_SINGLE_PORT" != "1" ] && $SUDO firewall-cmd --permanent --add-port=22/tcp >/dev/null 2>&1 || true
    $SUDO firewall-cmd --reload >/dev/null 2>&1 || true
    echo "   ✅ firewalld 已添加允许规则"
  fi
fi

# 应用配置
echo "🔄 重载/重启 SSH..."
$SUDO systemctl daemon-reload
if [ "$USE_SOCKET" = true ]; then
  $SUDO systemctl stop ssh.service 2>/dev/null || true
  $SUDO systemctl stop ssh.socket 2>/dev/null || true
  $SUDO systemctl start ssh.socket
  echo "   ✅ socket 模式启动"
  timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/$SSH_PORT" 2>/dev/null || true
  [ "$FORCE_SINGLE_PORT" != "1" ] && timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/22" 2>/dev/null || true
else
  $SUDO systemctl restart ssh
  echo "   ✅ 传统模式重启完成"
fi
$SUDO systemctl enable ssh >/dev/null 2>&1 || true

# 状态验证
echo "🧪 状态验证..."
PASSWORD_AUTH="$($SUDO timeout 5 sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}')"
PUBKEY_AUTH="$($SUDO timeout 5 sshd -T 2>/dev/null | awk '/^pubkeyauthentication/{print $2}')"
ROOT_LOGIN="$($SUDO timeout 5 sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}')"
PORTS="$($SUDO timeout 5 sshd -T 2>/dev/null | awk '/^port/{print $2}' | xargs echo -n || true)"
echo "   • pubkeyauthentication : ${PUBKEY_AUTH:-unknown}   (expect: yes)"
echo "   • passwordauthentication: ${PASSWORD_AUTH:-unknown} (expect: no, SSH 仅密钥)"
echo "   • permitrootlogin      : ${ROOT_LOGIN:-unknown}    (expect: no)"
echo "   • ports (sshd -T)      : ${PORTS:-unknown}"

LISTEN_V4_NEW="$($SUDO ss -tlnp | grep -c "0.0.0.0:$SSH_PORT" || true)"
LISTEN_V6_NEW="$($SUDO ss -tlnp | grep -c "\[::\]:$SSH_PORT" || true)"
[ "$FORCE_SINGLE_PORT" != "1" ] && LISTEN_V4_22="$($SUDO ss -tlnp | grep -c "0.0.0.0:22 " || true)" || LISTEN_V4_22=0
[ "$FORCE_SINGLE_PORT" != "1" ] && LISTEN_V6_22="$($SUDO ss -tlnp | grep -c "\[::\]:22 " || true)" || LISTEN_V6_22=0

[ "$LISTEN_V4_NEW" -gt 0 ] || [ "$LISTEN_V6_NEW" -gt 0 ] \
  && echo "   ✅ 新端口 $SSH_PORT 正在监听（本机层面）" \
  || echo -e "   ${YELLOW}⚠️ 新端口 $SSH_PORT 暂未监听（若为 socket 模式或云防火墙未放通，属正常现象）${NC}"

if [ "$FORCE_SINGLE_PORT" != "1" ]; then
  [ "$LISTEN_V4_22" -gt 0 ] || [ "$LISTEN_V6_22" -gt 0 ] \
    && echo "   ✅ 端口 22 仍在监听（扶梯已就绪）" \
    || echo -e "   ${YELLOW}⚠️ 端口 22 未监听；若云防火墙未放通新端口，可能无法远程连接${NC}"
fi

# 安装管理工具（含“一键移除 22”）
echo "📝 安装管理工具 /usr/local/bin/ssh-security-manage ..."
$SUDO tee /usr/local/bin/ssh-security-manage >/dev/null <<'SCRIPT_EOF'
#!/bin/bash
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
cfg='/etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf'
drop22() {
  if [ ! -f "$cfg" ]; then echo -e "${RED}未找到配置: $cfg${NC}"; exit 1; fi
  sudo sed -i '/^Port 22$/d' "$cfg"
  if [ -f /etc/systemd/system/ssh.socket.d/override.conf ]; then
    sudo sed -i '/ListenStream=.*22/d' /etc/systemd/system/ssh.socket.d/override.conf || true
  fi
  sudo systemctl daemon-reload
  sudo systemctl restart ssh || sudo systemctl restart ssh.socket || true
  echo -e "${GREEN}✅ 已移除 22 并重启 SSH${NC}"
}
case "${1:-status}" in
  status)
    echo "SSH/Socket 状态"; echo "=============="
    sudo systemctl status ssh --no-pager -l || true
    systemctl list-units | grep -q ssh.socket && { echo ""; sudo systemctl status ssh.socket --no-pager -l || true; }
    echo ""; echo "配置与监听"; echo "=========="
    timeout 5 sshd -T 2>/dev/null | awk '/^(port|passwordauthentication|pubkeyauthentication|permitrootlogin)/{print}'
    echo ""; sudo ss -tlnp | grep -E 'ssh|:22|:9833|:8022' || true
    ;;
  restore)
    echo "恢复默认 SSH 配置（端口 22）..."
    sudo systemctl stop ssh ssh.socket 2>/dev/null || true
    sudo rm -f /etc/ssh/sshd_config.d/99-zzz-*.conf || true
    sudo rm -rf /etc/systemd/system/ssh.socket.d/ || true
    sudo systemctl daemon-reload
    sudo systemctl restart ssh || true
    echo -e "${GREEN}✅ 已恢复默认配置（端口 22）${NC}"
    ;;
  drop22)
    drop22
    ;;
  test)
    P="$(timeout 5 sshd -T 2>/dev/null | awk '/^port/{print $2}' | tail -1)"
    [ -z "${P:-}" ] && P=22
    echo "本地测试端口: $P"
    timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/$P" 2>/dev/null && echo -e "${GREEN}✅ IPv4 OK${NC}" || echo -e "${YELLOW}⚠️ IPv4 FAIL${NC}"
    timeout 2 bash -c "echo > /dev/tcp/::1/$P" 2>/dev/null && echo -e "${GREEN}✅ IPv6 OK${NC}" || echo -e "${YELLOW}⚠️ IPv6 FAIL${NC}"
    ;;
  diagnose)
    echo "诊断"; echo "===="
    systemctl show ssh.service -p TriggeredBy || true
    systemctl list-units | grep -q ssh.socket && systemctl show ssh.socket -p Listen || true
    echo ""; sudo ss -tlnp | grep -E 'ssh|:22|:9833|:8022' || true
    echo ""; sudo journalctl -u ssh -u ssh.socket -n 50 --no-pager || true
    ;;
  fix)
    sudo mkdir -p /run/sshd /var/run/sshd; sudo chmod 755 /run/sshd /var/run/sshd
    systemctl list-units | grep -q ssh.socket && sudo systemctl restart ssh.socket || sudo systemctl restart ssh
    sleep 1; sudo ss -tlnp | grep ssh || true
    ;;
  *)
    echo "用法: $0 {status|restore|drop22|test|diagnose|fix}"
    ;;
esac
SCRIPT_EOF
$SUDO chmod +x /usr/local/bin/ssh-security-manage
echo "   ✅ 管理工具已安装（含 drop22）"

# 完成
echo ""
echo -e "${GREEN}✅ 部署完成（v6.3）${NC}"
echo "————————————————————————————————"
echo "• 扶梯模式：当前监听端口 -> $([ "$FORCE_SINGLE_PORT" = "1" ] && echo "$SSH_PORT（单端口）" || echo "22 与 $SSH_PORT（双端口）")"
echo "• 建议流程："
echo "   1) 在云防火墙放通 $SSH_PORT；"
echo "   2) 用密钥从新端口登录测试成功；"
echo "   3) 执行：ssh-security-manage drop22（移除 22）并在云防火墙关闭 22。"
echo ""
echo "⚠️ 如果你现在还未放通 $SSH_PORT，千万不要先关 22。"
echo "   （本脚本已经为你保留 22 作为应急扶梯，除非你设置了 FORCE_SINGLE_PORT=1）"
