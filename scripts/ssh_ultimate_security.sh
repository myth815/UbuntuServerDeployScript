#!/bin/bash

# SSH配置测试验证脚本
# 用于验证SSH安全配置是否正确应用

echo "🔍 SSH配置完整性测试"
echo "====================="
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 测试结果计数
PASS=0
FAIL=0
WARN=0

# 测试函数
test_check() {
    local test_name="$1"
    local test_cmd="$2"
    local expected="$3"
    
    echo -n "检查: $test_name ... "
    
    result=$(eval "$test_cmd" 2>/dev/null)
    
    if [ "$result" = "$expected" ]; then
        echo -e "${GREEN}✅ 通过${NC}"
        ((PASS++))
        return 0
    else
        echo -e "${RED}❌ 失败${NC}"
        echo "  期望: $expected"
        echo "  实际: $result"
        ((FAIL++))
        return 1
    fi
}

test_warn() {
    local test_name="$1"
    local test_cmd="$2"
    
    echo -n "检查: $test_name ... "
    
    if eval "$test_cmd" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ 通过${NC}"
        ((PASS++))
        return 0
    else
        echo -e "${YELLOW}⚠️  警告${NC}"
        ((WARN++))
        return 1
    fi
}

# 1. 检查服务状态
echo "1️⃣  服务状态检查"
echo "----------------"

test_check "SSH服务运行状态" \
    "systemctl is-active ssh" \
    "active"

test_check "SSH Socket状态(如果存在)" \
    "systemctl is-active ssh.socket 2>/dev/null || echo 'not-found'" \
    "active"

if [ "$(systemctl is-active ssh.socket 2>/dev/null)" = "active" ]; then
    test_check "Socket触发关系" \
        "systemctl show ssh.service -p TriggeredBy --value | grep -q ssh.socket && echo 'yes' || echo 'no'" \
        "yes"
fi

echo ""

# 2. 端口配置检查
echo "2️⃣  端口配置检查"
echo "----------------"

# 获取配置的端口
CONFIG_PORT=$(sudo sshd -T 2>/dev/null | grep "^port" | awk '{print $2}')
echo "配置端口: $CONFIG_PORT"

# 检查实际监听端口
LISTENING_PORTS=$(sudo ss -tlnp | grep -E 'sshd|systemd' | grep -oE ':[0-9]+' | cut -d: -f2 | sort -u | tr '\n' ' ')
echo "监听端口: $LISTENING_PORTS"

test_check "端口监听状态" \
    "sudo ss -tlnp | grep -q \":$CONFIG_PORT\" && echo 'listening' || echo 'not-listening'" \
    "listening"

# 如果使用socket激活，检查socket配置
if [ -f /etc/systemd/system/ssh.socket.d/override.conf ]; then
    SOCKET_PORT=$(grep "ListenStream=" /etc/systemd/system/ssh.socket.d/override.conf | grep -v "^#" | tail -1 | cut -d= -f2)
    test_check "Socket端口配置" \
        "[ '$SOCKET_PORT' = '$CONFIG_PORT' ] && echo 'match' || echo 'mismatch'" \
        "match"
fi

echo ""

# 3. 安全配置检查
echo "3️⃣  安全配置检查"
echo "----------------"

test_check "密码认证禁用" \
    "sudo sshd -T 2>/dev/null | grep '^passwordauthentication' | awk '{print \$2}'" \
    "no"

test_check "公钥认证启用" \
    "sudo sshd -T 2>/dev/null | grep '^pubkeyauthentication' | awk '{print \$2}'" \
    "yes"

test_check "Root登录禁用" \
    "sudo sshd -T 2>/dev/null | grep '^permitrootlogin' | awk '{print \$2}'" \
    "no"

test_check "空密码禁用" \
    "sudo sshd -T 2>/dev/null | grep '^permitemptypasswords' | awk '{print \$2}'" \
    "no"

# 检查允许的用户
ALLOWED_USERS=$(sudo sshd -T 2>/dev/null | grep '^allowusers' | cut -d' ' -f2-)
if [ -n "$ALLOWED_USERS" ]; then
    echo "允许的用户: $ALLOWED_USERS"
else
    echo -e "${YELLOW}⚠️  未设置用户限制${NC}"
    ((WARN++))
fi

echo ""

# 4. 加密算法检查
echo "4️⃣  加密算法检查"
echo "----------------"

test_warn "现代密钥交换算法" \
    "sudo sshd -T 2>/dev/null | grep '^kexalgorithms' | grep -q 'curve25519-sha256'"

test_warn "现代加密算法" \
    "sudo sshd -T 2>/dev/null | grep '^ciphers' | grep -q 'chacha20-poly1305@openssh.com'"

test_warn "ED25519密钥支持" \
    "sudo sshd -T 2>/dev/null | grep '^pubkeyacceptedalgorithms' | grep -q 'ssh-ed25519'"

echo ""

# 5. 防火墙检查
echo "5️⃣  防火墙配置检查"
echo "------------------"

if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS=$(sudo ufw status 2>/dev/null | grep -i "^status:" | awk '{print $2}')
    echo "UFW状态: $UFW_STATUS"
    
    if [ "$UFW_STATUS" = "active" ]; then
        test_check "UFW端口$CONFIG_PORT开放" \
            "sudo ufw status | grep -q \"$CONFIG_PORT/tcp\" && echo 'open' || echo 'closed'" \
            "open"
    else
        echo -e "${YELLOW}⚠️  UFW防火墙未激活${NC}"
        ((WARN++))
    fi
fi

if command -v firewall-cmd >/dev/null 2>&1; then
    if sudo firewall-cmd --state 2>/dev/null | grep -q "running"; then
        test_check "Firewalld端口$CONFIG_PORT开放" \
            "sudo firewall-cmd --list-ports | grep -q \"$CONFIG_PORT/tcp\" && echo 'open' || echo 'closed'" \
            "open"
    fi
fi

echo ""

# 6. 配置文件检查
echo "6️⃣  配置文件检查"
echo "----------------"

test_check "安全配置文件存在" \
    "[ -f /etc/ssh/sshd_config.d/99-zzz-ultimate-security.conf ] && echo 'exists' || echo 'missing'" \
    "exists"

test_warn "配置语法正确" \
    "sudo sshd -t -f /etc/ssh/sshd_config"

if [ -d /etc/ssh/backups ]; then
    BACKUP_COUNT=$(ls -1 /etc/ssh/backups/ 2>/dev/null | wc -l)
    echo "配置备份数量: $BACKUP_COUNT"
fi

echo ""

# 7. 连接测试
echo "7️⃣  连接能力测试"
echo "----------------"

# 本地连接测试
if timeout 2 bash -c "echo > /dev/tcp/localhost/$CONFIG_PORT" 2>/dev/null; then
    echo -e "${GREEN}✅ 本地端口可访问${NC}"
    ((PASS++))
else
    echo -e "${RED}❌ 本地端口不可访问${NC}"
    ((FAIL++))
fi

# 测试SSH协议响应
if echo "quit" | timeout 2 telnet localhost $CONFIG_PORT 2>/dev/null | grep -q "SSH-2.0"; then
    echo -e "${GREEN}✅ SSH协议响应正常${NC}"
    ((PASS++))
else
    echo -e "${YELLOW}⚠️  SSH协议响应异常${NC}"
    ((WARN++))
fi

echo ""

# 8. 密钥文件检查
echo "8️⃣  密钥配置检查"
echo "----------------"

CURRENT_USER=$(whoami)
if [ -f "$HOME/.ssh/authorized_keys" ]; then
    KEY_COUNT=$(wc -l < "$HOME/.ssh/authorized_keys")
    echo "当前用户($CURRENT_USER)授权密钥数: $KEY_COUNT"
    
    # 检查权限
    test_check "SSH目录权限(700)" \
        "stat -c %a $HOME/.ssh" \
        "700"
    
    test_check "authorized_keys权限(600)" \
        "stat -c %a $HOME/.ssh/authorized_keys" \
        "600"
else
    echo -e "${YELLOW}⚠️  当前用户无授权密钥${NC}"
    ((WARN++))
fi

echo ""

# 总结
echo "📊 测试结果总结"
echo "==============="
echo -e "通过: ${GREEN}$PASS${NC}"
echo -e "失败: ${RED}$FAIL${NC}"
echo -e "警告: ${YELLOW}$WARN${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    if [ $WARN -eq 0 ]; then
        echo -e "${GREEN}🎉 所有测试通过！SSH配置完美。${NC}"
    else
        echo -e "${GREEN}✅ 核心测试通过，但有一些警告需要注意。${NC}"
    fi
else
    echo -e "${RED}❌ 存在配置问题，请运行 'ssh-security-manage diagnose' 诊断。${NC}"
fi

# 提供下一步建议
echo ""
echo "💡 建议操作："
if [ $FAIL -gt 0 ]; then
    echo "1. 运行诊断: ssh-security-manage diagnose"
    echo "2. 查看日志: sudo journalctl -u ssh -u ssh.socket -n 50"
    echo "3. 如需恢复: ssh-security-manage restore"
elif [ $WARN -gt 0 ]; then
    echo "1. 检查警告项目并根据需要调整"
    echo "2. 确保防火墙已正确配置"
    echo "3. 验证远程连接: ssh user@server -p $CONFIG_PORT"
else
    echo "1. 测试远程连接确保一切正常"
    echo "2. 保存配置备份: sudo tar -czf ~/ssh-config-backup.tar.gz /etc/ssh/"
    echo "3. 如果端口已更改，记得关闭旧端口: sudo ufw delete allow 22/tcp"
fi
