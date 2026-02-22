#!/bin/bash

VERSION="4.2.2"
RELEASE_DATE="2026-02-22"
SCRIPT_DIR="/opt/ban_asn"
SCRIPT_FILE="$SCRIPT_DIR/ban_asn.sh"
GLOBALCMD="/usr/local/bin/oban"
SUDOERS_FILE="/etc/sudoers.d/ban_asn"
SYSTEMD_SERVICE="/etc/systemd/system/ban-asn.service"

DEFAULT_ASNS="45102 37963 132203 55990 136907 45050 135377 55967 16509 14618 15169 8075 31898 14061 63949 9009"
DEFAULT_COUNTRIES="kp iq af ru cu ir by vn id br pk ua"
ASNS="$DEFAULT_ASNS"
COUNTRIES="$DEFAULT_COUNTRIES"
SETNAME="black_list"
CACHE_DIR="/var/lib/ban_asn_cache"
PERSIST_DIR="/etc/nftables"
PERSIST_CONF="$PERSIST_DIR/ban_asn.conf"
PERSIST_IP_LIST="$PERSIST_DIR/ban_asn_ips.txt"
RUNTIME_CONF="/run/nftables.ban_asn.conf"
APP_CONF_DIR="/etc/ban_asn"
POLICY_CONF="$APP_CONF_DIR/ban_asn.conf"

GITHUB_REPO="https://github.com/oOuuuuOo/ban_ash"
GITHUB_RAW="https://raw.githubusercontent.com/oOuuuuOo/ban_ash/main/ban_asn.sh"

CF_WORKER_URL="https://ouo.run/ban"
FORCE_REINSTALL=0
LANG_MODE="en"

for arg in "$@"; do
    case "$arg" in
        -cn|--cn|--zh|--zh-cn)
            LANG_MODE="cn"
            ;;
        --force-reinstall)
            FORCE_REINSTALL=1
            ;;
    esac
done

FILTERED_ARGS=()
for arg in "$@"; do
    case "$arg" in
        -cn|--cn|--zh|--zh-cn)
            ;;
        *)
            FILTERED_ARGS+=("$arg")
            ;;
    esac
done
set -- "${FILTERED_ARGS[@]}"

check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo "✗ 此命令需要 sudo 权限"
        echo "请使用: sudo $0 $@"
        exit 1
    fi
}

get_installed_version() {
    if [ -f "$SCRIPT_FILE" ]; then
        grep "^VERSION=" "$SCRIPT_FILE" 2>/dev/null | cut -d'"' -f2 || echo "unknown"
    fi
}

write_default_policy_conf() {
    mkdir -p "$APP_CONF_DIR"
    cat > "$POLICY_CONF" <<EOF
ASNS="$DEFAULT_ASNS"
COUNTRIES="$DEFAULT_COUNTRIES"
EOF
    chmod 644 "$POLICY_CONF"
}

read_policy_value() {
    local key="$1"
    local raw
    raw=$(grep -E "^${key}=" "$POLICY_CONF" 2>/dev/null | tail -n 1 || true)
    raw="${raw#${key}=}"
    raw="${raw%\"}"
    raw="${raw#\"}"
    raw="${raw%\'}"
    raw="${raw#\'}"
    printf '%s' "$raw"
}

load_policy_conf() {
    ASNS="$DEFAULT_ASNS"
    COUNTRIES="$DEFAULT_COUNTRIES"

    if [ ! -f "$POLICY_CONF" ] && [ "$EUID" -eq 0 ]; then
        write_default_policy_conf
    fi

    if [ -f "$POLICY_CONF" ]; then
        local conf_asns conf_countries
        conf_asns=$(read_policy_value "ASNS")
        conf_countries=$(read_policy_value "COUNTRIES")

        if [ -n "${conf_asns// }" ]; then
            ASNS="$conf_asns"
        fi
        if [ -n "${conf_countries// }" ]; then
            COUNTRIES="$conf_countries"
        fi
    fi
}

check_package() {
    if [ -f /etc/debian_version ]; then
        dpkg -l | grep -qw "$1" && return 0 || return 1
    elif [ -f /etc/redhat-release ]; then
        rpm -q "$1" >/dev/null 2>&1 && return 0 || return 1
    fi
    return 1
}

check_env() {
    echo "[检查] 系统环境和依赖..."
    PACKAGES="nftables whois curl python3"
    MISSING=""
    
    for pkg in $PACKAGES; do
        if ! check_package "$pkg"; then
            MISSING="$MISSING $pkg"
            echo "  ⚠ 缺失: $pkg"
        else
            echo "  ✓ 已装: $pkg"
        fi
    done
    
    if [ -n "$MISSING" ]; then
        echo ""
        echo "[提示] 需要安装的组件: $MISSING"
        echo -n "是否继续安装? (y/yes 确认, 其他取消): "
        read -r confirm
        
        if [[ "$confirm" == "y" || "$confirm" == "yes" ]]; then
            echo "[安装] 正在安装缺失组件..."
            if [ -f /etc/debian_version ]; then
                apt-get update && apt-get install -y $MISSING
                if [ $? -ne 0 ]; then
                    echo "✗ 安装失败，请手动安装: $MISSING"
                    exit 1
                fi
            elif [ -f /etc/redhat-release ]; then
                yum install -y $MISSING || dnf install -y $MISSING
                if [ $? -ne 0 ]; then
                    echo "✗ 安装失败，请手动安装: $MISSING"
                    exit 1
                fi
            else
                echo "✗ 无法识别的系统类型，请手动安装: $MISSING"
                exit 1
            fi
            echo "[完成] 依赖安装完毕"
        else
            echo "✗ 用户取消安装，无法继续"
            exit 1
        fi
    fi
    
    mkdir -p "$CACHE_DIR" "$PERSIST_DIR"
    chmod 755 "$PERSIST_DIR"
}

save_to_persistence() {
    local prefixes="$1"
    local conf_file="$2"

    cat > "$conf_file" <<EOF
table inet filter {
    set $SETNAME {
        type ipv4_addr
        flags interval
        elements = {
$(echo "$prefixes" | awk '{print "            " $1 ","}')
        }
    }
    chain china_cloud_black {
        type filter hook input priority -10; policy accept;
        ct state established,related accept
        ip saddr @$SETNAME counter log prefix "[BLOCK_SCAN] " flags all limit rate 10/minute burst 5 packets drop
    }
    chain china_cloud_black_fwd {
        type filter hook forward priority -10; policy accept;
        ct state established,related accept
        ip saddr @$SETNAME counter log prefix "[BLOCK_SCAN] " flags all limit rate 10/minute burst 5 packets drop
    }
}
EOF
    chmod 644 "$conf_file"
}

load_from_persistence() {
    if [ -f "$PERSIST_CONF" ]; then
        echo "从持久化文件加载配置..."
        nft delete table inet filter 2>/dev/null
        if nft -f "$PERSIST_CONF"; then
            echo "✓ 已从持久化配置恢复"
            return 0
        else
            echo "✗ 加载持久化配置失败"
            return 1
        fi
    fi
    return 1
}

get_asn_prefixes() {
    local asn=$1
    local res=""

    res=$(whois -h whois.radb.net -- "-i origin AS$asn" 2>/dev/null | grep -E "^route:" | awk '{print $2}')

    if [ -z "$res" ]; then
        res=$(curl -s "https://ip.guide/AS$asn" | python3 -c "import sys, json; d=json.load(sys.stdin); print('\n'.join(d.get('routes', [])))" 2>/dev/null)
    fi

    if [ -z "$res" ]; then
        res=$(curl -s "https://api.hackertarget.com/aslookup/?q=AS$asn" | grep "/" 2>/dev/null)
    fi

    echo "$res"
}

get_country_prefixes() {
    local cc=$1
    curl -s --connect-timeout 10 --retry 3 "http://www.ipdeny.com/ipblocks/data/countries/${cc}.zone"
}

exec_install_command() {
    local installer="$1"
    if [ "$EUID" -ne 0 ]; then
        if [ "$FORCE_REINSTALL" -eq 1 ]; then
            exec sudo "$installer" install --force-reinstall
        else
            exec sudo "$installer" install
        fi
    else
        if [ "$FORCE_REINSTALL" -eq 1 ]; then
            exec "$installer" install --force-reinstall
        else
            exec "$installer" install
        fi
    fi
}

resolve_editor_command() {
    local editor_cmd="${EDITOR:-vi}"
    if ! command -v "$editor_cmd" >/dev/null 2>&1; then
        editor_cmd="vi"
    fi
    printf '%s' "$editor_cmd"
}

bootstrap_install_from_stdin() {
    local tmp_script="/tmp/ban_asn.sh"
    local installed_version=""
    local new_version=""

    echo "🚀 检测到一键安装模式，准备安装 ban_asn..."

    if ! curl -fsSL "$CF_WORKER_URL" -o "$tmp_script"; then
        echo "✗ 下载安装脚本失败: $CF_WORKER_URL"
        exit 1
    fi

    chmod +x "$tmp_script"

    if [ -f "$SCRIPT_FILE" ]; then
        installed_version=$(grep "^VERSION=" "$SCRIPT_FILE" 2>/dev/null | cut -d'"' -f2 || true)
    fi
    new_version=$(grep "^VERSION=" "$tmp_script" 2>/dev/null | cut -d'"' -f2 || true)

    if [ "$FORCE_REINSTALL" -eq 0 ] && [ -n "$installed_version" ] && [ -n "$new_version" ] && [ "$installed_version" = "$new_version" ] && [ -x "$GLOBALCMD" ]; then
        echo "✅ 检测到已安装 ban_asn (v$installed_version)，无需重复安装"
        echo "💡 可使用: oban status / oban version"
        exit 0
    fi

    if [ "$FORCE_REINSTALL" -eq 1 ]; then
        echo "⚠️  已启用强制重装 (--force-reinstall)，将覆盖当前安装"
    fi

    exec_install_command "$tmp_script"
}

if [ ! -t 0 ] && { [ -z "$1" ] || [ "$1" = "--force-reinstall" ]; }; then
    bootstrap_install_from_stdin
fi

load_policy_conf

cmd_ban() {
    check_env
    echo "--- 开始同步全球黑名单数据 ---"
    ALL_RAW=""

    for asn in $ASNS; do
        if [ -f "$CACHE_DIR/AS$asn" ] && [ -s "$CACHE_DIR/AS$asn" ] && [ "$(( $(date +%s) - $(stat -c %Y "$CACHE_DIR/AS$asn") ))" -lt 86400 ]; then
            echo "[缓存] AS$asn"; prefixes=$(cat "$CACHE_DIR/AS$asn")
        else
            echo "[网络] AS$asn"; prefixes=$(get_asn_prefixes "$asn")
            if [ -n "$prefixes" ]; then
                echo "$prefixes" > "$CACHE_DIR/AS$asn"
            else
                echo "[警告] AS$asn 获取失败，请检查网络"
            fi
        fi
        ALL_RAW+=$'\n'"$prefixes"
    done

    for cc in $COUNTRIES; do
        echo "[网络] 国家: $cc"
        prefixes=$(get_country_prefixes "$cc")
        ALL_RAW+=$'\n'"$prefixes"
    done

    echo "正在合并海量数据 (Python 极速合并)..."
    CLEAN_PREFIXES=$(echo "$ALL_RAW" | python3 -c '
import sys, ipaddress
ips = []
for line in sys.stdin:
    line = line.strip()
    if "/" in line:
        try: ips.append(ipaddress.ip_network(line))
        except: pass
merged = ipaddress.collapse_addresses(ips)
for net in merged:
    print(net)
')

    if [ -f "$PERSIST_IP_LIST" ]; then
        CUSTOM_IPS=$(cat "$PERSIST_IP_LIST" | grep -v "^#" | grep -v "^$")
        CLEAN_PREFIXES=$(echo -e "$CLEAN_PREFIXES\n$CUSTOM_IPS" | python3 -c '
import sys, ipaddress
ips = []
for line in sys.stdin:
    line = line.strip()
    if "/" in line or "/" not in line and ":" not in line:  # 支持单个IP
        try:
            if "/" not in line:
                line = line + "/32"
            ips.append(ipaddress.ip_network(line))
        except: pass
merged = ipaddress.collapse_addresses(ips)
for net in merged:
    print(net)
')
    fi

    save_to_persistence "$CLEAN_PREFIXES" "$PERSIST_CONF"

    echo "正在原子化注入内核 (请稍候)..."
    nft delete table inet filter 2>/dev/null
    if nft -f "$PERSIST_CONF"; then
        echo "完成！目前封禁网段数: $(echo "$CLEAN_PREFIXES" | wc -l)"
        echo "✓ 配置已持久化到 $PERSIST_CONF"
    else
        echo "错误：数据注入失败。"
    fi
}

cmd_add_ip() {
    if [ -z "$2" ]; then
        echo "Usage: $0 add_ip <IP或IP段>"
        echo "示例: $0 add_ip 192.168.1.1/24"
        exit 1
    fi

    check_env
    IP="$2"

    if ! echo "$IP" | grep -qE '^[0-9./]+$'; then
        echo "错误：IP地址格式不正确"
        exit 1
    fi

    if [[ ! "$IP" =~ / ]]; then
        IP="$IP/32"
    fi

    echo "$IP" >> "$PERSIST_IP_LIST"
    echo "✓ 已添加 $IP 到自定义列表"

    if nft list set inet filter $SETNAME >/dev/null 2>&1; then
        nft add element inet filter $SETNAME "{ $IP }"
        echo "✓ 已立即生效"
    else
        echo "⚠ 当前没有激活的黑名单，请先运行: $0 ban"
    fi
}

cmd_update() {
    if [ -z "$2" ]; then
        echo "Usage: $0 update <country|all>"
        echo "示例: $0 update ru  (更新俄罗斯ASN)"
        echo "      $0 update all (更新所有ASN和国家)"
        exit 1
    fi

    check_env
    TARGET="$2"
    ALL_RAW=""

    echo "--- 开始更新黑名单 ($TARGET) ---"

    if [ "$TARGET" = "all" ]; then
        for asn in $ASNS; do
            echo "[更新] AS$asn"
            rm -f "$CACHE_DIR/AS$asn"  # 清除缓存强制重新获取
            prefixes=$(get_asn_prefixes "$asn")
            if [ -n "$prefixes" ]; then
                echo "$prefixes" > "$CACHE_DIR/AS$asn"
                ALL_RAW+=$'\n'"$prefixes"
            fi
        done

        for cc in $COUNTRIES; do
            echo "[更新] 国家: $cc"
            prefixes=$(get_country_prefixes "$cc")
            ALL_RAW+=$'\n'"$prefixes"
        done
    else
        if echo "$ASNS" | grep -qw "$TARGET"; then
            echo "[更新] AS$TARGET"
            rm -f "$CACHE_DIR/AS$TARGET"
            prefixes=$(get_asn_prefixes "$TARGET")
            if [ -n "$prefixes" ]; then
                echo "$prefixes" > "$CACHE_DIR/AS$TARGET"
                ALL_RAW="$prefixes"
            fi
        elif echo "$COUNTRIES" | grep -qw "$TARGET"; then
            echo "[更新] 国家: $TARGET"
            prefixes=$(get_country_prefixes "$TARGET")
            ALL_RAW="$prefixes"
        else
            echo "错误：未知的ASN或国家代码 ($TARGET)"
            echo "已配置ASN: $ASNS"
            echo "已配置国家: $COUNTRIES"
            exit 1
        fi
    fi

    echo "正在合并更新数据..."
    CURRENT_PREFIXES=$(echo "$ALL_RAW" | python3 -c '
import sys, ipaddress
ips = []
for line in sys.stdin:
    line = line.strip()
    if "/" in line:
        try: ips.append(ipaddress.ip_network(line))
        except: pass
merged = ipaddress.collapse_addresses(ips)
for net in merged:
    print(net)
')

    if [ "$TARGET" = "all" ]; then
        ALL_RAW=""
        for asn in $ASNS; do
            if [ -f "$CACHE_DIR/AS$asn" ]; then
                ALL_RAW+=$'\n'"$(cat $CACHE_DIR/AS$asn)"
            fi
        done
        for cc in $COUNTRIES; do
            prefixes=$(get_country_prefixes "$cc")
            ALL_RAW+=$'\n'"$prefixes"
        done

        CLEAN_PREFIXES=$(echo "$ALL_RAW" | python3 -c '
import sys, ipaddress
ips = []
for line in sys.stdin:
    line = line.strip()
    if "/" in line:
        try: ips.append(ipaddress.ip_network(line))
        except: pass
merged = ipaddress.collapse_addresses(ips)
for net in merged:
    print(net)
')
    else
        echo "抽取现有配置..."
        EXISTING=$(nft list set inet filter $SETNAME 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | sort -u)
        CLEAN_PREFIXES=$(echo -e "$EXISTING\n$CURRENT_PREFIXES" | python3 -c '
import sys, ipaddress
ips = []
seen = set()
for line in sys.stdin:
    line = line.strip()
    if "/" in line and line not in seen:
        try:
            ips.append(ipaddress.ip_network(line))
            seen.add(line)
        except: pass
merged = ipaddress.collapse_addresses(ips)
for net in merged:
    print(net)
')
    fi

    if [ -f "$PERSIST_IP_LIST" ]; then
        CUSTOM_IPS=$(cat "$PERSIST_IP_LIST" | grep -v "^#" | grep -v "^$")
        CLEAN_PREFIXES=$(echo -e "$CLEAN_PREFIXES\n$CUSTOM_IPS" | python3 -c '
import sys, ipaddress
ips = []
for line in sys.stdin:
    line = line.strip()
    if "/" in line or "/" not in line and ":" not in line:
        try:
            if "/" not in line:
                line = line + "/32"
            ips.append(ipaddress.ip_network(line))
        except: pass
merged = ipaddress.collapse_addresses(ips)
for net in merged:
    print(net)
')
    fi

    save_to_persistence "$CLEAN_PREFIXES" "$PERSIST_CONF"

    echo "正在更新内核规则..."
    nft delete table inet filter 2>/dev/null
    if nft -f "$PERSIST_CONF"; then
        echo "✓ 更新完成！目前封禁网段数: $(echo "$CLEAN_PREFIXES" | wc -l)"
    else
        echo "错误：更新失败"
        exit 1
    fi
}

cmd_status() {
    if nft list table inet filter >/dev/null 2>&1; then
        echo "--- 全球防御状态报告 ---"
        echo "运行状态: [已激活]"
        echo "持久化文件: $PERSIST_CONF"
        count=$(nft list set inet filter $SETNAME | wc -l)
        echo "封禁网段: $((count - 7)) 个"
        rule_info=$(nft list chain inet filter china_cloud_black 2>/dev/null | grep "drop")
        pkts=$(echo "$rule_info" | awk '{for(i=1;i<=NF;i++) if($i=="packets") print $(i+1)}')
        bytes=$(echo "$rule_info" | awk '{for(i=1;i<=NF;i++) if($i=="bytes") print $(i+1)}')
        echo "拦截统计: ${pkts:-0} 数据包 / ${bytes:-0} 字节"
        [[ "$rule_info" == *"log"* ]] && echo "日志状态: [已开启(限速)]"

        if [ -f "$PERSIST_IP_LIST" ]; then
            custom_count=$(grep -v "^#" "$PERSIST_IP_LIST" | grep -v "^$" | wc -l)
            echo "自定义IP: $custom_count 个"
        fi
    else
        echo "运行状态: [未激活]"
        if load_from_persistence; then
            echo "✓ 已尝试从持久化配置恢复"
        fi
    fi
}

cmd_unban() {
    nft delete table inet filter 2>/dev/null
    echo "✓ 已解除封禁"
    echo "⚠ 持久化配置文件仍保留在 $PERSIST_CONF"
}

cmd_restore() {
    check_env
    echo "--- 正在恢复持久化配置 ---"
    if load_from_persistence; then
        echo "✓ 配置已恢复"
    else
        echo "✗ 未找到持久化配置"
        exit 1
    fi
}

cmd_install() {
    check_sudo
    INSTALLED_VERSION=$(get_installed_version)
    TARGET_VERSION="$VERSION"
    INSTALL_MODE="fresh"

    if [ -n "$INSTALLED_VERSION" ]; then
        if [ "$FORCE_REINSTALL" -eq 0 ] && [ "$INSTALLED_VERSION" = "$TARGET_VERSION" ] && [ -x "$GLOBALCMD" ]; then
            echo "✅ 当前已安装 ban_asn v$INSTALLED_VERSION，无需重复安装"
            echo "💡 可使用: oban status / oban version"
            exit 0
        fi
        INSTALL_MODE="upgrade"
        if [ "$FORCE_REINSTALL" -eq 1 ]; then
            echo "♻️  检测到已安装版本: v${INSTALLED_VERSION:-unknown}，执行强制重装到 v$TARGET_VERSION..."
        else
            echo "⬆️  检测到已安装版本: v${INSTALLED_VERSION:-unknown}，正在升级到 v$TARGET_VERSION..."
        fi
    else
        echo "🔄 开始安装 ban_asn..."
    fi

    mkdir -p "$SCRIPT_DIR"

    if [ "$(readlink -f "$0" 2>/dev/null)" = "/tmp/ban_asn.sh" ] && [ -f "/tmp/ban_asn.sh" ]; then
        cp "/tmp/ban_asn.sh" "$SCRIPT_FILE"
    else
        cp "$0" "$SCRIPT_FILE"
    fi
    chmod +x "$SCRIPT_FILE"
    echo "✓ 脚本已安装到 $SCRIPT_FILE"

    cat > "$GLOBALCMD" <<'WRAPPER'
#!/bin/bash
sudo /opt/ban_asn/ban_asn.sh "$@"
WRAPPER
    chmod +x "$GLOBALCMD"
    echo "✓ 全局命令已创建: $GLOBALCMD"

    REAL_USER="${SUDO_USER:-$(whoami)}"

    cat > "$SUDOERS_FILE" <<SUDOERS
Defaults:$REAL_USER !requiretty
$REAL_USER ALL=(ALL) NOPASSWD: /opt/ban_asn/ban_asn.sh
SUDOERS
    chmod 440 "$SUDOERS_FILE"
    echo "✓ Sudoers 配置已设置（用户: $REAL_USER）"

    cat > "$SYSTEMD_SERVICE" <<'SYSTEMD'
[Unit]
Description=Global ASN/Country IP Blacklist (ban_asn)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/opt/ban_asn/ban_asn.sh restore
ExecReload=/opt/ban_asn/ban_asn.sh restore
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SYSTEMD
    chmod 644 "$SYSTEMD_SERVICE"
    systemctl daemon-reload
    systemctl enable ban-asn.service
    echo "✓ Systemd 服务已注册"

    mkdir -p "$CACHE_DIR" "$PERSIST_DIR"
    touch "$PERSIST_IP_LIST"
    chmod 755 "$PERSIST_DIR" "$CACHE_DIR"

    if [ ! -f "$POLICY_CONF" ]; then
        write_default_policy_conf
    fi
    echo "✓ 策略配置文件: $POLICY_CONF"

    echo ""
    if [ "$INSTALL_MODE" = "upgrade" ]; then
        echo "✅ 升级完成！当前版本: v$TARGET_VERSION"
    else
        echo "✅ 安装完成！"
    fi
    echo ""
    echo "📖 使用方式:"
    echo "   oban ban                 # 激活全球黑名单"
    echo "   oban status              # 查看状态"
    echo "   oban add_ip <IP>         # 添加自定义IP"
    echo "   oban update <target>     # 更新指定国家或ASN"
    echo "   oban unban               # 解除黑名单"
    echo "   oban upgrade             # 升级到最新版本"
    echo "   oban version             # 显示版本信息"
    echo ""
    if [ "$INSTALL_MODE" = "fresh" ]; then
        echo "⚠️  首次使用请运行: oban ban"
    else
        echo "ℹ️  升级后可运行: oban status"
    fi
}

cmd_uninstall() {
    check_sudo
    if [ "$LANG_MODE" = "cn" ]; then
        echo "⚠️  确认要卸载 ban_asn 吗？(y/yes 确认): "
    else
        echo "⚠️  Confirm uninstall ban_asn? (y/yes to confirm): "
    fi
    read -r confirm

    if [[ "$confirm" != "y" && "$confirm" != "yes" ]]; then
        echo "✗ 已取消卸载"
        exit 0
    fi

    echo "🔄 开始卸载..."

    systemctl stop ban-asn.service 2>/dev/null || true
    systemctl disable ban-asn.service 2>/dev/null || true

    nft delete table inet filter 2>/dev/null || true

    rm -f "$SYSTEMD_SERVICE"
    rm -f "$GLOBALCMD"
    rm -f "$SUDOERS_FILE"
    rm -rf "$SCRIPT_DIR"
    rm -rf "$PERSIST_DIR"
    rm -rf "$CACHE_DIR"
    rm -rf "$APP_CONF_DIR"

    systemctl daemon-reload

    echo "✅ 卸载完成"
    echo "所有规则、配置和缓存已删除"
}

cmd_upgrade() {
    check_sudo
    echo "🔄 检查最新版本..."

    NEW_SCRIPT=$(mktemp)
    trap "rm -f '$NEW_SCRIPT'" EXIT

    if ! curl -sL "$CF_WORKER_URL" > "$NEW_SCRIPT"; then
        echo "✗ 下载最新脚本失败"
        exit 1
    fi

    chmod +x "$NEW_SCRIPT"

    NEW_VERSION=$(grep "^VERSION=" "$NEW_SCRIPT" | cut -d'"' -f2)
    CURRENT_VERSION=$(get_installed_version)

    echo "当前版本: $CURRENT_VERSION"
    echo "最新版本: $NEW_VERSION"

    if [ "$NEW_VERSION" = "$CURRENT_VERSION" ]; then
        echo "✓ 已是最新版本"
        exit 0
    fi

    echo ""
    echo "⚠️  确认升级到 $NEW_VERSION 吗？(y/yes 确认): "
    read -r confirm

    if [[ "$confirm" != "y" && "$confirm" != "yes" ]]; then
        echo "✗ 已取消升级"
        exit 0
    fi

    systemctl stop ban-asn.service 2>/dev/null || true

    cp "$NEW_SCRIPT" "$SCRIPT_FILE"
    echo "✓ 脚本已升级到 $NEW_VERSION"

    systemctl start ban-asn.service 2>/dev/null || true

    echo "✅ 升级完成！"
}

cmd_version() {
    echo "ban_asn.sh v$VERSION"
    echo "发布日期: $RELEASE_DATE"
    echo "安装路径: $SCRIPT_FILE"
    echo "配置路径: $PERSIST_DIR"
    echo "策略配置: $POLICY_CONF"
    echo ""
    echo "仓库地址: $GITHUB_REPO"
    echo "分发地址: $CF_WORKER_URL"
}

cmd_config() {
    if [ "$2" = "edit" ]; then
        check_sudo
        if [ ! -f "$POLICY_CONF" ]; then
            write_default_policy_conf
        fi

        EDITOR_CMD="$(resolve_editor_command)"

        if [ "$3" = "--check" ]; then
            if [ "$LANG_MODE" = "cn" ]; then
                echo "✅ 检查通过: editor=$EDITOR_CMD, config=$POLICY_CONF"
            else
                echo "✅ Check passed: editor=$EDITOR_CMD, config=$POLICY_CONF"
            fi
            exit 0
        fi

        if [ "$LANG_MODE" = "cn" ]; then
            echo "📝 正在使用 $EDITOR_CMD 编辑: $POLICY_CONF"
            echo "修改后请运行: oban ban"
        else
            echo "📝 Opening $POLICY_CONF with $EDITOR_CMD"
            echo "Run 'oban ban' after saving changes"
        fi

        "$EDITOR_CMD" "$POLICY_CONF"
    else
        echo "ASNS=\"$ASNS\""
        echo "COUNTRIES=\"$COUNTRIES\""
        echo "POLICY_CONF=\"$POLICY_CONF\""
    fi
}

translate_to_en() {
    local line="$1"
    line="${line//此命令需要 sudo 权限/This command requires sudo privileges}"
    line="${line//，/, }"
    line="${line//（/(}"
    line="${line//）/)}"
    line="${line//请使用:/Please use:}"
    line="${line//无参数时：/No-argument behavior:}"
    line="${line//通过 stdin 执行（curl | bash）=> 自动安装/Run through stdin (curl | bash) => auto install}"
    line="${line//本地直接运行 => 显示帮助/Run locally => show help}"
    line="${line//检测到一键安装模式，准备安装 ban_asn.../One-line installer detected, preparing ban_asn setup...}"
    line="${line//检测到一键安装模式, 准备安装 ban_asn.../One-line installer detected, preparing ban_asn setup...}"
    line="${line//下载安装脚本失败/Failed to download installer script}"
    line="${line//检测到已安装 ban_asn/ban_asn is already installed}"
    line="${line//无需重复安装/skipping reinstall}"
    line="${line//可使用:/You can run:}"
    line="${line//已启用强制重装/Force reinstall enabled}"
    line="${line//将覆盖当前安装/current installation will be overwritten}"
    line="${line//检测到已安装版本/Existing installation detected}"
    line="${line//准备升级到/upgrading to}"
    line="${line//执行强制重装/force reinstalling}"
    line="${line//force reinstalling到 /force reinstalling to }"
    line="${line//正在升级到/upgrading to}"
    line="${line//开始安装 ban_asn.../Starting ban_asn installation...}"
    line="${line//脚本已安装到/Script installed to}"
    line="${line//全局命令已创建/Global command created}"
    line="${line//配置已设置/Configuration applied}"
    line="${line//用户:/user:}"
    line="${line//服务已注册/Systemd service registered}"
    line="${line//升级完成！当前版本/Upgrade completed! Current version}"
    line="${line//安装完成！/Installation completed!}"
    line="${line//使用方式 / Usage:/Usage:}"
    line="${line//使用方式:/Usage:}"
    line="${line//首次使用请运行/First run suggestion:}"
    line="${line//升级后可运行/After upgrade, run:}"
    line="${line//语言选项: -cn (中文输出；默认英文)/Language option: -cn (Chinese output; English by default)}"
    line="${line//检查] 系统环境和依赖/Check] System environment and dependencies}"
    line="${line//缺失:/Missing:}"
    line="${line//已装:/Installed:}"
    line="${line//提示] 需要安装的组件/Hint] Required components}"
    line="${line//是否继续安装?/Continue installation?}"
    line="${line//安装] 正在安装缺失组件/Install] Installing missing components}"
    line="${line//安装失败，请手动安装/Installation failed, please install manually}"
    line="${line//无法识别的系统类型，请手动安装/Unknown system type, please install manually}"
    line="${line//完成] 依赖安装完毕/Done] Dependencies installed}"
    line="${line//用户取消安装，无法继续/User cancelled installation, aborting}"
    line="${line//正在恢复持久化配置/Restoring persisted configuration}"
    line="${line//配置已恢复/Configuration restored}"
    line="${line//未找到持久化配置/Persisted configuration not found}"
    line="${line//开始更新黑名单/Starting blacklist update}"
    line="${line//开始同步全球黑名单数据/Starting global blacklist sync}"
    line="${line//全球防御状态报告/Global Defense Status Report}"
    line="${line//持久化版/persistent edition}"
    line="${line//持久化文件/Persisted file}"
    line="${line//正在合并海量数据 (Python 极速合并).../Merging large dataset (Python fast merge)...}"
    line="${line//正在原子化注入内核 (请稍候).../Applying rules atomically to kernel (please wait)...}"
    line="${line//完成！目前封禁网段数:/Done! Current blocked CIDRs:}"
    line="${line//配置已持久化到/Configuration persisted to}"
    line="${line//缓存/Cache}"
    line="${line//网络/Network}"
    line="${line//警告/Warning}"
    line="${line//国家:/Country:}"
    line="${line//正在更新内核规则.../Updating kernel rules...}"
    line="${line//正在合并更新数据.../Merging updated data...}"
    line="${line//抽取现有配置.../Extracting existing configuration...}"
    line="${line//更新] /Update] }"
    line="${line//错误：/Error: }"
    line="${line//更新完成/Update completed}"
    line="${line//运行状态/Runtime status}"
    line="${line//已激活/active}"
    line="${line//未激活/inactive}"
    line="${line//封禁网段/Blocked CIDRs}"
    line="${line//拦截统计/Blocked traffic}"
    line="${line//日志状态/Log status}"
    line="${line//已开启(限速)/enabled (rate limited)}"
    line="${line//数据包/packets}"
    line="${line//字节/bytes}"
    line="${line// 个/ entries}"
    line="${line//添加自定义IP/Add custom IP}"
    line="${line//自定义IP/Custom IPs}"
    line="${line//已解除封禁/Blacklist disabled}"
    line="${line//确认要卸载/Confirm uninstall}"
    line="${line//已取消卸载/Uninstall cancelled}"
    line="${line//开始卸载/Starting uninstall}"
    line="${line//卸载完成/Uninstall completed}"
    line="${line//所有规则、配置和缓存已删除/All rules, config, and cache removed}"
    line="${line//检查最新版本/Checking latest version}"
    line="${line//下载最新脚本失败/Failed to download latest script}"
    line="${line//当前版本/Current version}"
    line="${line//最新版本/Latest version}"
    line="${line//已是最新版本/Already on latest version}"
    line="${line//确认升级到/Confirm upgrade to}"
    line="${line//已取消升级/Upgrade cancelled}"
    line="${line//脚本已升级到/Script upgraded to}"
    line="${line//升级完成！/Upgrade completed!}"
    line="${line//发布日期/Release date}"
    line="${line//安装路径/Install path}"
    line="${line//配置路径/Config path}"
    line="${line//策略配置文件/Policy config file}"
    line="${line//策略配置/Policy config}"
    line="${line//仓库地址/Repository}"
    line="${line//分发地址/Distribution URL}"
    line="${line//生命周期命令/Lifecycle Commands}"
    line="${line//运行命令/Runtime Commands}"
    line="${line//激活全球黑名单/Enable global blacklist}"
    line="${line//激活黑名单/Enable blacklist}"
    line="${line//解除黑名单/Disable blacklist}"
    line="${line//查看状态/Show status}"
    line="${line//更新指定国家或ASN/Update country or ASN}"
    line="${line//显示版本信息/Show version}"
    line="${line//升级到最新版本/Upgrade to latest version}"
    line="${line//升级到Latest version/Upgrade to latest version}"
    line="${line//显示当前状态/Show current status}"
    line="${line//添加自定义IP/CIDR（会持久化）/Add custom IP/CIDR (persisted)}"
    line="${line//更新指定ASN或国家的列表/Update list by ASN or country}"
    line="${line//目标可以是/Target can be}"
    line="${line//从持久化配置恢复（systemd自启动用）/Restore from persisted config (for systemd startup)}"
    line="${line//After upgrade, run::/After upgrade, run:}"
    printf '%s' "$line"
}

echo() {
    local newline=1
    local escape=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -n) newline=0; shift ;;
            -e) escape=1; shift ;;
            -ne|-en) newline=0; escape=1; shift ;;
            --) shift; break ;;
            *) break ;;
        esac
    done

    local text="$*"
    if [ "$LANG_MODE" != "cn" ]; then
        text="$(translate_to_en "$text")"
    fi

    if [ $escape -eq 1 ]; then
        if [ $newline -eq 1 ]; then
            builtin echo -e "$text"
        else
            builtin echo -ne "$text"
        fi
    else
        if [ $newline -eq 1 ]; then
            builtin echo "$text"
        else
            builtin echo -n "$text"
        fi
    fi
}

print_help() {
    if [ "$LANG_MODE" = "cn" ]; then
        builtin echo "Usage: $0 [-cn] {ban|unban|status|add_ip|update|restore|install|uninstall|upgrade|version|config}"
        builtin echo ""
        builtin echo "语言选项: -cn (中文输出；默认英文)"
        builtin echo ""
        builtin echo "🔧 生命周期命令:"
        builtin echo "  install              - 安装脚本到系统（需要 sudo）"
        builtin echo "  uninstall            - 卸载脚本（需要 sudo）"
        builtin echo "  upgrade              - 升级到最新版本（需要 sudo）"
        builtin echo "  version              - 显示版本信息"
        builtin echo ""
        builtin echo "📋 运行命令:"
        builtin echo "  ban                  - 激活黑名单（基于预定义ASN和国家）"
        builtin echo "  unban                - 解除黑名单"
        builtin echo "  status               - 显示当前状态"
        builtin echo "  config               - 显示当前生效的 ASNS/COUNTRIES"
        builtin echo "  config edit          - 用 \$EDITOR 编辑策略配置"
        builtin echo "  config edit --check  - 检查编辑器与配置文件状态（不打开编辑器）"
        builtin echo "  add_ip <IP>          - 添加自定义IP/CIDR（会持久化）"
        builtin echo "  update <target>      - 更新指定ASN或国家的列表"
        builtin echo "                         目标可以是: 'all' 或具体的ASN/国家代码"
        builtin echo "  restore              - 从持久化配置恢复（systemd自启动用）"
    else
        builtin echo "Usage: $0 [-cn] {ban|unban|status|add_ip|update|restore|install|uninstall|upgrade|version|config}"
        builtin echo ""
        builtin echo "Language option: -cn (Chinese output; English by default)"
        builtin echo ""
        builtin echo "🔧 Lifecycle Commands:"
        builtin echo "  install              - Install script to system (requires sudo)"
        builtin echo "  uninstall            - Uninstall script (requires sudo)"
        builtin echo "  upgrade              - Upgrade to latest version (requires sudo)"
        builtin echo "  version              - Show version information"
        builtin echo ""
        builtin echo "📋 Runtime Commands:"
        builtin echo "  ban                  - Enable blacklist (predefined ASN and countries)"
        builtin echo "  unban                - Disable blacklist"
        builtin echo "  status               - Show current status"
        builtin echo "  config               - Show effective ASNS/COUNTRIES"
        builtin echo "  config edit          - Edit policy config with \$EDITOR"
        builtin echo "  config edit --check  - Check editor/config readiness (without opening editor)"
        builtin echo "  add_ip <IP>          - Add custom IP/CIDR (persisted)"
        builtin echo "  update <target>      - Update list by ASN or country"
        builtin echo "                         Target can be: 'all' or specific ASN/country code"
        builtin echo "  restore              - Restore from persisted config (for systemd startup)"
    fi
}

case "$1" in
    ban)
        cmd_ban "$@"
        ;;
    add_ip)
        cmd_add_ip "$@"
        ;;
    update)
        cmd_update "$@"
        ;;
    status)
        cmd_status "$@"
        ;;
    unban)
        cmd_unban "$@"
        ;;
    restore)
        cmd_restore "$@"
        ;;
    install)
        cmd_install "$@"
        ;;
    uninstall)
        cmd_uninstall "$@"
        ;;
    upgrade)
        cmd_upgrade "$@"
        ;;
    version)
        cmd_version "$@"
        ;;
    config)
        cmd_config "$@"
        ;;
    -h|--help|help)
        print_help
        exit 0
        ;;
    *)
        print_help
        exit 1
        ;;
esac

