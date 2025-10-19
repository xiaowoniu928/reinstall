#!/bin/ash
# shellcheck shell=dash
# alpine/debian initrd 共用此脚本

# accept_ra 接收 RA + 自动配置网关
# autoconf  自动配置地址，依赖 accept_ra

# Arguments from reinstall.sh (MAC might be ignored now)
mac_addr=$1
ipv4_addr=$2
ipv4_gateway=$3
ipv6_addr=$4
ipv6_gateway=$5
is_in_china=$6

DHCP_TIMEOUT=15
DNS_FILE_TIMEOUT=5
TEST_TIMEOUT=10

# ... [DNS IP definitions remain the same] ...

# --- NEW get_ethx function ---
# Tries to find the interface via default route, falls back to first up non-lo.
get_ethx() {
    local default_iface
    local first_up_iface

    # Try IPv4 default route
    default_iface=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {print $(NF-1); exit}')

    # Try IPv6 default route if IPv4 failed
    if [ -z "$default_iface" ]; then
        default_iface=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '/dev/ {print $(NF-1); exit}')
    fi

    if [ -n "$default_iface" ]; then
        echo "$default_iface"
        return 0
    fi

    # Fallback: Find the first non-loopback interface that is UP
    first_up_iface=$(ip -o link show up | awk '!/LOOPBACK/ {print $2; exit}' | cut -d: -f1)

    if [ -n "$first_up_iface" ]; then
        echo "Warning: Could not determine interface via default route. Falling back to first UP interface: $first_up_iface" >&2
        echo "$first_up_iface"
        return 0
    else
        echo "Error: Could not determine network interface." >&2
        return 1
    fi
}
# --- END NEW get_ethx function ---


get_ipv4_gateway() {
    ip -4 route show default dev "$ethx" | head -1 | cut -d ' ' -f3
}

# ... [Other helper functions like get_ipv6_gateway, get_first_ipvX_addr, is_have_ipvX, etc. remain the same] ...
# ... [They will now use the dynamically determined $ethx] ...

is_have_ipv4_dns() {
    [ -f /etc/resolv.conf ] && grep -q '^nameserver .*\.' /etc/resolv.conf
}

is_have_ipv6_dns() {
    [ -f /etc/resolv.conf ] && grep -q '^nameserver .*:' /etc/resolv.conf
}

add_missing_ipv4_config() {
    if [ -n "$ipv4_addr" ] && [ -n "$ipv4_gateway" ]; then
        if ! is_have_ipv4_addr; then
            ip -4 addr add "$ipv4_addr" dev "$ethx"
        fi
        if ! is_have_ipv4_gateway; then
            ip -4 route add "$ipv4_gateway" dev "$ethx" || true # Allow failure if already exists somehow
            ip -4 route add default via "$ipv4_gateway" dev "$ethx" || true
        fi
    fi
}

add_missing_ipv6_config() {
    if [ -n "$ipv6_addr" ] && [ -n "$ipv6_gateway" ]; then
        if ! is_have_ipv6_addr; then
            ip -6 addr add "$ipv6_addr" dev "$ethx"
        fi
        if ! is_have_ipv6_gateway; then
             ip -6 route add "$ipv6_gateway" dev "$ethx" || true # Allow failure
             ip -6 route add default via "$ipv6_gateway" dev "$ethx" || true
        fi
    fi
}

is_need_test_ipv4() {
    is_have_ipv4 && ! $ipv4_has_internet
}

is_need_test_ipv6() {
    is_have_ipv6 && ! $ipv6_has_internet
}

# ... [test_by_wget, test_by_nc, is_debian_kali, test_connect, test_internet remain the same] ...

flush_ipv4_config() {
    ip -4 addr flush scope global dev "$ethx"
    ip -4 route flush dev "$ethx"
    sed -i "/\./d" /etc/resolv.conf
}

should_disable_dhcpv4=false
should_disable_accept_ra=false
should_disable_autoconf=false

flush_ipv6_config() {
    if $should_disable_accept_ra; then echo 0 >"/proc/sys/net/ipv6/conf/$ethx/accept_ra"; fi
    if $should_disable_autoconf; then echo 0 >"/proc/sys/net/ipv6/conf/$ethx/autoconf"; fi
    ip -6 addr flush scope global dev "$ethx"
    ip -6 route flush dev "$ethx"
    sed -i "/:/d" /etc/resolv.conf
}

# --- SCRIPT START ---
# Determine the primary interface name first
ethx=$(get_ethx)
if [ -z "$ethx" ]; then
    echo "Fatal: Could not find a suitable network interface."
    exit 1
fi
echo "Primary interface determined as: $ethx"

# (Optional) You could try to find the MAC of the determined $ethx if needed later,
# though the script is trying to move away from relying on it.
# found_mac=$(ip -o link show dev "$ethx" | awk '/link\/ether/ {print $17}')

echo "Configuring $ethx..."

ip link set dev lo up
ip link set dev "$ethx" up
sleep 1

# ... [DHCP/SLAAC/Static IP logic remains largely the same, using the determined $ethx] ...
# ... [The logic comparing obtained IPs vs passed IPs ($ipv4_addr, $ipv6_addr) still works] ...
# ... [It compares current state against expected state] ...

# (Example section, needs integration into the existing DHCP/Static logic flow)
# Initiate DHCP/SLAAC
if [ -f /usr/share/debconf/confmodule ]; then
    # Debian/Kali DHCP logic using udhcpc and dhcp6c
    . /usr/share/debconf/confmodule
    db_progress STEP 1
    db_progress INFO netcfg/dhcp_progress
    udhcpc -i "$ethx" -f -q -n -t 5 || true # Added timeout
    db_progress STEP 1
    db_progress INFO netcfg/slaac_wait_title
    cat <<EOF >/var/lib/netcfg/dhcp6c.conf
interface $ethx { send ia-na 0; request domain-name-servers; request domain-name; script "/lib/netcfg/print-dhcp6c-info"; }; id-assoc na 0 {};
EOF
    timeout $DHCP_TIMEOUT dhcp6c -c /var/lib/netcfg/dhcp6c.conf "$ethx" || true
    # kill might fail if timeout already killed it
    kill "$(cat /var/run/dhcp6c.pid 2>/dev/null)" 2>/dev/null || true
    rm -f /var/run/dhcp6c.pid
    db_progress STEP 1
    db_subst netcfg/link_detect_progress interface "$ethx"; db_progress INFO netcfg/link_detect_progress
else
    # Alpine DHCP logic using dhcpcd (preferred)
    method=dhcpcd
    case "$method" in
    dhcpcd)
        grep -q dhcpcd /etc/group || addgroup -S dhcpcd
        grep -q dhcpcd /etc/passwd || adduser -S -D -H -h /var/lib/dhcpcd -s /sbin/nologin -G dhcpcd -g dhcpcd dhcpcd
        # Try to get lease and DNS quickly, then exit daemon
        dhcpcd --persistent --noipv4ll "$ethx" # Backgrounds quickly
        sleep $DNS_FILE_TIMEOUT                # Wait for DNS
        dhcpcd -x "$ethx"                      # Stop daemon
        # Re-enable autoconf/RA if dhcpcd turned them off
        sysctl -w "net.ipv6.conf.$ethx.autoconf=1" >/dev/null 2>&1 || true
        sysctl -w "net.ipv6.conf.$ethx.accept_ra=1" >/dev/null 2>&1 || true
        ;;
    # udhcpc case removed for simplicity, dhcpcd is generally better
    esac
fi

# Wait briefly for SLAAC if no IPv6 address yet
for i in $(seq 3 -1 0); do is_have_ipv6 && break; echo "waiting potentially for slaac ${i}s"; sleep 1; done

# Record if dynamic addresses were obtained
is_have_ipv4_addr && dhcpv4=true || dhcpv4=false
is_have_ipv6_addr && dhcpv6_or_slaac=true || dhcpv6_or_slaac=false
is_have_ipv6_gateway && ra_has_gateway=true || ra_has_gateway=false # Check if RA provided a gateway

# --- Logic to compare obtained dynamic vs expected static, flush if needed ---
current_ipv4=$(get_first_ipv4_addr | cut -d/ -f1)
current_ipv6=$(get_first_ipv6_addr | cut -d/ -f1)
expected_ipv4=$(echo "$ipv4_addr" | cut -d/ -f1)
expected_ipv6=$(echo "$ipv6_addr" | cut -d/ -f1)

if $dhcpv4 && [ -n "$expected_ipv4" ] && [ "$current_ipv4" != "$expected_ipv4" ]; then
    echo "IPv4 address ($current_ipv4) from DHCP differs from expected ($expected_ipv4). Switching to static."
    should_disable_dhcpv4=true
    flush_ipv4_config
fi
if $dhcpv6_or_slaac && [ -n "$expected_ipv6" ] && [ "$current_ipv6" != "$expected_ipv6" ]; then
    echo "IPv6 address ($current_ipv6) from DHCP6/SLAAC differs from expected ($expected_ipv6). Switching to static."
    should_disable_accept_ra=true
    should_disable_autoconf=true
    flush_ipv6_config
fi

# Apply static config if needed (or re-apply if flushed)
add_missing_ipv4_config
add_missing_ipv6_config

# Test connectivity
ipv4_has_internet=false
ipv6_has_internet=false
test_internet

# --- Logic to compare obtained dynamic netmask/gateway vs expected static, flush if needed ---
current_ipv4_gw=$(get_first_ipv4_gateway)
current_ipv6_gw=$(get_first_ipv6_gateway)

if ! $ipv4_has_internet && $dhcpv4 && [ -n "$ipv4_addr" ] && [ -n "$ipv4_gateway" ] &&
   ! { [ "$ipv4_addr" = "$(get_first_ipv4_addr)" ] && [ "$ipv4_gateway" = "$current_ipv4_gw" ]; }; then
    echo "IPv4 seems offline, and DHCP netmask/gateway differs from expected. Switching to static."
    should_disable_dhcpv4=true
    flush_ipv4_config
    add_missing_ipv4_config
    test_internet # Retest after applying static
fi
if ! $ipv6_has_internet && { $dhcpv6_or_slaac || $ra_has_gateway; } &&
   [ -n "$ipv6_addr" ] && [ -n "$ipv6_gateway" ] &&
   ! { [ "$ipv6_addr" = "$(get_first_ipv6_addr)" ] && [ "$ipv6_gateway" = "$current_ipv6_gw" ]; }; then
    echo "IPv6 seems offline, and DHCP6/SLAAC netmask/gateway differs from expected. Switching to static."
    should_disable_accept_ra=true
    should_disable_autoconf=true
    flush_ipv6_config
    add_missing_ipv6_config
    test_internet # Retest after applying static
fi


# --- Flush configurations that don't have internet ---
if ! $ipv4_has_internet; then
    if $dhcpv4; then should_disable_dhcpv4=true; fi
    echo "Flushing non-working IPv4 configuration for $ethx."
    flush_ipv4_config
fi
if ! $ipv6_has_internet; then
    if $dhcpv6_or_slaac; then should_disable_accept_ra=true; should_disable_autoconf=true; fi
    echo "Flushing non-working IPv6 configuration for $ethx."
    flush_ipv6_config
fi

# Add fallback DNS if needed
if ! is_have_ipv4_dns && $ipv4_has_internet; then # Only add if protocol works
    echo "Adding fallback IPv4 DNS."
    echo "nameserver $ipv4_dns1" >>/etc/resolv.conf
    echo "nameserver $ipv4_dns2" >>/etc/resolv.conf
fi
if ! is_have_ipv6_dns && $ipv6_has_internet; then # Only add if protocol works
    echo "Adding fallback IPv6 DNS."
    echo "nameserver $ipv6_dns1" >>/etc/resolv.conf
    echo "nameserver $ipv6_dns2" >>/etc/resolv.conf
fi

# Save state for trans.sh
netconf="/dev/netconf/$ethx"
mkdir -p "$netconf"
# Use determined state variables
$dhcpv4 && echo 1 >"$netconf/dhcpv4" || echo 0 >"$netconf/dhcpv4"
$dhcpv6_or_slaac && echo 1 >"$netconf/dhcpv6_or_slaac" || echo 0 >"$netconf/dhcpv6_or_slaac"
$should_disable_dhcpv4 && echo 1 >"$netconf/should_disable_dhcpv4" || echo 0 >"$netconf/should_disable_dhcpv4"
$should_disable_accept_ra && echo 1 >"$netconf/should_disable_accept_ra" || echo 0 >"$netconf/should_disable_accept_ra"
$should_disable_autoconf && echo 1 >"$netconf/should_disable_autoconf" || echo 0 >"$netconf/should_disable_autoconf"
$is_in_china && echo 1 >"$netconf/is_in_china" || echo 0 >"$netconf/is_in_china"
echo "$ethx" >"$netconf/ethx"
# Save the originally passed MAC, might still be useful for logging/debugging
echo "$mac_addr" >"$netconf/mac_addr"
# Save the originally passed static config
echo "$ipv4_addr" >"$netconf/ipv4_addr"
echo "$ipv4_gateway" >"$netconf/ipv4_gateway"
echo "$ipv6_addr" >"$netconf/ipv6_addr"
echo "$ipv6_gateway" >"$netconf/ipv6_gateway"
# Save final connectivity state
$ipv4_has_internet && echo 1 >"$netconf/ipv4_has_internet" || echo 0 >"$netconf/ipv4_has_internet"
$ipv6_has_internet && echo 1 >"$netconf/ipv6_has_internet" || echo 0 >"$netconf/ipv6_has_internet"

echo "Configuration for $ethx completed."
# Final check
ip addr show dev "$ethx"
ip route show dev "$ethx"
cat /etc/resolv.conf
