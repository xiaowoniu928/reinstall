#!/bin/ash
# shellcheck shell=dash
# shellcheck disable=SC2086,SC3047,SC3036,SC3010,SC3001,SC3060
# alpine 默认使用 busybox ash
# 注意 bash 和 ash 以下语句结果不同
# [[ a = '*a' ]] && echo 1

# 出错后停止运行，将进入到登录界面，防止失联
set -eE

# 用于判断 reinstall.sh 和 trans.sh 是否兼容
# shellcheck disable=SC2034
SCRIPT_VERSION=4BACD833-A585-23BA-6CBB-9AA4E08E0003 # Keep version check

TRUE=0
FALSE=1

error() {
    color='\e[31m'
    plain='\e[0m'
    echo -e "${color}***** ERROR *****${plain}" >&2
    echo -e "${color}$*${plain}" >&2
}

info() {
    color='\e[32m'
    plain='\e[0m'
    local msg

    if [ "$1" = false ]; then
        shift
        msg=$*
    else
        msg=$(echo "$*" | to_upper)
    fi

    echo -e "${color}***** $msg *****${plain}" >&2
}

warn() {
    color='\e[33m'
    plain='\e[0m'
    echo -e "${color}Warning: $*${plain}" >&2
}

error_and_exit() {
    error "$@"
    echo "Automatic installation failed." >&2
    # Removed retry instructions as complex install logic is gone.
    exit 1
}

trap_err() {
    line_no=$1
    ret_no=$2

    error_and_exit "$(
        echo "Line $line_no return $ret_no"
        if [ -f "/trans.sh" ]; then
            sed -n "$line_no"p /trans.sh
        fi
    )"
}

is_run_from_locald() {
     # This might still be relevant if run within an Alpine intermediate OS
    [[ "$0" = "/etc/local.d/*" ]]
}

add_community_repo() {
    # Relevant for Alpine intermediate OS
    # 先检查原来的repo是不是egde
    if grep -q '^http.*/edge/main$' /etc/apk/repositories; then
        alpine_ver=edge
    else
        alpine_ver=v$(cut -d. -f1,2 </etc/alpine-release)
    fi

    if ! grep -q "^http.*/$alpine_ver/community$" /etc/apk/repositories; then
        alpine_mirror=$(grep '^http.*/main$' /etc/apk/repositories | sed 's,/[^/]*/main$,,' | head -1)
        echo $alpine_mirror/$alpine_ver/community >>/etc/apk/repositories
    fi
}

# Keep apk() and wget() helpers
apk() {
    retry 5 command apk "$@" >&2
}

wget() {
    echo "$@" | grep -o 'http[^ ]*' >&2
    if command wget 2>&1 | grep -q BusyBox; then
        # busybox wget 没有重试功能
        # 好像默认永不超时
        retry 5 command wget "$@" -T 10
    else
        # 原版 wget 自带重试功能
        command wget --tries=5 --progress=bar:force "$@"
    fi
}

# Keep is_have_cmd() and related helpers
is_have_cmd() {
    # command -v 包括脚本里面的方法
    is_have_cmd_on_disk / "$1"
}

is_have_cmd_on_disk() {
    local os_dir=$1
    local cmd=$2

    for bin_dir in /bin /sbin /usr/bin /usr/sbin; do
        if [ -f "$os_dir$bin_dir/$cmd" ]; then
            return
        fi
    done
    return 1
}

is_num() {
    echo "$1" | grep -Exq '[0-9]*\.?[0-9]*'
}

retry() {
    local max_try=$1
    shift

    if is_num "$1"; then
        local interval=$1
        shift
    else
        local interval=5
    fi

    for i in $(seq $max_try); do
        if "$@"; then
            return
        else
            ret=$?
            if [ $i -ge $max_try ]; then
                return $ret
            fi
            sleep $interval
        fi
    done
}

# Keep basic environment checks
is_efi() {
    # Keep force_boot_mode check
    if [ -n "$force_boot_mode" ]; then
        [ "$force_boot_mode" = efi ]
    else
        [ -d /sys/firmware/efi/ ]
    fi
}

is_use_cloud_image() {
    # Keep as reinstall.sh might pass this
    [ -n "$cloud_image" ] && [ "$cloud_image" = 1 ]
}

is_allow_ping() {
    # Keep as reinstall.sh might pass this
    [ -n "$allow_ping" ] && [ "$allow_ping" = 1 ]
}

# Keep web server setup (for viewing logs during install)
setup_websocketd() {
    apk add websocketd coreutils # coreutils for stdbuf
    # Assume confhome is available from cmdline extract
    wget $confhome/logviewer.html -O /tmp/index.html

    if [ -z "$web_port" ]; then
        web_port=80
    fi

    pkill websocketd || true
    # websocketd 遇到 \n 才推送，因此要转换 \r 为 \n
    websocketd --port "$web_port" --loglevel=fatal --staticdir=/tmp \
        stdbuf -oL -eL sh -c "tail -fn+0 /reinstall.log | tr '\r' '\n'" &
}

get_approximate_ram_size() {
    ram_size=$(free -m | awk '{print $2}' | sed -n '2p')
    echo "$ram_size"
}

setup_web_if_enough_ram() {
    total_ram=$(get_approximate_ram_size)
    # Keep threshold, maybe adjust if needed
    if [ $total_ram -gt 400 ]; then
        setup_websocketd
    fi
}

# Keep get_ttys()
get_ttys() {
    prefix=$1
    # Assume confhome is available
    wget $confhome/ttys.sh -O- | sh -s $prefix
}

# Keep extract_env_from_cmdline()
extract_env_from_cmdline() {
    # 提取 finalos/extra 到变量
    for prefix in finalos extra; do
        while read -r line; do
            if [ -n "$line" ]; then
                key=$(echo $line | cut -d= -f1)
                value=$(echo $line | cut -d= -f2-)
                eval "$key='$value'"
            fi
        done < <(xargs -n1 </proc/cmdline | grep "^${prefix}_" | sed "s/^${prefix}_//")
    done
}

# Keep service helpers (might be needed for intermediate Alpine)
ensure_service_started() {
    service=$1

    if ! rc-service -q $service status; then
        if ! retry 5 rc-service -q $service start; then
            error_and_exit "Failed to start $service."
        fi
    fi
}

ensure_service_stopped() {
    service=$1

    if rc-service -q $service status; then
        if ! retry 5 rc-service -q $service stop; then
            error_and_exit "Failed to stop $service."
        fi
    fi
}

# Keep mod_motd (for intermediate Alpine)
mod_motd() {
    # Always assume it might be Alpine intermediate
    file=/etc/motd
    if ! [ -e $file.orig ]; then
        cp $file $file.orig
        # This setup-disk modification is Alpine specific, remove if not needed
        # shellcheck disable=SC2016
        # echo "mv "\$mnt$file.orig" "\$mnt$file"" |
        #     insert_into_file "$(which setup-disk)" before 'cleanup_chroot_mounts "\$mnt"'

        cat <<EOF >$file
Reinstalling...
To view logs run:
tail -fn+1 /reinstall.log
EOF
    fi
}

# Keep umount_all and clear_previous
umount_all() {
    # Simplified relevant mount points for intermediate OS context
    dirs="/mnt /os /iso /installer /nbd /root"
    regex=$(echo "$dirs" | sed 's, ,|,g')
    if mounts=$(mount | grep -Ew "on $regex" | awk '{print $3}' | tac); then
        for mount in $mounts; do
            echo "umount $mount"
            umount $mount
        done
    fi
}

clear_previous() {
    # Keep LVM, NBD cleanup as the previous system might have used them
    if is_have_cmd vgchange; then
        umount -R /os /nbd || true
        vgchange -an
        apk add device-mapper # Needed for dmsetup
        dmsetup remove_all
    fi
    # Keep disconnect_qcow (although qcow logic removed, cleanup doesn't hurt)
    disconnect_qcow() { :; } # Dummy function as qemu-nbd won't be installed
    # Keep swapoff and umount_all
    swapoff -a
    umount_all
}

# Keep config helpers
get_config() {
    cat "/configs/$1"
}

set_config() {
    printf '%s' "$2" >"/configs/$1"
}

# Keep password/key related helpers
get_password_linux_sha512() {
    get_config password-linux-sha512
}

is_need_set_ssh_keys() {
    [ -s /configs/ssh_keys ]
}

is_need_change_ssh_port() {
    [ -n "$ssh_port" ] && ! [ "$ssh_port" = 22 ]
}

# Keep network detection helpers
show_netconf() {
    grep -r . /dev/netconf/
}

get_ra_to() {
    # Keep as networking logic needs it
     if [ -z "$_ra" ]; then
        apk add ndisc6
        echo "Gathering network info..."
        # shellcheck disable=SC2154
        _ra="$(rdisc6 -1 "$ethx")"
        apk del ndisc6

        info "Network info:"
        echo
        echo "$_ra" | cat -n
        echo
        ip addr | cat -n
        echo
        show_netconf | cat -n
        echo
    fi
    eval "$1='$_ra'"
}

get_netconf_to() {
    # Keep as networking logic needs it
    case "$1" in
    slaac | dhcpv6 | rdnss | other) get_ra_to ra ;;
    esac

    # shellcheck disable=SC2154
    case "$1" in
    slaac) echo "$ra" | grep 'Autonomous address conf' | grep -q Yes && res=1 || res=0 ;;
    dhcpv6) echo "$ra" | grep 'Stateful address conf' | grep -q Yes && res=1 || res=0 ;;
    rdnss) res=$(echo "$ra" | grep 'Recursive DNS server' | cut -d: -f2-) ;;
    other) echo "$ra" | grep 'Stateful other conf' | grep -q Yes && res=1 || res=0 ;;
    *) res=$(cat /dev/netconf/$ethx/$1) ;;
    esac

    eval "$1='$res'"
}

# Keep all is_* network helpers (is_dhcpv4, is_staticv4, is_slaac, etc.)
is_any_ipv4_has_internet() {
    grep -q 1 /dev/netconf/*/ipv4_has_internet
}

is_in_china() {
    grep -q 1 /dev/netconf/*/is_in_china
}

is_dhcpv4() {
    if ! is_ipv4_has_internet || should_disable_dhcpv4; then
        return 1
    fi
    get_netconf_to dhcpv4
    # shellcheck disable=SC2154
    [ "$dhcpv4" = 1 ]
}

is_staticv4() {
    if ! is_ipv4_has_internet; then
        return 1
    fi
    if ! is_dhcpv4; then
        get_netconf_to ipv4_addr
        get_netconf_to ipv4_gateway
        if [ -n "$ipv4_addr" ] && [ -n "$ipv4_gateway" ]; then
            return 0
        fi
    fi
    return 1
}

is_staticv6() {
    if ! is_ipv6_has_internet; then
        return 1
    fi
    if ! is_slaac && ! is_dhcpv6; then
        get_netconf_to ipv6_addr
        get_netconf_to ipv6_gateway
        if [ -n "$ipv6_addr" ] && [ -n "$ipv6_gateway" ]; then
            return 0
        fi
    fi
    return 1
}

is_dhcpv6_or_slaac() {
    get_netconf_to dhcpv6_or_slaac
    # shellcheck disable=SC2154
    [ "$dhcpv6_or_slaac" = 1 ]
}

is_ipv4_has_internet() {
    get_netconf_to ipv4_has_internet
    # shellcheck disable=SC2154
    [ "$ipv4_has_internet" = 1 ]
}

is_ipv6_has_internet() {
    get_netconf_to ipv6_has_internet
    # shellcheck disable=SC2154
    [ "$ipv6_has_internet" = 1 ]
}

should_disable_dhcpv4() {
    get_netconf_to should_disable_dhcpv4
    # shellcheck disable=SC2154
    [ "$should_disable_dhcpv4" = 1 ]
}

should_disable_accept_ra() {
    get_netconf_to should_disable_accept_ra
    # shellcheck disable=SC2154
    [ "$should_disable_accept_ra" = 1 ]
}

should_disable_autoconf() {
    get_netconf_to should_disable_autoconf
    # shellcheck disable=SC2154
    [ "$should_disable_autoconf" = 1 ]
}

is_slaac() {
    if ! is_ipv6_has_internet || ! is_dhcpv6_or_slaac || should_disable_accept_ra || should_disable_autoconf; then
        return 1
    fi
    get_netconf_to slaac
    # shellcheck disable=SC2154
    [ "$slaac" = 1 ]
}

is_dhcpv6() {
    if ! is_ipv6_has_internet || ! is_dhcpv6_or_slaac || should_disable_accept_ra || should_disable_autoconf; then
        return 1
    fi
    get_netconf_to dhcpv6
    # shellcheck disable=SC2154
    if [ "$dhcpv6" = 1 ] && ! ip -6 -o addr show scope global dev "$ethx" | grep -q .; then
        echo 'DHCPv6 flag is on, but DHCPv6 is not working.'
        return 1
    fi
    [ "$dhcpv6" = 1 ]
}

is_have_ipv6() {
    is_slaac || is_dhcpv6 || is_staticv6
}

is_enable_other_flag() {
    get_netconf_to other
    # shellcheck disable=SC2154
    [ "$other" = 1 ]
}

is_have_rdnss() {
    get_netconf_to rdnss
    [ -n "$rdnss" ]
}

is_elts() {
    # Keep as reinstall.sh might pass this
    [ -n "$elts" ] && [ "$elts" = 1 ]
}

is_need_manual_set_dnsv6() {
    # Keep for network config generation
    ! is_have_ipv6 && return $FALSE
    is_dhcpv6 && return $FALSE
    is_staticv6 && return $TRUE
    # Simplified: Assume if SLAAC, we don't manually set DNS unless other flags are off and no RDNSS
    is_slaac && ! is_enable_other_flag && ! is_have_rdnss
}

get_current_dns() {
    # Keep for network config generation
    mark=$(
        case "$1" in
        4) echo . ;;
        6) echo : ;;
        esac
    )
    grep '^nameserver' /etc/resolv.conf | cut -d' ' -f2 | grep -F "$mark" | cut -d '%' -f1
}

# Keep string manipulation helpers
to_upper() { tr '[:lower:]' '[:upper:]'; }
to_lower() { tr '[:upper:]' '[:lower:]'; }
del_cr() { sed 's/\r$//'; }
del_comment_lines() { sed '/^[[:space:]]*#/d'; }
del_empty_lines() { sed '/^[[:space:]]*$/d'; }
trim() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

# Keep insert_into_file helper
insert_into_file() {
    file=$1
    location=$2
    regex_to_find=$3
    shift 3

    # 默认 grep -E
    if [ $# -eq 0 ]; then
        set -- -E
    fi

    if [ "$location" = head ]; then
        bak=$(mktemp)
        cp $file $bak
        cat - $bak >$file
    else
        line_num=$(grep "$@" -n "$regex_to_find" "$file" | cut -d: -f1)
        found_count=$(echo "$line_num" | wc -l)
        if [ ! "$found_count" -eq 1 ]; then return 1; fi
        case "$location" in before) line_num=$((line_num - 1)) ;; after) ;; *) return 1 ;; esac
        sed -i "${line_num}r /dev/stdin" "$file"
    fi
}

# Keep get_eths() helper
get_eths() { ( cd /dev/netconf; ls ); }

# Keep is_distro_like_debian() helper
is_distro_like_debian() {
    [ "$distro" = debian ] # Removed Kali
}

# Keep create_ifupdown_config() - CRITICAL for Debian installer patch
create_ifupdown_config() {
    conf_file=$1
    rm -f $conf_file

    # Only keep Debian specific part
    if is_distro_like_debian; then
        cat <<EOF >>$conf_file
source /etc/network/interfaces.d/*

EOF
    fi

    cat <<EOF >>$conf_file
auto lo
iface lo inet loopback
EOF

    for ethx in $(get_eths); do
        mode=auto
        get_netconf_to mac_addr
        {
            echo
            # shellcheck disable=SC2154
            echo "# mac $mac_addr"
            echo $mode $ethx
        } >>$conf_file

        # ipv4
        if is_dhcpv4; then
            echo "iface $ethx inet dhcp" >>$conf_file
        elif is_staticv4; then
            get_netconf_to ipv4_addr
            get_netconf_to ipv4_gateway
            cat <<EOF >>$conf_file
iface $ethx inet static
    address $ipv4_addr
    gateway $ipv4_gateway
EOF
            if list=$(get_current_dns 4); then
                for dns in $list; do echo "    dns-nameservers $dns" >>$conf_file; done
            fi
        fi

        # ipv6
        if is_slaac; then
            echo "iface $ethx inet6 auto" >>$conf_file
        elif is_dhcpv6; then
            # Simplify: assume 'auto' works generally for newer Debians
             echo "iface $ethx inet6 auto" >>$conf_file
        elif is_staticv6; then
            get_netconf_to ipv6_addr
            get_netconf_to ipv6_gateway
            cat <<EOF >>$conf_file
iface $ethx inet6 static
    address $ipv6_addr
    gateway $ipv6_gateway
EOF
            # Keep Debian 9 static gateway fix
            # shellcheck disable=SC2154
            if [ "$distro" = debian ] && [ "$releasever" -le 9 ]; then
                sed -Ei '$s/^( *)/\1# /' "$conf_file"
                cat <<EOF >>$conf_file
    post-up ip route add $ipv6_gateway dev $ethx
    post-up ip route add default via $ipv6_gateway dev $ethx
EOF
            fi
        fi

        # dns for ipv6
        if is_need_manual_set_dnsv6; then
            for dns in $(get_current_dns 6); do echo "    dns-nameserver $dns" >>$conf_file; done
        fi

        # Keep disable ra/autoconf logic
        if should_disable_accept_ra; then
           # Simplified: assume Debian style works
           echo "    accept_ra 0" >>$conf_file
        fi
        if should_disable_autoconf; then
            # Simplified: assume Debian style works
            echo "    autoconf 0" >>$conf_file
        fi
    done
}


# Keep SSH key/password helpers needed for initrd setup
set_ssh_keys_and_del_password() {
    os_dir=$1 # Should be '/' in initrd context
    info 'set ssh keys'
    ( umask 077; mkdir -p $os_dir/root/.ssh; cat /configs/ssh_keys >$os_dir/root/.ssh/authorized_keys )
    # passwd might not exist in minimal initrd, but doesn't hurt to try
    chroot $os_dir passwd -d root || true
}

change_root_password() {
    os_dir=$1 # Should be '/' in initrd context
    info 'change root password'
    # Simplified: always use encrypted password from configs
    echo "root:$(get_password_linux_sha512)" | chroot $os_dir chpasswd -e || \
    echo "root:$(get_password_linux_sha512)" | chpasswd -e # Fallback if chroot fails/not needed
}

change_ssh_conf() {
    # Keep for initrd SSH setup
    os_dir=$1; key=$2; value=$3; sub_conf=$4
    # Simplified: assume sshd_config exists at /etc/ssh/sshd_config
    # and always append/replace there. Subdirs might not exist in initrd.
    line="^#?$key .*"
    if grep -Exq "$line" $os_dir/etc/ssh/sshd_config 2>/dev/null ; then
        sed -Ei "s/$line/$key $value/" $os_dir/etc/ssh/sshd_config
    else
        # Ensure sshd_config exists before appending
        mkdir -p "$(dirname "$os_dir/etc/ssh/sshd_config")"
        touch "$os_dir/etc/ssh/sshd_config"
        echo "$key $value" >> $os_dir/etc/ssh/sshd_config
    fi
}
allow_password_login() { change_ssh_conf "$1" PasswordAuthentication yes 01-PasswordAuthentication.conf; }
allow_root_password_login() { change_ssh_conf "$1" PermitRootLogin yes 01-permitrootlogin.conf; }
change_ssh_port() { change_ssh_conf "$1" Port "$2" 01-change-ssh-port.conf; }

# Keep sync_time
sync_time() {
    # http method seems safer in initrd
    method=http
    case "$method" in
    http)
        # Try apk repo first, fallback to a known site if needed
        url=$(grep -m1 ^http /etc/apk/repositories 2>/dev/null)/$(uname -m)/APKINDEX.tar.gz || url="http://detectportal.firefox.com/success.txt"
        date_header=$(wget -S --no-check-certificate --spider "$url" 2>&1 | grep -m1 '^ *Date:')
        if [ -n "$date_header" ]; then
            # Need busybox date format
            # Extract date string after "Date: "
            date_str=$(echo "$date_header" | sed 's/^ *Date: //')
            # Attempt to set date, allow failure
            busybox date -u -D "%a, %d %b %Y %H:%M:%S GMT" -s "$date_str" || warn "Failed to set date from HTTP header: $date_str"

        else
            warn "Could not get date from HTTP header."
            return 1
        fi
        ;;
    esac
}

# --- Main trans() function ---
trans() {
    info "start trans (Debian Focused)"

    # Keep mod_motd for potential Alpine intermediate case
    mod_motd

    # Keep initial cleanup and checks
    cat /proc/cmdline
    clear_previous
    add_community_repo # Needed for Alpine intermediate

    # Keep web server setup for logs
    setup_web_if_enough_ram

    # --- REMOVED OS INSTALLATION/MODIFICATION LOGIC ---
    info "Setup complete for Debian installer or intermediate OS."
    info "Waiting for installer process or manual intervention if needed."
    # The script might exit here if patched by reinstall.sh,
    # or it might continue to hold state if run manually or as intermediate OS.
}

# --- Script Entry Point ---
# Keep the ': main' label for Debian initrd patch compatibility
: main

# Keep script self-copy
if ! [ "$(readlink -f "$0")" = /trans.sh ]; then
    cp -f "$0" /trans.sh
fi
trap 'trap_err $LINENO $?' ERR

# Keep self-removal logic (relevant in Alpine intermediate OS)
rm -f /etc/local.d/trans.start
rm -f /etc/runlevels/default/local

# Keep variable extraction
extract_env_from_cmdline

# Keep parameter handling (update, but remove 'alpine' target)
if [ "$1" = "update" ]; then
    info 'update script'
    # shellcheck disable=SC2154
    wget -O /trans.sh "$confhome/trans.sh"
    chmod +x /trans.sh
    exec /trans.sh
elif [ -n "$1" ]; then
    # Removed 'alpine' case
    error_and_exit "unknown option $1"
fi

# Keep initrd/intermediate OS setup steps
mount / -o remount,size=100%
sync_time || true # Allow failure

apk add openssh # Essential for remote access
if is_need_change_ssh_port; then change_ssh_port / $ssh_port; fi

# Setup SSH keys or password for the initrd/intermediate OS environment
if is_need_set_ssh_keys; then
    set_ssh_keys_and_del_password /
    # setup-sshd might not exist in Debian initrd, check and run if exists
    is_have_cmd setup-sshd && printf '\n' | setup-sshd
else
    change_root_password /
    is_have_cmd setup-sshd && printf '\nyes' | setup-sshd
fi
# Always allow root login in this temporary environment
allow_root_password_login /
allow_password_login /
# Restart sshd if possible
rc-service sshd restart || service ssh restart || true


# Remove FRPC setup from initrd context
# if [ -s /configs/frpc.toml ] && ! pidof frpc >/dev/null; then ... fi

# Keep hold logic
# shellcheck disable=SC2154
if [ "$hold" = 1 ]; then
    if is_run_from_locald; then info "hold"; exit; fi
fi

# Keep log redirection and call trans()
# shellcheck disable=SC2046
exec > >(exec tee $(get_ttys /dev/) /reinstall.log) 2>&1
trans

# Keep hold logic
if [ "$hold" = 2 ]; then info "hold 2"; exit; fi

# Keep final reboot (relevant for intermediate OS)
sync
reboot
