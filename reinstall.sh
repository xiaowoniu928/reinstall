#!/usr/bin/env bash
# shellcheck disable=SC2086

# --- CONFIGURATION ---
# URL pointing to the directory containing trans.sh and helper scripts
confhome=https://raw.githubusercontent.com/imengying/reinstall/main # <-- 修改为你托管脚本的 URL

# --- Essential Variables ---
DEFAULT_PASSWORD=123@@@
SCRIPT_VERSION=4BACDD33-A585-23BA-6CBB-9AA4E08E0003 # <-- 自定义一个版本号，确保和精简版 trans.sh 一致
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
exec > >(tee >(grep -iv password >>/reinstall.log)) 2>&1
THIS_SCRIPT=$(readlink -f "$0")
trap 'trap_err $LINENO $?' ERR
tmp=/reinstall-tmp # Temporary directory

# --- Logging and Error Handling ---
trap_err() {
    line_no=$1; ret_no=$2
    error "Line $line_no return $ret_no"
    sed -n "$line_no"p "$THIS_SCRIPT"
}
echo_color_text() { color="$1"; shift; plain="\e[0m"; echo -e "$color$*$plain"; }
info() { msg="***** $(to_upper <<<"$*") *****"; echo_color_text '\e[32m' "$msg" >&2; }
warn() { msg="Warning: $*"; echo_color_text '\e[33m' "$msg" >&2; }
error() { echo_color_text '\e[31m' "***** ERROR *****" >&2; echo_color_text '\e[31m' "$*" >&2; }
error_and_exit() { error "$@"; exit 1; }
to_upper() { tr '[:lower:]' '[:upper:]'; }
to_lower() { tr '[:upper:]' '[:lower:]'; }
del_cr() { sed -E 's/\r+$//'; }
is_digit() { [[ "$1" =~ ^[0-9]+$ ]]; }
is_port_valid() { is_digit "$1" && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
get_function() { declare -f "$1"; }
get_function_content() { declare -f "$1" | sed '1d;2d;$d'; }
insert_into_file() {
    file=$1; location=$2; regex_to_find=$3
    line_num=$(grep -E -n "$regex_to_find" "$file" | cut -d: -f1)
    found_count=$(echo "$line_num" | wc -l); [ "$found_count" -eq 1 ] || return 1
    case "$location" in before) line_num=$((line_num - 1)) ;; after) ;; *) return 1 ;; esac
    sed -i "${line_num}r /dev/stdin" "$file"
}
mkdir_clear() { dir=$1; [ -z "$dir" ] || [ "$dir" = / ] && return; rm -rf $dir; mkdir -p $dir; }
is_efi() { [ -d /sys/firmware/efi ]; }
get_maybe_efi_dirs_in_linux() { mount | awk '$5=="vfat" || $5=="autofs" {print $3}' | grep -E '/boot|/efi' | sort -u; }
get_disk_by_part() { dev_part=$1; install_pkg lsblk >&2; lsblk -rn --inverse "$dev_part" | grep -w disk | awk '{print $1}'; }
get_part_num_by_part() { dev_part=$1; grep -oE '[0-9]*$' <<<"$dev_part"; }
grep_efi_entry() { grep -E '^Boot[0-9a-fA-F]{4}'; }
grep_efi_index() { awk '{print $1}' | sed -e 's/Boot//' -e 's/\*//'; }
get_entry_name() { printf 'reinstall (DD Debian)'; }
get_grub_efi_filename() { case "$basearch" in x86_64) echo grubx64.efi ;; aarch64) echo grubaa64.efi ;; esac; }

# --- Utility Functions ---
is_have_cmd() { type -f -p "$1" >/dev/null 2>&1; }
curl() {
    is_have_cmd curl || install_pkg curl
    grep -o 'http[^ ]*' <<<"$@" >&2
    for i in $(seq 5); do
        if command curl --insecure --connect-timeout 10 -f "$@"; then return; else
            ret=$?; [ $ret -eq 22 ] || [ $i -eq 5 ] && return $ret; sleep 1; fi
    done
}
is_in_china() {
    [ "$force_cn" = 1 ] && return 0
    if [ -z "$_loc" ]; then
        if ! _loc=$(curl -Ls http://www.qualcomm.cn/cdn-cgi/trace | grep '^loc=' | cut -d= -f2 | grep .); then
            warn "Could not determine location, assuming not in China."
            _loc="N/A" # Set to non-CN value
            return 1
        fi
        echo "Location: $_loc" >&2
    fi
    [ "$_loc" = CN ]
}
install_pkg() {
    find_pkg_mgr() {
        [ -n "$pkg_mgr" ] && return
        for mgr in apt-get yum dnf apk; do is_have_cmd $mgr && pkg_mgr=$mgr && return; done; return 1
    }
    cmd_to_pkg() {
        case $cmd in
        xz) pkg="xz-utils" ;; # Debian/Ubuntu specific
        lsblk | findmnt) pkg="util-linux" ;;
        fdisk) pkg="fdisk" ;; # Debian/Ubuntu specific, others use util-linux
        efibootmgr) pkg="efibootmgr" ;;
        parted) pkg="parted" ;;
        gzip) pkg="gzip" ;;
        cpio) pkg="cpio" ;;
        tar) pkg="tar" ;;
        wget) pkg="wget" ;;
        *) pkg=$cmd ;;
        esac
    }
    install_pkg_real() {
        local text="$pkg"; [ "$pkg" != "$cmd" ] && text+=" ($cmd)"
        echo "Installing package '$text'..." >&2
        case $pkg_mgr in
        dnf|yum) $pkg_mgr install -y $pkg ;;
        apt-get) [ -z "$apt_updated" ] && apt-get update && apt_updated=1; DEBIAN_FRONTEND=noninteractive apt-get install -y $pkg ;;
        apk) apk add $pkg ;;
        *) error_and_exit "Unsupported package manager: $pkg_mgr" ;;
        esac
    }
    for cmd in "$@"; do
        if ! is_have_cmd "$cmd"; then
            find_pkg_mgr || error_and_exit "Can't find package manager to install $cmd."
            cmd_to_pkg; install_pkg_real
        fi
    done
}

# --- Network Configuration ---
collect_netconf() {
    for v in 4 6; do
        if via_gateway_dev_ethx=$(ip -$v route show default | grep -Ewo 'via [^ ]+ dev [^ ]+' | head -1 | grep .); then
            read -r _ gateway _ ethx <<<"$via_gateway_dev_ethx"
            eval ipv${v}_ethx="$ethx"
            eval ipv${v}_mac="$(ip link show dev $ethx | grep link/ether | head -1 | awk '{print $2}')"
            eval ipv${v}_gateway="$gateway"
            eval ipv${v}_addr="$(ip -$v -o addr show scope global dev $ethx | grep -v temporary | head -1 | awk '{print $4}')"
        fi
    done
    if [ -z "$ipv4_mac" ] && [ -z "$ipv6_mac" ]; then error_and_exit "Can not get IP info."; fi
    info "Network Info Found"
}
get_ip_conf_cmd() {
    collect_netconf >&2
    is_in_china && is_in_china_flag=true || is_in_china_flag=false
    sh=/initrd-network.sh
    cmd_list=()
    if [ -n "$ipv4_mac" ]; then
        cmd_list+=("'$sh' '$ipv4_mac' '$ipv4_addr' '$ipv4_gateway' '' '' '$is_in_china_flag'")
    fi
    if [ -n "$ipv6_mac" ] && { [ -z "$ipv4_mac" ] || [ "$ipv4_mac" != "$ipv6_mac" ]; }; then
         cmd_list+=("'$sh' '$ipv6_mac' '' '' '$ipv6_addr' '$ipv6_gateway' '$is_in_china_flag'")
    elif [ -n "$ipv6_mac" ] && [ "$ipv4_mac" == "$ipv6_mac" ]; then
        cmd_list[0]="'$sh' '$ipv4_mac' '$ipv4_addr' '$ipv4_gateway' '$ipv6_addr' '$ipv6_gateway' '$is_in_china_flag'"
    fi
    printf '%s\n' "${cmd_list[@]}"
}

# --- Disk Detection ---
find_main_disk() {
    if [ -n "$main_disk" ]; then return; fi
    install_pkg lsblk fdisk
    # Use heuristic: find disk containing root '/' or '/boot'
    mapper=$(mount | awk '$3=="/boot" {print $1}' | grep '^/dev/' | head -n 1 || mount | awk '$3=="/" {print $1}' | grep '^/dev/' | head -n 1)
    [ -z "$mapper" ] && error_and_exit "Could not determine device for / or /boot."
    xda=$(lsblk -rnpo NAME "$mapper" | head -n 1 | sed 's/[0-9]*$//; s/p[0-9]*$//') # More robustly find the base disk name
    [ -z "$xda" ] && error_and_exit "Could not determine disk name from $mapper."
    xda_base=$(basename "$xda") # Get sda, vda etc.

    info "Main disk identified as device containing '$mapper': /dev/$xda_base"
    # Get Disk Identifier using fdisk
    main_disk_id=$(fdisk -l "/dev/$xda_base" 2>/dev/null | grep 'Disk identifier' | awk '{print $NF}' | sed 's/0x//')
    if ! grep -Eiq '[0-9a-f]{8}|[0-9a-f-]{36}' <<<"$main_disk_id"; then
        warn "Could not reliably get Disk Identifier for /dev/$xda_base using fdisk. Using device name '$xda_base' as fallback ID for initrd."
        main_disk_id="$xda_base" # Fallback to device name if ID is weird/missing
    fi
    main_disk="$main_disk_id" # Set the global variable
    xda="$xda_base" # Set global xda
}

# --- Password Handling ---
prompt_password() { info "Prompting for password"; while true; do IFS= read -r -s -p "Enter password for initrd SSH [$DEFAULT_PASSWORD]: " password; echo; IFS= read -r -s -p "Retype password: " password_confirm; echo; password=${password:-$DEFAULT_PASSWORD}; password_confirm=${password_confirm:-$DEFAULT_PASSWORD}; if [ -z "$password" ]; then error "Password is empty."; elif [ "$password" != "$password_confirm" ]; then error "Passwords don't match."; else break; fi; done; }
save_password() {
    dir=$1; info "Saving password hash to $dir"
    printf '%s' "$password" >"$dir/password-plaintext" # Keep plaintext for initrd SSH/final system if needed
    if install_pkg openssl && openssl passwd --help 2>&1 | grep -wq '\-6'; then
        crypted=$(printf '%s' "$password" | openssl passwd -6 -stdin)
    elif install_pkg whois && is_have_cmd mkpasswd && mkpasswd -m help | grep -wq sha-512; then
         crypted=$(printf '%s' "$password" | mkpasswd -m sha-512 --stdin)
    else warn "Could not generate sha512 hash, password may not be set correctly in final system."; crypted=""; fi # Add warning
    [ -n "$crypted" ] && echo "$crypted" >"$dir/password-linux-sha512" || touch "$dir/password-linux-sha512" # Create empty file if failed
}

# --- Initrd Modification ---
mod_initrd_alpine() {
    # Hack 1: Ensure ipv6 module is present (Simplified check)
    if ! ls $initrd_dir/lib/modules/*/kernel/net/ipv6/ipv6.ko* > /dev/null 2>&1 && \
       ! grep -q 'kernel/net/ipv6/ipv6.ko' $initrd_dir/lib/modules/*/modules.builtin 2>/dev/null; then
        warn "ipv6 module might be missing in initrd, network issues may occur."
    fi

    # Hack 2: Insert network configuration call
    insert_into_file init after 'configure_ip\(\)' <<EOF
        depmod >/dev/null 2>&1 || true # Run depmod, ignore errors if modules are missing
        [ -d /sys/module/ipv6 ] || modprobe ipv6 || echo 'Failed to load ipv6 module' >&2
        # Execute network setup script(s) generated by get_ip_conf_cmd
        $(get_ip_conf_cmd)
        MAC_ADDRESS=1 # Mark network as configured for Alpine's init logic
        return
EOF

    # Hack 3: Run trans.sh before switch_root
    insert_into_file init before '^exec (/bin/busybox )?switch_root' <<EOF
        echo "Copying DD script and configs..." >&2
        cp /trans.sh \$sysroot/trans.sh
        chmod a+x \$sysroot/trans.sh
        # Set up local.d to run the script on boot
        mkdir -p \$sysroot/etc/local.d/
        ln -s /trans.sh \$sysroot/etc/local.d/00-reinstall-dd.start
        # Ensure local service is enabled
        mkdir -p \$sysroot/etc/runlevels/default/
        ln -sf /etc/init.d/local \$sysroot/etc/runlevels/default/local

        # Copy configs (password, keys)
        if [ -d /configs ]; then cp -r /configs \$sysroot/; fi

        # Copy essential helper scripts needed by trans.sh
        cp /initrd-network.sh \$sysroot/initrd-network.sh
        cp /get-xda.sh \$sysroot/get-xda.sh
        cp /ttys.sh \$sysroot/ttys.sh
        cp /fix-eth-name.sh \$sysroot/fix-eth-name.sh
        cp /fix-eth-name.service \$sysroot/fix-eth-name.service
        chmod a+x \$sysroot/initrd-network.sh \$sysroot/get-xda.sh \$sysroot/ttys.sh \$sysroot/fix-eth-name.sh

        echo "Alpine initrd modification complete." >&2
EOF
}

mod_initrd() {
    info "Modifying Alpine initrd for DD"
    install_pkg gzip cpio tar xz wget # wget needed for trans.sh (apk add in initrd)
    # Required tools within initrd for DD and resize
    install_pkg e2fsprogs parted util-linux # for resize/partitioning, blkid, blockdev
    # Add other filesystem tools if the target image might use them
    # install_pkg xfsprogs # Example for XFS
    # install_pkg btrfs-progs # Example for Btrfs

    initrd_dir=$tmp/initrd
    mkdir_clear $initrd_dir
    cd $initrd_dir

    info "Unpacking initrd..."
    # Handle potential cpio errors on specific platforms like Cygwin if needed
    if ! zcat /reinstall-initrd | cpio -idm; then
        warn "cpio extracted initrd with errors. Continuing, but initrd might be corrupted."
    fi

    # Fetch the streamlined DD trans script and helpers
    info "Downloading trans.sh and helper scripts..."
    curl -Lo $initrd_dir/trans.sh $confhome/trans.sh
    curl -Lo $initrd_dir/initrd-network.sh $confhome/initrd-network.sh
    curl -Lo $initrd_dir/get-xda.sh $confhome/get-xda.sh
    curl -Lo $initrd_dir/ttys.sh $confhome/ttys.sh
    curl -Lo $initrd_dir/fix-eth-name.sh $confhome/fix-eth-name.sh
    curl -Lo $initrd_dir/fix-eth-name.service $confhome/fix-eth-name.service

    # Verify trans.sh version
    if ! grep -q "$SCRIPT_VERSION" $initrd_dir/trans.sh; then
        error_and_exit "trans.sh version mismatch ($SCRIPT_VERSION expected). Update scripts."
    fi
    chmod a+x $initrd_dir/trans.sh $initrd_dir/initrd-network.sh \
              $initrd_dir/get-xda.sh $initrd_dir/ttys.sh $initrd_dir/fix-eth-name.sh

    # Save password/keys into initrd
    mkdir -p $initrd_dir/configs
    if [ -n "$ssh_keys" ]; then
        info "Saving SSH key to initrd"
        echo "$ssh_keys" >$initrd_dir/configs/ssh_keys # Use echo instead of cat <<<
    else
        save_password $initrd_dir/configs
    fi

    # Apply Alpine-specific init script modifications
    mod_initrd_alpine

    info "Repacking initrd..."
    # Use higher compression, handle potential cpio ownership/permission warnings
    if ! find . | cpio --quiet -o -H newc | gzip -9 > /reinstall-initrd; then
        error_and_exit "Failed to repack initrd."
    fi
    cd - >/dev/null
    info "Initrd modification complete."
}


# --- Bootloader Configuration ---
add_efi_entry_in_linux() {
    source=$1; install_pkg efibootmgr findmnt
    for efi_part in $(get_maybe_efi_dirs_in_linux); do
        if find "$efi_part" -maxdepth 3 -iname "*.efi" >/dev/null 2>&1; then # Limit depth for speed
            dist_dir=$efi_part/EFI/reinstall; basename=$(basename "$source"); mkdir -p "$dist_dir"
            info "Copying $basename to $dist_dir"
            if [[ "$source" = http* ]]; then curl -Lo "$dist_dir/$basename" "$source"; else cp -f "$source" "$dist_dir/$basename"; fi
            # Ensure file was copied
            [ -f "$dist_dir/$basename" ] || { warn "Failed to copy $basename to $dist_dir"; continue; }

            dev_part=$(findmnt -T "$dist_dir" -no SOURCE | grep '^/dev/' | head -n 1)
            [ -z "$dev_part" ] && { warn "Could not find device for EFI directory $efi_part"; continue; }
            disk_dev="/dev/$(get_disk_by_part "$dev_part")"
            part_num=$(get_part_num_by_part "$dev_part")
            loader_path="\\EFI\\reinstall\\$basename"
            entry_label="$(get_entry_name)"

            info "Creating EFI boot entry: Disk=$disk_dev Part=$part_num Label='$entry_label' Loader=$loader_path"
            if id=$(efibootmgr --create-only --disk "$disk_dev" --part "$part_num" --label "$entry_label" --loader "$loader_path" 2>/dev/null | grep_efi_entry | tail -1 | grep_efi_index); then
                 info "Created EFI entry $id. Setting as next boot."
                 efibootmgr --bootnext "$id"
                 efibootmgr -v # Show current entries
                 return 0 # Success
            else warn "efibootmgr failed to create entry for $efi_part. Trying next."; fi
        fi
    done; error_and_exit "Can't find a suitable EFI partition or efibootmgr failed."
}
install_grub_linux_efi() {
    info 'Download and install temporary GRUB EFI'
    grub_efi=$(get_grub_efi_filename)
    # Using a known reliable source (like Fedora) for the temporary GRUB
    fedora_ver=39 # Or fetch latest dynamically if needed
    is_in_china && mirror=https://mirror.nju.edu.cn/fedora || mirror=https://dl.fedoraproject.org/pub/fedora/linux # Use HTTPS for dl.fedoraproject
    efi_url="$mirror/releases/$fedora_ver/Everything/$basearch/os/EFI/BOOT/$grub_efi"
    info "Downloading GRUB EFI from $efi_url"
    if curl -fLo "$tmp/$grub_efi" "$efi_url"; then
        add_efi_entry_in_linux "$tmp/$grub_efi"
    else error_and_exit "Failed to download GRUB EFI from $efi_url"; fi
}
build_cmdline() {
    info "Building kernel command line"
    find_main_disk # Ensure main_disk and xda are identified
    # 1. Base command line for Alpine initrd
    # shellcheck disable=SC2154
    nextos_cmdline="alpine_repo=$nextos_repo modloop=$nextos_modloop modules=sd-mod,usb-storage,${disk_driver_modules},${net_driver_modules} quiet" # Add essential modules, keep it quiet
    nextos_cmdline+=" $(curl -Ls $confhome/ttys.sh | sh -s "console=")" # Get TTYs
    nextos_cmdline+=" ip=dhcp" # Basic network config for initrd

    # 2. Add parameters for trans.sh (passed via extra_*)
    extra_cmdline=" extra_img='$debian_img_url'" # Pass the DD image URL (ensure quoting)
    extra_cmdline+=" extra_main_disk=$main_disk" # Pass the target disk ID
    extra_cmdline+=" extra_xda=$xda" # Pass the target disk device name
    extra_cmdline+=" extra_confhome=$confhome" # Pass confhome URL
    [ -n "$ssh_port" ] && extra_cmdline+=" extra_ssh_port=$ssh_port"
    [ "$hold" = 1 ] && extra_cmdline+=" extra_hold=1" # Pass hold flag for initrd debugging
    [ "$hold" = 2 ] && extra_cmdline+=" extra_hold=2" # Pass hold flag for post-DD debugging
    [ "$force_cn" = 1 ] && extra_cmdline+=" extra_force_cn=1" # Pass CN flag

    # Combine
    cmdline="$nextos_cmdline $extra_cmdline"
    info "Kernel cmdline: $cmdline"
}
setup_bootloader() {
    build_cmdline # Generate the kernel command line
    # Copy kernel/initrd to a standard location accessible by bootloader
    cp -f /reinstall-vmlinuz /boot/reinstall-vmlinuz || cp -f /reinstall-vmlinuz /reinstall-vmlinuz # Try /boot first, then /
    cp -f /reinstall-initrd /boot/reinstall-initrd || cp -f /reinstall-initrd /reinstall-initrd
    vmlinuz_path=$(find /boot / -maxdepth 1 -name reinstall-vmlinuz)
    initrd_path=$(find /boot / -maxdepth 1 -name reinstall-initrd)
    [ -z "$vmlinuz_path" ] || [ -z "$initrd_path" ] && error_and_exit "Failed to copy kernel/initrd to /boot or /"

    if is_efi; then
        # Use downloaded temporary GRUB EFI
        install_grub_linux_efi
        # shellcheck disable=SC2046
        efi_reinstall_dir=$(find $(get_maybe_efi_dirs_in_linux) -type d -name "reinstall" -print -quit) # Find the first one
        [ -z "$efi_reinstall_dir" ] && error_and_exit "Could not find EFI reinstall directory after setup."
        target_cfg=$efi_reinstall_dir/grub.cfg
        linux_cmd="linux"; initrd_cmd="initrd" # GRUB EFI uses linux/initrd
        # Paths relative to EFI root are tricky, use search --file
        vmlinuz_search_arg="/reinstall-vmlinuz" # Path relative to the root of the filesystem where vmlinuz is
        initrd_search_arg="/reinstall-initrd"
    else
        # BIOS - Assume GRUB is installed and working
        install_pkg grub # Ensure grub commands
        grub=grub; is_have_cmd grub2-mkconfig && grub=grub2
        grub_mkconfig_cmd="$grub-mkconfig"
        grub_reboot_cmd="$grub-reboot"
        is_have_cmd "$grub_mkconfig_cmd" || error_and_exit "$grub_mkconfig_cmd not found"

        # Find existing config (heuristic)
        grub_cfg_path=$($grub_mkconfig_cmd -o /dev/null 2>&1 | grep -o '/[^ ]*grub\.cfg' | head -n 1 || echo "/boot/grub/grub.cfg")
        target_cfg=$(dirname "$grub_cfg_path")/custom.cfg # Add to custom.cfg for safety
        linux_cmd="linux"; initrd_cmd="initrd" # GRUB BIOS uses linux/initrd
        vmlinuz_search_arg="$vmlinuz_path" # Use absolute path found earlier
        initrd_search_arg="$initrd_path"

        # Set next boot entry
        if ! "$grub_reboot_cmd" "$(get_entry_name)"; then
             warn "grub-reboot failed, try manually selecting entry '$(get_entry_name)' at boot."
        fi
    fi

    info "Configuring GRUB entry in: $target_cfg"
    # Create the boot entry using search --file
    cat <<EOF >"$target_cfg"
set timeout_style=menu
set timeout=5
menuentry "$(get_entry_name)" --unrestricted {
    echo "Loading Alpine initrd for DD..."
    # Search for the kernel file on any filesystem and set root
    search --no-floppy --file --set=root "$vmlinuz_search_arg"
    echo "Found kernel at (\$root)$vmlinuz_search_arg"
    # Load kernel and initrd using paths relative to the found root
    $linux_cmd "$vmlinuz_search_arg" $cmdline
    $initrd_cmd "$initrd_search_arg"
    echo "Booting..."
}
EOF
    info "GRUB entry created:"
    cat "$target_cfg" >&2 # Show the generated config
}

# --- Determine required modules ---
get_required_modules() {
    info "Detecting required disk and network drivers..."
    disk_driver_modules=""
    net_driver_modules=""
    find_main_disk # Ensure xda is set
    # Get disk drivers
    drivers=$( (cd "/sys/block/$xda/device"; pwd -P) | grep -o 'drivers/[^/]*' | cut -d/ -f2 | sort -u )
    for drv in $drivers; do disk_driver_modules+="$drv,"; done
    # Get network drivers for all interfaces
    for iface in $(ls /sys/class/net/ | grep -v lo); do
        drivers=$( (cd "/sys/class/net/$iface/device"; pwd -P) | grep -o 'drivers/[^/]*' | cut -d/ -f2 | sort -u )
        for drv in $drivers; do net_driver_modules+="$drv,"; done
    done
    # Remove trailing commas and duplicates
    disk_driver_modules=$(echo "$disk_driver_modules" | sed 's/,$//' | tr ',' '\n' | sort -u | paste -sd,)
    net_driver_modules=$(echo "$net_driver_modules" | sed 's/,$//' | tr ',' '\n' | sort -u | paste -sd,)
    info "Required disk modules (heuristic): $disk_driver_modules"
    info "Required net modules (heuristic): $net_driver_modules"
}


# --- Main Execution Logic ---

# Check root
[ "$EUID" -ne 0 ] && error_and_exit "Please run as root."

# Parameter parsing
long_opts="img:,password:,ssh-key:,ssh-port:,hold:,force-cn,help"
if ! opts=$(getopt -n "$0" -o "h" --long "$long_opts" -- "$@"); then exit 1; fi
eval set -- "$opts"
debian_img_url=""
password=""
ssh_keys=""
ssh_port=""
hold=""
force_cn=""
while true; do
    case "$1" in
        -h|--help) echo "Usage: $0 --img <debian_image_url> [--password PWD | --ssh-key KEY] [--ssh-port PORT] [--hold 1|2] [--force-cn]"; exit 0 ;;
        --img) debian_img_url=$2; shift 2 ;;
        --password) password=$2; shift 2 ;;
        --ssh-key) ssh_keys=$2; shift 2 ;; # Simplified: assumes key value is directly usable or fetched before save_password
        --ssh-port) if ! is_port_valid "$2"; then error_and_exit "Invalid SSH port: $2"; fi; ssh_port=$2; shift 2 ;;
        --hold) if [[ "$2" != "1" && "$2" != "2" ]]; then error_and_exit "Invalid hold value: $2 (use 1 or 2)"; fi; hold=$2; shift 2 ;;
        --force-cn) force_cn=1; shift ;;
        --) shift; break ;;
        *) echo "Internal error! Unexpected option: $1"; exit 1 ;;
    esac
done

# Validate essential parameters
[ -z "$debian_img_url" ] && error_and_exit "Debian image URL (--img) is required."
if [ -z "$password" ] && [ -z "$ssh_keys" ]; then
    prompt_password # Prompt if neither is provided
elif [ -n "$password" ] && [ -n "$ssh_keys" ]; then
    warn "Both --password and --ssh-key provided. SSH key will be used."
    unset password # Prioritize SSH key
fi

# Basic checks
install_pkg curl grep gzip cpio # Core utils
basearch=$(uname -m); case "$(echo "$basearch" | to_lower)" in x86*|amd64) basearch=x86_64; basearch_alt=amd64 ;; arm*|aarch64) basearch=aarch64; basearch_alt=arm64 ;; *) error_and_exit "Unsupported arch: $basearch" ;; esac
check_ram() {
    ram_size_k=$(grep '^MemTotal:' /proc/meminfo | awk '{print $2}'); ram_size=$((ram_size_k / 1024))
    echo "Detected RAM: ${ram_size}MB" >&2
    [ $ram_size -lt 256 ] && error_and_exit "Minimum 256MB RAM required for intermediate OS."
}
check_ram
get_required_modules # Detect modules needed for cmdline

# Intermediate OS (Alpine) details
alpine_ver=3.19 # Use a known stable version
is_in_china && nextos_repo=http://mirror.nju.edu.cn/alpine/v$alpine_ver/main || nextos_repo=https://dl-cdn.alpinelinux.org/alpine/v$alpine_ver/main
nextos_boot_base=$nextos_repo/../../v$alpine_ver/releases/$basearch_alt
# Use virt kernel for intermediate OS as it's smaller and likely sufficient for most hardware
nextos_vmlinuz=$nextos_boot_base/netboot/vmlinuz-virt
nextos_initrd=$nextos_boot_base/netboot/initramfs-virt
nextos_modloop=$nextos_boot_base/netboot/modloop-virt # Needed if mod_initrd needs to extract modules

# Download intermediate kernel/initrd
info "Downloading Alpine kernel and initrd (v$alpine_ver $basearch_alt)"
mkdir_clear "$tmp" # Ensure temp dir is clean
if ! curl -fLo /reinstall-vmlinuz "$nextos_vmlinuz"; then error_and_exit "Failed to download Alpine kernel."; fi
if ! curl -fLo /reinstall-initrd "$nextos_initrd"; then error_and_exit "Failed to download Alpine initrd."; fi
info "Download complete."

# Modify initrd
mod_initrd

# Configure bootloader
setup_bootloader

info 'Setup complete. Please verify the GRUB/EFI entry and reboot.'
echo "Target Debian Image: $debian_img_url"
echo "Username: root (in final system)"
if [ -n "$ssh_keys" ]; then echo "Login: SSH Key"; else echo "Login Password: $password"; fi
[ -n "$ssh_port" ] && echo "SSH Port (initrd & final): $ssh_port" || echo "SSH Port (initrd & final): 22 (default)"
echo "Reboot now to start the DD process via Alpine initrd."
