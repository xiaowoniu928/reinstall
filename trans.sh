#!/bin/ash
# shellcheck shell=dash disable=SC2154,SC2086,SC3047,SC3010,SC3001,SC3060

# Simplified trans script for DD Debian - Runs within Alpine initrd

set -eE
confhome="MUST_BE_SET_BY_CMDLINE" # Will be overridden by extra_confhome
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin # Ensure path is set
THIS_SCRIPT=$(readlink -f "$0")
trap 'trap_err $LINENO $?' ERR

# --- Essential Variables ---
SCRIPT_VERSION=4BACD833-A585-23BA-6CBB-9AA4E08E0003 # <-- 确保和 reinstall.sh 中的一致

# --- Logging and Error Handling ---
trap_err() { line_no=$1; ret_no=$2; _log_msg='\e[31m'; echo -e "${_log_msg}***** ERROR *****"; echo -e "${_log_msg}Line $line_no failed with exit code $ret_no:"; sed -n "${line_no}p" "$THIS_SCRIPT" | sed "s/^/${_log_msg}  /"; echo -e "\e[0m"; echo "DD failed. System might be in an unusable state."; exit 1; }
_log() { color=$1; shift; echo -e "$color***** $(echo "$*" | tr '[:lower:]' '[:upper:]') *****\e[0m" >&2; }
info() { _log '\e[32m' "$@"; }
warn() { _log '\e[33m' "Warning: $*"; }
error() { _log '\e[31m' "ERROR: $*"; } # Don't exit here, trap_err handles exit
error_and_exit() { error "$@"; exit 1; } # For explicit exits not caught by trap
to_upper() { tr '[:lower:]' '[:upper:]'; }
to_lower() { tr '[:lower:]' '[:lower:]'; }
is_efi() { [ -d /sys/firmware/efi/ ]; }
get_all_disks() { ls /sys/block/ | grep -Ev '^(loop|sr|nbd|ram|zram)'; } # Exclude ramdisks etc.
update_part() { info "Updating partition table on /dev/$xda"; sleep 1; sync; partprobe "/dev/$xda" >/dev/null 2>&1 || true; partx -u "/dev/$xda" >/dev/null 2>&1 || true; mdev -sf >/dev/null 2>&1 || true; sleep 1; }
get_disk_size() { blockdev --getsize64 "$1" 2>/dev/null || echo 0; } # Add error handling

# --- wget wrapper ---
wget() {
    # Simple wget wrapper, relies on apk adding it if missing
    apk add wget >/dev/null 2>&1 || true # Add if missing, suppress output
    echo "wget args: $*" | grep -o 'http[^ ]*' >&2 || true # Log URL
    retry 5 5 command wget --no-check-certificate "$@" # Use retry with timeout
}
retry() {
    local max_try=$1; shift; local interval=5; [ "$(echo "$1" | grep -Ex '[0-9]+')" ] && { interval=$1; shift; };
    info "Retrying command (max $max_try times, interval ${interval}s): $*"
    for i in $(seq $max_try); do if "$@"; then info "Command successful."; return 0; else ret=$?; warn "Command failed with code $ret (Attempt $i/$max_try)."; [ $i -ge $max_try ] && { error "Command failed after $max_try attempts."; return $ret; }; sleep $interval; fi; done
}

# --- apk wrapper ---
apk() { retry 5 command apk "$@" >&2; }

# --- Disk/Partition Functions ---
find_xda() {
    if [ -n "$extra_xda" ] && [ -b "/dev/$extra_xda" ]; then
        xda="$extra_xda"
        info "Using target disk from cmdline: /dev/$xda"
        return
    elif [ -n "$extra_main_disk" ]; then
        info "Searching for disk with ID/Name: $extra_main_disk"
        # Use get-xda.sh script provided in initrd
        xda_found=$(sh /get-xda.sh "$extra_main_disk") # Pass ID to script
        if [ "$xda_found" != "MAIN_DISK_NOT_FOUND" ] && [ "$xda_found" != "XDA_NOT_FOUND" ] && [ -b "/dev/$xda_found" ]; then
            xda="$xda_found"
            info "Found target disk: /dev/$xda"
            return
        else
             error "get-xda.sh failed to find disk '$extra_main_disk', reported: $xda_found"
        fi
    fi
    error_and_exit "Could not determine target disk (xda). Missing or invalid extra_xda/extra_main_disk in cmdline."
}

# --- DD Function ---
dd_raw_image() {
    info "Starting DD operation from $extra_img to /dev/$xda"
    apk add wget pv # Ensure wget and pv are available

    # Check image URL
    [ -z "$extra_img" ] && error_and_exit "Image URL (extra_img) not provided in cmdline."

    # Directly pipe wget to pv to dd
    # Use pv options: -p (progress), -t (timer), -e (eta), -r (rate), -b (bytes), -s (size if known, enhances ETA)
    # Getting size beforehand might be slow or unsupported, so omit -s for now
    if ! wget "$extra_img" -O- | pv -pterb > "/dev/$xda"; then
        # Check dd exit code specifically if possible (ash doesn't have PIPESTATUS easily)
        # Check for common "No space left on device" error
        # NOTE: pv errors might mask dd errors. Check dmesg too.
        dmesg | tail -n 10 # Show last kernel messages
        if dmesg | grep -q "No space left on device"; then
             warn "DD likely failed due to 'No space left on device'. Attempting to proceed with resize/fix."
             # Try to read partition table to see if it's somewhat usable
             if ! parted -sf "/dev/$xda" 'unit b print' >/dev/null 2>&1; then
                  error_and_exit "DD failed AND partition table unreadable. Cannot proceed."
             fi
             # If table is readable, maybe only the end was truncated (e.g., VHD footer)
             return 0 # Continue despite the error, resize might fix it
        fi
        # If it's another error
        error_and_exit "DD command failed. Check logs and dmesg."
    fi
    info "DD operation completed successfully."
    # Ensure data is written to disk
    sync; sync
}

# --- Resizing Functions ---
fix_gpt_backup_partition_table_by_parted() {
    info "Checking/Fixing GPT backup partition table on /dev/$xda"
    apk add parted # Ensure parted is available
    if parted "/dev/$xda" -f -s print >/dev/null 2>&1; then
        info "GPT table appears OK or was fixed by parted."
    else
        warn "Parted failed to read/fix backup table. Resizing might fail."
    fi
    update_part # Update kernel view
}
resize_partition_and_fs() {
    info "Attempting to resize partition and filesystem on /dev/$xda"
    lsblk -f "/dev/$xda" || warn "lsblk failed" # Show layout before resizing
    fix_gpt_backup_partition_table_by_parted # Ensure table is valid

    disk_size=$(get_disk_size "/dev/$xda"); [ "$disk_size" -eq 0 ] && { warn "Could not get disk size for /dev/$xda"; return 1; }
    disk_end=$((disk_size - 1))

    # Get last partition number and its end position
    # Use parted machine-readable output for robustness
    last_part_info=$(parted -sm "/dev/$xda" 'unit B print' | grep -v '^BYT;' | tail -n 1)
    last_part_num=$(echo "$last_part_info" | cut -d: -f1)
    last_part_end=$(echo "$last_part_info" | cut -d: -f3 | sed 's/B$//')

    # Check if partition number and end look valid
    if ! echo "$last_part_num" | grep -q '^[0-9]\+$' || ! echo "$last_part_end" | grep -q '^[0-9]\+$'; then
        error "Failed to parse last partition info from parted output: $last_part_info"
        return 1
    fi
    info "Last partition is $last_part_num, ends at $last_part_end B. Disk ends at $disk_end B."

    # Check if there's space to grow (add a small buffer like 1MB to avoid precision issues)
    if [ $((disk_end - last_part_end)) -gt 1048576 ]; then
        info "Extending partition $last_part_num to fill disk (approx ${disk_size} B)"
        # Use pretend-input-tty for parted non-interactive resize confirmation
        if printf "Ignore\nyes\n" | parted ---pretend-input-tty "/dev/$xda" resizepart "$last_part_num" 100%; then
             update_part
             last_part_dev="/dev/${xda}${last_part_num}"
             # Detect filesystem using blkid
             apk add util-linux # for blkid
             last_part_fs=$(blkid -o value -s TYPE "${last_part_dev}" 2>/dev/null)
             info "Detected filesystem: '$last_part_fs' on $last_part_dev. Attempting resize."
             case "$last_part_fs" in
             ext[234])
                 apk add e2fsprogs e2fsprogs-extra # Need both for check and resize
                 info "Checking filesystem..."
                 e2fsck -p -f "$last_part_dev" || warn "e2fsck found errors, resize might fail or cause issues."
                 info "Resizing ext filesystem..."
                 resize2fs "$last_part_dev" || error "resize2fs failed."
                 ;;
             xfs)
                 apk add xfsprogs xfsprogs-extra
                 mount_dir=/mnt/os_resize
                 mkdir -p "$mount_dir"
                 info "Mounting $last_part_dev..."
                 if mount "$last_part_dev" "$mount_dir"; then
                     info "Resizing XFS filesystem..."
                     if xfs_growfs "$mount_dir"; then info "xfs_growfs successful."; else error "xfs_growfs failed."; fi
                     info "Unmounting $mount_dir..."
                     umount "$mount_dir" || warn "Failed to unmount $mount_dir after resize."
                 else error "Failed to mount $last_part_dev for XFS resize."; fi
                 rmdir "$mount_dir"
                 ;;
             btrfs)
                 apk add btrfs-progs
                 mount_dir=/mnt/os_resize
                 mkdir -p "$mount_dir"
                 info "Mounting $last_part_dev..."
                 if mount "$last_part_dev" "$mount_dir"; then
                     info "Resizing Btrfs filesystem..."
                     if btrfs filesystem resize max "$mount_dir"; then info "Btrfs resize successful."; else error "Btrfs resize failed."; fi
                     info "Unmounting $mount_dir..."
                     umount "$mount_dir" || warn "Failed to unmount $mount_dir after resize."
                 else error "Failed to mount $last_part_dev for Btrfs resize."; fi
                 rmdir "$mount_dir"
                 ;;
             *)
                 warn "Filesystem type '$last_part_fs' detected, but automatic resizing is not supported by this script. Manual resize might be needed after reboot."
                 ;;
             esac
             update_part # Update kernel again after FS resize
        else
            error "Parted failed to resize partition $last_part_num."
        fi
    else
        info "Partition $last_part_num already seems to fill the disk. No resize needed."
    fi
    info "Final partition layout:"
    parted "/dev/$xda" -s print || warn "parted print failed after resize attempt"
    lsblk -f "/dev/$xda" || warn "lsblk failed after resize attempt"
}


# --- Post-DD Modification Functions ---
get_config() { cat "/configs/$1" 2>/dev/null || true; }
is_need_set_ssh_keys() { [ -f /configs/ssh_keys ] && [ -s /configs/ssh_keys ]; }

change_root_password() {
    os_dir=$1; info "Setting root password in $os_dir/etc/shadow"
    shadow_file="$os_dir/etc/shadow"
    # Check if shadow file exists and is writable
    if [ ! -f "$shadow_file" ]; then warn "Shadow file not found at $shadow_file"; return 1; fi
    # if [ ! -w "$shadow_file" ]; then warn "Shadow file $shadow_file not writable"; return 1; fi # Might fail if mounted RO initially

    password_entry=""
    # Prioritize hashed password if available
    if hashed_pw=$(get_config password-linux-sha512) && [ -n "$hashed_pw" ]; then
        info "Using pre-generated sha512 hash."
        # Get current epoch time for last password change field
        current_epoch=$(date +%s)
        days_since_epoch=$((current_epoch / 86400))
        # Format: user:password:lastchange:min:max:warn:inactive:expire
        password_entry="root:$hashed_pw:$days_since_epoch:0:99999:7:::"
    elif password=$(get_config password-plaintext) && [ -n "$password" ]; then
        info "Generating password hash from plaintext (using busybox crypt)..."
        # Requires busybox built with crypt support
        hashed_pw=$(busybox cryptpw -m sha512 "$password" 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$hashed_pw" ]; then
             current_epoch=$(date +%s); days_since_epoch=$((current_epoch / 86400))
             password_entry="root:$hashed_pw:$days_since_epoch:0:99999:7:::"
        else warn "Failed to hash plaintext password using busybox cryptpw. Password not set."; fi
    fi

    if [ -n "$password_entry" ]; then
        # Use awk for safer replacement to handle special characters in hash
        awk -v entry="$password_entry" 'BEGIN{FS=OFS=":"} /^root:/ { $0 = entry } { print }' "$shadow_file" > "$shadow_file.tmp" && \
        mv "$shadow_file.tmp" "$shadow_file" && \
        chmod 600 "$shadow_file" && \
        info "Root password updated in shadow file." || \
        error "Failed to update shadow file."
    else warn "No password information (hash or plaintext) found. Root password not set."; fi
}

set_ssh_keys_and_del_password() {
    os_dir=$1; info "Setting SSH keys and disabling password login in $os_dir"
    shadow_file="$os_dir/etc/shadow"
    # Set keys
    auth_keys_file="$os_dir/root/.ssh/authorized_keys"
    mkdir -p "$(dirname "$auth_keys_file")" && \
    chmod 700 "$(dirname "$auth_keys_file")" && \
    cp /configs/ssh_keys "$auth_keys_file" && \
    chmod 600 "$auth_keys_file" && \
    info "SSH keys copied to $auth_keys_file." || \
    error "Failed to copy SSH keys."

    # Disable password by locking account in shadow file
    # if [ ! -f "$shadow_file" ]; then warn "Shadow file not found at $shadow_file"; return 1; fi
    # if [ ! -w "$shadow_file" ]; then warn "Shadow file $shadow_file not writable"; return 1; fi # Check writability
    if [ -f "$shadow_file" ]; then
        # Replace password hash with '!' or '*' (both typically lock)
         awk 'BEGIN{FS=OFS=":"} /^root:/ { $2 = "!" } { print }' "$shadow_file" > "$shadow_file.tmp" && \
         mv "$shadow_file.tmp" "$shadow_file" && \
         chmod 600 "$shadow_file" && \
         info "Root password login disabled in shadow file." || \
         error "Failed to disable password login in shadow file."
    else warn "Shadow file not found, cannot disable password login."; fi

    # Also configure sshd_config for safety (PermitRootLogin without-password, PasswordAuthentication no)
    sshd_config="$os_dir/etc/ssh/sshd_config"
    if [ -f "$sshd_config" ]; then
        info "Configuring sshd_config for key-only login."
        # Use sed carefully, preserving existing lines, changing only relevant settings
        sed -i -e 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' \
               -e 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' \
               "$sshd_config"
        # Add settings if they don't exist
        grep -q '^PermitRootLogin' "$sshd_config" || echo "PermitRootLogin prohibit-password" >> "$sshd_config"
        grep -q '^PasswordAuthentication' "$sshd_config" || echo "PasswordAuthentication no" >> "$sshd_config"
    else warn "sshd_config not found, cannot enforce key-only login via config."; fi
}

basic_init_on_disk() {
    os_dir=$1; info "Performing basic system initialization on $os_dir"
    ssh_dir="$os_dir/etc/ssh"

    if [ -d "$ssh_dir" ]; then
        # Ensure host keys exist (generate if needed, though unlikely after DD)
        if ! ls "$ssh_dir"/ssh_host_*_key > /dev/null 2>&1; then
             info "Generating SSH host keys in $os_dir"
             # Need ssh-keygen in initrd, or mount proc/dev and chroot (complex)
             # Let's assume keys exist or first boot will generate them.
             warn "SSH host keys not found. First boot might generate them or SSH may fail."
        fi

        # Ensure sshd service is enabled (best effort for systemd)
        if [ -d "$os_dir/etc/systemd/system" ]; then
             ssh_service=$(find "$os_dir/lib/systemd/system/" "$os_dir/etc/systemd/system/" -name 'ssh*.service' -printf '%f\n' | grep -v '@' | head -n 1)
             if [ -n "$ssh_service" ]; then
                 target_wants_dir="$os_dir/etc/systemd/system/multi-user.target.wants"
                 service_link_target="../$(find "$os_dir/lib/systemd/system/" "$os_dir/etc/systemd/system/" -name "$ssh_service" -printf '%P\n' | head -n 1)" # Relative path
                 service_link_path="$target_wants_dir/$ssh_service"
                 if [ ! -e "$service_link_path" ]; then # Only link if not already linked
                      info "Enabling $ssh_service (best effort by creating symlink)"
                      mkdir -p "$target_wants_dir"
                      ln -sf "$service_link_target" "$service_link_path" || warn "Failed to create symlink for $ssh_service"
                 else info "$ssh_service seems already enabled."; fi
             else warn "Could not find sshd service file."; fi
        fi

        # Set password or keys & configure sshd_config
        if is_need_set_ssh_keys; then
            set_ssh_keys_and_del_password "$os_dir" # Handles sshd_config too
        else
            change_root_password "$os_dir"
            # Ensure root login via password is allowed in sshd_config
            sshd_config="$os_dir/etc/ssh/sshd_config"
            if [ -f "$sshd_config" ]; then
                info "Ensuring PermitRootLogin yes and PasswordAuthentication yes in sshd_config."
                sed -i -e 's/^#*PermitRootLogin.*/PermitRootLogin yes/' \
                       -e 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' \
                       "$sshd_config"
                grep -q '^PermitRootLogin' "$sshd_config" || echo "PermitRootLogin yes" >> "$sshd_config"
                grep -q '^PasswordAuthentication' "$sshd_config" || echo "PasswordAuthentication yes" >> "$sshd_config"
            else warn "sshd_config not found, cannot ensure password login is enabled."; fi
        fi

        # Adjust SSH port if specified
        if [ -n "$extra_ssh_port" ]; then
             info "Setting SSH port to $extra_ssh_port in sshd_config"
             sshd_config="$os_dir/etc/ssh/sshd_config"
             if [ -f "$sshd_config" ]; then
                 if grep -qE '^#?Port ' "$sshd_config"; then
                      sed -i "s/^#*Port .*/Port $extra_ssh_port/" "$sshd_config"
                 else echo "Port $extra_ssh_port" >> "$sshd_config"; fi
             else warn "sshd_config not found, cannot set custom SSH port."; fi
        fi

    else warn "SSH configuration directory not found at $ssh_dir. Cannot configure SSH."; fi
}
add_fix_eth_name_service_on_disk() {
    os_dir=$1; info "Adding fix-eth-name service to $os_dir"
    # Assumes systemd
    if [ -d "$os_dir/etc/systemd/system" ]; then
        if cp /fix-eth-name.sh "$os_dir/fix-eth-name.sh" && \
           cp /fix-eth-name.service "$os_dir/etc/systemd/system/fix-eth-name.service"; then
             target_wants_dir="$os_dir/etc/systemd/system/multi-user.target.wants"
             service_link_path="$target_wants_dir/fix-eth-name.service"
             mkdir -p "$target_wants_dir"
             ln -sf "../fix-eth-name.service" "$service_link_path" || warn "Failed to create symlink for fix-eth-name.service"
             info "fix-eth-name service added and enabled (best effort)."
        else error "Failed to copy fix-eth-name files."; fi
    else warn "Systemd directory not found in $os_dir, cannot install fix-eth-name service."; fi
}

modify_debian_after_dd() {
    mount_dir=/mnt/os_final; info "Attempting to mount and modify DD'd Debian system"
    mkdir -p "$mount_dir"
    # Find the last partition device again after potential resizing
    last_part_num=$(parted -sm "/dev/$xda" 'unit B print' | grep -v '^BYT;' | tail -n 1 | cut -d: -f1)
    [ -z "$last_part_num" ] && { error "Could not determine last partition number after resize."; return 1; }
    last_part_dev="/dev/${xda}${last_part_num}"

    info "Mounting $last_part_dev to $mount_dir"
    # Try mounting (read-write needed for modifications)
    # Detect FS type again in case it matters for mount options
    fs_type=$(blkid -o value -s TYPE "$last_part_dev" 2>/dev/null)
    mount_opts="-o rw" # Default read-write
    # Add specific options if needed (e.g., Btrfs subvolume)
    # [ "$fs_type" = "btrfs" ] && mount_opts="-o rw,subvol=/@" # Example

    if mount $mount_opts "$last_part_dev" "$mount_dir"; then
        info "System mounted successfully. Performing basic initialization."
        basic_init_on_disk "$mount_dir"
        add_fix_eth_name_service_on_disk "$mount_dir" # Add network fixup service

        # Optional: Add any other critical modifications here
        # Example: Ensure /etc/fstab points to the correct root device (UUID recommended)
        # info "Updating fstab..."
        # root_uuid=$(blkid -o value -s UUID "$last_part_dev")
        # if [ -n "$root_uuid" ]; then
        #     sed -i.bak "s|^[^#].*[[:space:]]/[[:space:]]|UUID=$root_uuid / |" "$mount_dir/etc/fstab" && \
        #     info "Updated root entry in fstab with UUID=$root_uuid" || \
        #     warn "Failed to update fstab with UUID."
        # else warn "Could not get UUID for root device, fstab not updated."; fi

        info "Unmounting Debian system from $mount_dir"
        sync # Sync before unmount
        umount "$mount_dir" || warn "Failed to unmount $mount_dir. Reboot might be unclean."
    else
        error "Failed to mount $last_part_dev read-write. Cannot perform post-DD modifications."
        # Decide whether to proceed with reboot or halt
        # return 1 # Indicate failure
    fi
    rmdir "$mount_dir" >/dev/null 2>&1 || true
}


# --- Main DD Transition Logic ---
trans() {
    info "Starting DD Transition Script in Alpine initrd"
    extract_env_from_cmdline # Get extra_* variables from kernel cmdline
    confhome="$extra_confhome" # Set confhome from cmdline

    # 0. Basic setup
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev
    mdev -sf # Populate /dev based on /sys

    # Ensure essential tools are present in initrd (should have been added during mod_initrd)
    for cmd in wget pv parted blockdev blkid e2fsck resize2fs xfs_growfs btrfs ssh-keygen date awk sed grep cut mount umount sync reboot; do
         command -v $cmd >/dev/null || apk add $(echo $cmd | sed 's/e2fsck/e2fsprogs/;s/resize2fs/e2fsprogs-extra/;s/xfs_growfs/xfsprogs-extra/;s/btrfs/btrfs-progs/;s/blkid/util-linux/;s/blockdev/util-linux/')
    done

    # 1. Setup Network (using script passed from reinstall.sh)
    info "Configuring network..."
    # Execute the network setup script(s) - already done by init? Rerun for safety?
    # $(get_ip_conf_cmd) # Re-running might be complex, assume init configured it.
    ip a # Show current IP config

    # 1b. Setup SSH server in initrd for debugging
    apk add openssh > /dev/null
    ssh-keygen -A > /dev/null
    if [ -n "$extra_ssh_port" ]; then sed -i "s/^#*Port .*/Port $extra_ssh_port/" /etc/ssh/sshd_config; fi
    # Set password or key for initrd SSH
    mkdir -p /root/.ssh; chmod 700 /root/.ssh
    if [ -f /configs/ssh_keys ]; then
        cp /configs/ssh_keys /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    else
        passwd_plain=$(cat /configs/password-plaintext 2>/dev/null)
        [ -n "$passwd_plain" ] && echo "root:$passwd_plain" | chpasswd || echo "root:$(cat /configs/password-linux-sha512)" | chpasswd -e
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    fi
    /usr/sbin/sshd # Start SSH daemon
    info "SSH server started in initrd on port ${extra_ssh_port:-22}."

    # 1c. Optional hold for debugging initrd *before* DD
    if [ "$extra_hold" = 1 ]; then
         info "Holding before DD (hold=1). Connect via SSH. Run 'kill $$' to continue."
         tail -f /dev/null # Wait indefinitely
         # User needs to kill this shell process (kill $$) to proceed
         info "Continuing after hold..."
    fi

    # 2. Find the target disk
    find_xda

    # 3. Perform the DD operation
    if ! dd_raw_image; then
        error_and_exit "DD operation failed critically." # Exit if dd_raw_image returns non-zero
    fi

    # 4. Resize partition and filesystem
    if ! resize_partition_and_fs; then
        warn "Resizing failed or was skipped. Manual resizing may be needed after boot."
        # Decide whether to continue or stop if resizing is critical
        # error_and_exit "Resizing failed, cannot proceed." # Example if resizing must succeed
    fi

    # 5. Mount and perform minimal modifications
    if ! modify_debian_after_dd; then
        warn "Post-DD modifications failed or were skipped."
        # Decide whether to continue or stop
        # error_and_exit "Post-DD modification failed, cannot proceed."
    fi

    info "DD and modification process complete."

    # 6. Optional hold for debugging *after* DD and modifications
    if [ "$extra_hold" = 2 ]; then
         info "Holding after DD (hold=2). System was mounted at /mnt/os_final (if successful) during modification."
         info "Connect via SSH to inspect. Reboot manually when done."
         exit 0 # Exit without rebooting
    fi

    # 7. Reboot into the new system
    info "Rebooting into the new Debian system in 10 seconds..."
    sleep 10
    # Ensure sync before reboot
    sync; sync
    info "REBOOTING NOW..."
    reboot -f # Force reboot
}

# --- Script Entry Point ---
extract_env_from_cmdline() {
    # Extract extra_* variables from kernel cmdline (/proc/cmdline)
    info "Parsing kernel command line..."
    for arg in $(cat /proc/cmdline); do
        if echo "$arg" | grep -q '^extra_'; then
            # Handle key='value' or key=value
            key=$(echo "$arg" | cut -d= -f1)
            value=$(echo "$arg" | cut -d= -f2- | sed "s/^'//" | sed "s/'$//")
            info "  Found cmdline var: $key=$value"
            eval "$key='$value'" # Set the variable in the current shell
        fi
    done
}

# Run the main transition function
# Use tee to capture output to log file and console(s)
# Determine console devices using ttys.sh
console_devs=$(sh /ttys.sh /dev/ 2>/dev/null || echo /dev/console) # Fallback to /dev/console
log_file=/reinstall-dd.log
info "Starting DD process. Output logged to $log_file and console(s): $console_devs"
# exec > >(exec tee $console_devs $log_file) 2>&1 # This causes issues in busybox ash
# Simple redirection, might lose console output if tee fails early
trans 2>&1 | tee $console_devs $log_file

# Fallback reboot if trans doesn't exit/reboot (shouldn't be reached if trans is successful)
error "Trans function finished unexpectedly without rebooting. Attempting fallback reboot."
sleep 10
sync; sync
reboot -f
