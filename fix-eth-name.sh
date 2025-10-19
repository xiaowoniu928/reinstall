#!/usr/bin/env bash
# shellcheck shell=dash
# shellcheck disable=SC3001,SC3010
# alpine 使用 busybox ash

set -eE

# Give udev/systemd time to rename interfaces
sleep 10
if command -v udevadm >/dev/null; then udevadm settle; fi

# ... [to_lower, retry remain the same] ...

# --- MODIFIED _get_ethx_by_mac ---
# Still primarily uses MAC, as it's needed for mapping config files.
# Added retry logic directly here.
_get_ethx_by_mac() {
    local mac
    mac=$(echo "$1" | to_lower)
    local found_ethx
    local i

    for i in $(seq 10); do
        # Use ip -br link for potentially simpler parsing and UP state check
        # Example: eth0    UP    00:11:22:33:44:55 <BROADCAST,...>
        # Filter out master interfaces (like Azure VF)
        found_ethx=$(ip -br link show up | grep -i " $mac " | grep -v ' master ' | awk '{print $1}' | head -n 1)

        # Alternative using /sys/class/net (less preferred now)
        # for iface in $(cd /sys/class/net && echo *); do
        #     if [ "$(cat "/sys/class/net/$iface/address" 2>/dev/null)" = "$mac" ]; then
        #         found_ethx="$iface"
        #         break
        #     fi
        # done

        if [ -n "$found_ethx" ]; then
            echo "$found_ethx"
            return 0
        fi
        echo "Waiting for interface with MAC $mac... ($i/10)" >&2
        sleep 1
    done

    echo "Error: Could not find UP interface with MAC $mac after 10 retries." >&2
    return 1
}
# --- END MODIFIED _get_ethx_by_mac ---

# Helper to find the current default route interface
get_default_route_iface() {
    local default_iface
    # Try IPv4 default route
    default_iface=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {print $(NF-1); exit}')
    # Try IPv6 default route if IPv4 failed
    if [ -z "$default_iface" ]; then
        default_iface=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '/dev/ {print $(NF-1); exit}')
    fi
    echo "$default_iface"
}

# Helper to find the first UP non-loopback interface
get_first_up_iface() {
     ip -o link show up | awk '!/LOOPBACK/ {print $2; exit}' | cut -d: -f1
}


# --- Functions to fix specific config types (remain largely the same) ---
# --- They now rely on the modified get_ethx_by_mac which includes retries ---
fix_rh_sysconfig() {
    local mac ethx proper_file file tmp_file
    echo "Checking sysconfig (ifcfg)..."
    for file in /etc/sysconfig/network-scripts/ifcfg-eth*; do
        [ -f "$file" ] || continue
        mac=$(grep -i ^HWADDR= "$file" | cut -d= -f2 | sed 's/"//g' | grep .) || continue
        ethx=$(_get_ethx_by_mac "$mac") || { echo "Skipping $file - could not find interface for MAC $mac"; continue; }

        proper_file=/etc/sysconfig/network-scripts/ifcfg-$ethx
        if [ "$file" != "$proper_file" ]; then
            echo "Updating $file -> $proper_file (MAC: $mac, IFACE: $ethx)"
            sed -i "s/^DEVICE=.*/DEVICE=$ethx/i" "$file"
            mv "$file" "$proper_file.tmp" # Rename temporarily
        else
             echo "File $file already has correct name for $ethx"
        fi
    done
    # Final rename
    for tmp_file in /etc/sysconfig/network-scripts/ifcfg-*.tmp; do
        [ -f "$tmp_file" ] && mv "$tmp_file" "${tmp_file%.tmp}"
    done
}

fix_suse_sysconfig() {
    local mac ethx file old_ethx type old_file new_file tmp_file
    echo "Checking sysconfig (wicked)..."
    for file in /etc/sysconfig/network/ifcfg-eth*; do
        [ -f "$file" ] || continue
        mac=$(grep -i ^LLADDR= "$file" | cut -d= -f2 | sed "s/['\"]//g" | grep .) || continue
        ethx=$(_get_ethx_by_mac "$mac") || { echo "Skipping $file - could not find interface for MAC $mac"; continue; }

        old_ethx=${file##*-}
        if [ "$old_ethx" != "$ethx" ]; then
             echo "Updating $old_ethx -> $ethx (MAC: $mac)"
            for type in ifcfg ifroute; do
                old_file=/etc/sysconfig/network/$type-$old_ethx
                new_file=/etc/sysconfig/network/$type-$ethx.tmp
                if [ -f "$old_file" ]; then mv "$old_file" "$new_file"; fi
            done
        else
            echo "File $file already has correct name for $ethx"
        fi
    done
    # Final rename
    for tmp_file in /etc/sysconfig/network/{ifcfg,ifroute}-*.tmp; do
         [ -f "$tmp_file" ] && mv "$tmp_file" "${tmp_file%.tmp}"
    done
}

fix_network_manager() {
    local mac ethx file proper_file
    echo "Checking NetworkManager connections..."
    # Check both potential locations
    for file in /etc/NetworkManager/system-connections/*.nmconnection /etc/NetworkManager/system-connections/cloud-init-eth*.nmconnection; do
        [ -f "$file" ] || continue
        # Use grep -i and handle potential spaces/quotes around MAC
        mac=$(grep -iE '^\s*mac-address\s*=' "$file" | head -n 1 | cut -d= -f2 | sed 's/"//g' | trim | grep .) || continue
        ethx=$(_get_ethx_by_mac "$mac") || { echo "Skipping $file - could not find interface for MAC $mac"; continue; }

        # Generate the expected filename based on the interface name found
        proper_file="/etc/NetworkManager/system-connections/$ethx.nmconnection"

        echo "Processing $file (MAC: $mac, IFACE: $ethx)"
        # Update connection ID and interface name within the file
        sed -i -e "s/^id=.*/id=$ethx/" \
               -e "s/^interface-name=.*/interface-name=$ethx/" "$file"

        # Rename the file if necessary
        if [ "$file" != "$proper_file" ]; then
            echo "Renaming $file -> $proper_file"
            # Ensure target directory exists
            mkdir -p "$(dirname "$proper_file")"
            # Use temporary name in case target exists but with different case
            mv "$file" "$proper_file.tmp"
            mv "$proper_file.tmp" "$proper_file"
        fi
    done
}


fix_ifupdown() {
    local file=/etc/network/interfaces
    local tmp_file=$file.tmp
    local mac ethx line del_this_line
    echo "Checking ifupdown ($file)..."

    rm -f "$tmp_file"
    [ ! -f "$file" ] && return 0

    while IFS= read -r line; do
        del_this_line=false
        # Match the specific comment format
        if echo "$line" | grep -q "^# mac "; then
            mac=$(echo "$line" | awk '{print $NF}')
            # Try to find the current interface for this MAC
            ethx=$(_get_ethx_by_mac "$mac") || ethx="" # Set empty if not found
            del_this_line=true # Don't write the '# mac' line to the new file
        # Match lines defining the interface stanza
        elif echo "$line" | grep -Eq '^(auto|allow-hotplug|iface) e'; then
            if [ -n "$ethx" ]; then
                # Replace the old interface name (e.g., eth0) with the new one ($ethx)
                line=$(echo "$line" | awk -v new_iface="$ethx" '{$2=new_iface; print $0}')
            else
                # If MAC lookup failed, keep the original line but maybe comment it out or warn
                echo "Warning: Could not find interface for MAC $mac, keeping original line: $line" >&2
            fi
        # Match lines referencing the device name (e.g., post-up ip route ... dev eth0)
        elif echo "$line" | grep -Eq '[[:space:]]dev e'; then
            if [ -n "$ethx" ]; then
                # Replace the old interface name at the end of the line
                line=$(echo "$line" | sed -E "s/dev [^ ]*$/dev $ethx/")
            else
                 echo "Warning: Could not find interface for MAC $mac, keeping original line: $line" >&2
            fi
        fi

        # Write the (potentially modified) line to the temp file, unless it's the '# mac' line
        if ! $del_this_line; then
            echo "$line" >>"$tmp_file"
        fi
    done <"$file"

    # Replace the original file with the modified temp file
    if [ -f "$tmp_file" ]; then
         echo "Updating $file"
         mv "$tmp_file" "$file"
         cat "$file" # Show the result
    fi
}


fix_netplan() {
    local file=/etc/netplan/50-cloud-init.yaml # Assuming this filename convention
    local tmp_file=$file.tmp
    local mac ethx line iface_block_indent current_iface
    echo "Checking netplan ($file)..."

    rm -f "$tmp_file"
    [ ! -f "$file" ] && return 0

    # Process line by line to handle indentation and blocks
    iface_block_indent=""
    current_iface=""

    while IFS= read -r line; do
        # Check if we are inside an interface block and find its MAC address
        if [ -n "$iface_block_indent" ] && echo "$line" | grep -Eq "^${iface_block_indent}[[:space:]]+macaddress:"; then
            mac=$(echo "$line" | awk '{print $NF}' | sed 's/"//g' | trim)
            ethx=$(_get_ethx_by_mac "$mac") || ethx=""
            if [ -z "$ethx" ]; then
                echo "Warning: Could not find interface for MAC $mac in netplan block starting with '$current_iface'" >&2
            fi
        # Detect the start of a new interface block (e.g., " eth0:")
        elif echo "$line" | grep -Eq '^[[:space:]]+eth[0-9]+:'; then
            # Extract indentation and the old interface name
            iface_block_indent=$(echo "$line" | sed -E 's/^([[:space:]]+).*/\1/')
            current_iface=$(echo "$line" | sed -E 's/^[[:space:]]+([^:]+):.*/\1/')
            # If we found the corresponding ethx from the macaddress line above, rename the block
            if [ -n "$ethx" ] && [ "$ethx" != "$current_iface" ]; then
                 echo "Updating netplan block $current_iface -> $ethx (MAC: $mac)"
                 line="${iface_block_indent}${ethx}:"
            elif [ -z "$ethx" ]; then
                 echo "Warning: Keeping original netplan block name '$current_iface' as MAC lookup failed." >&2
                 # Reset ethx so we don't accidentally rename the wrong block later
                 ethx=""
            fi
            # Reset mac/ethx for the next block
            mac=""
            # Keep ethx if it matched current_iface, reset otherwise
            [ "$ethx" = "$current_iface" ] || ethx=""

        # If the line's indentation is less than or equal to the current block, we've left the block
        elif [ -n "$iface_block_indent" ] && ! echo "$line" | grep -Eq "^${iface_block_indent}[[:space:]]+"; then
             iface_block_indent=""
             current_iface=""
             mac=""
             ethx=""
        fi
        echo "$line" >> "$tmp_file"
    done < "$file"

    if [ -f "$tmp_file" ]; then
        echo "Updating $file"
        mv "$tmp_file" "$file"
        cat "$file" # Show the result
    fi
}


fix_systemd_networkd() {
    local mac ethx file proper_file
    echo "Checking systemd-networkd..."
    for file in /etc/systemd/network/*.network /etc/systemd/network/10-cloud-init-eth*.network; do
        [ -f "$file" ] || continue
        # Handle MACAddress potentially being commented out or missing
        mac=$(grep -iE '^\s*MACAddress\s*=' "$file" | head -n 1 | cut -d= -f2 | trim | grep .) || continue
        ethx=$(_get_ethx_by_mac "$mac") || { echo "Skipping $file - could not find interface for MAC $mac"; continue; }

        # Expected filename based on interface name
        proper_file="/etc/systemd/network/10-$ethx.network"

        echo "Processing $file (MAC: $mac, IFACE: $ethx)"
        # Update Name= line if it exists and refers to a specific ethX
        # Use -i directly on the file
        sed -i -E "s/^(Name=)eth[0-9]+/\1$ethx/i" "$file"

        # Rename file if necessary
        if [ "$file" != "$proper_file" ]; then
            echo "Renaming $file -> $proper_file"
            mkdir -p "$(dirname "$proper_file")"
            mv "$file" "$proper_file.tmp"
            mv "$proper_file.tmp" "$proper_file"
        fi
    done
}


# --- Main Logic ---
echo "Starting network interface name fix..."

# Try to find the primary interface (default route or first up)
# This is mainly for logging/context, the fixing logic relies on MAC mapping
primary_iface=$(get_default_route_iface)
if [ -z "$primary_iface" ]; then
    primary_iface=$(get_first_up_iface)
    if [ -n "$primary_iface" ]; then
        echo "Could not find default route, assuming primary interface is first UP: $primary_iface"
    else
        echo "Warning: Could not determine primary interface."
    fi
else
     echo "Detected default route interface: $primary_iface"
fi


# Execute fix functions for different configuration types
# These functions internally use the MAC address from the config files
# to find the corresponding current interface name via _get_ethx_by_mac
fix_rh_sysconfig
fix_suse_sysconfig
fix_network_manager
fix_ifupdown
fix_netplan
fix_systemd_networkd

echo "Network interface name fix attempt finished."

# Optional: Restart networking service if possible/needed
# Be cautious with restarting networking unattended
# if command -v systemctl >/dev/null; then
#     echo "Attempting to restart networking..."
#     systemctl restart systemd-networkd NetworkManager networking wicked 2>/dev/null || true
# elif command -v rc-service >/dev/null; then
#      echo "Attempting to restart networking..."
#      rc-service networking restart 2>/dev/null || true
# fi

exit 0
