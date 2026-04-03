#!/bin/sh
show_progress()
{
	total_time=$1
	local count=0
	current_progress=0
	min_increment=5
	max_increment=20
	
	while [ $current_progress -lt 100 ]; do
		random_value=$((RANDOM % (max_increment - min_increment + 1) + min_increment))
		if [ $count -eq 0 ];then
			random_value=2
		fi
		if [ $count -eq 1 ];then
			random_value=10
		fi

		current_progress=$((current_progress + random_value))
		if [ $current_progress -gt 100 ]; then
			current_progress=100
		fi
		progress=$((current_progress))
		if [ $count -ge $total_time ];then
			progress=100
		fi
		printf "\rProgress: [%-50s] %d%%" $(printf "%0.s#" $(seq 1 $((progress / 2)))) $progress
		if [ $count -ge $total_time ];then
			break
		fi
		count=`expr $count + 1`	
		sleep 1
	done
	echo
}

get_cpu_usage() {
    cpu1=$(awk '/^cpu / {print $2, $3, $4, $5, $6, $7, $8}' /proc/stat)
    idle1=$(echo $cpu1 | awk '{print $4}')
    total1=$(echo $cpu1 | awk '{print $1 + $2 + $3 + $4 + $5 + $6 + $7}')

    sleep 1

    cpu2=$(awk '/^cpu / {print $2, $3, $4, $5, $6, $7, $8}' /proc/stat)
    idle2=$(echo $cpu2 | awk '{print $4}')
    total2=$(echo $cpu2 | awk '{print $1 + $2 + $3 + $4 + $5 + $6 + $7}')

    idle_diff=$((idle2 - idle1))
    total_diff=$((total2 - total1))

    cpu_usage=$((100 * (total_diff - idle_diff) / total_diff))
    echo "$cpu_usage"
}

refresh_system_info() {                                                                                  
    mem_total_kb=$(free | grep Mem | awk '{print $2}')                   
    mem_used_kb=$(free | grep Mem | awk '{print $3}') 
    mem_total=$(expr $mem_total_kb / 1024)                   
    mem_used=$(expr $mem_used_kb / 1024)                     
    mem_usage=$(expr $mem_used \* 100 / $mem_total)                             
    hostname=$(cat /proc/sys/kernel/hostname)
    conn_num=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
    client_num=$(cat /proc/net/af_client 2>/dev/null | wc -l)
    if [ $client_num -ge 1 ];then
     client_num=`expr $client_num - 1`
    fi
    cpu_usage=$(get_cpu_usage)
    
    # Get work mode from UCI config
    work_mode=$(uci get fwx.network.work_mode 2>/dev/null)
    if [ -z "$work_mode" ]; then
        work_mode="0"
    fi
    if [ "$work_mode" = "0" ]; then
        work_mode_str="Gateway Mode"
    elif [ "$work_mode" = "1" ]; then
        work_mode_str="Bypass Mode"
    else
        work_mode_str="Unknown Mode"
    fi
                                
    #ip_address=$(ip -o -4 addr show | awk '{print $2 ": " $4}' | tr '\n' ' ') 
    ip_address=$(ip -o -4 addr show | awk '{print $2 ": " $4}') 
    
    clear                                                                    
    echo -e "Hostname: \033[1;32m${hostname}\033[0m"                                                                     
    echo -e "Cpu Usage: \033[1;32m${cpu_usage}%\033[0m"                                                                     
    echo -e "Memory Usage: \033[1;32m${mem_used}MB/${mem_total}MB (${mem_usage}%)\033[0m"        
    echo -e "Network Sessions: \033[1;32m${conn_num}\033[0m"                                                                     
    echo -e "Client Num: \033[1;32m${client_num}\033[0m"     
    echo -e "Work Mode: \033[1;32m${work_mode_str}\033[0m"                                                  
    echo -e "IP Addresses:"
    prefix=""
    local count=`echo "$ip_address" | wc -l`
    local loop=0
    echo "$ip_address" | while read -r line; do
         loop=`expr $loop + 1`
         # Parse interface name and IP/CIDR
         iface=$(echo "$line" | awk -F': ' '{print $1}')
         ip_cidr=$(echo "$line" | awk -F': ' '{print $2}')
         
         # Extract IP and CIDR
         ip=$(echo "$ip_cidr" | cut -d'/' -f1)
         cidr=$(echo "$ip_cidr" | cut -d'/' -f2)
         
         # Convert CIDR to netmask
         if [ -n "$cidr" ]; then
             netmask=$(cidr_to_netmask $cidr)
             display_line="${iface}: ${ip} (${netmask})"
         else
             display_line="${iface}: ${ip_cidr}"
         fi
         
         if [ $loop -eq $count ];then
             echo -e "    └── ${display_line}"
         else
             echo -e "    ├── ${display_line}"
         fi
    done
    echo                                                                     
}  

usage() {
    echo "--------------------Quick Start-------------------"
    echo -e "\033[1;32m[1]\033[0m Set LAN(br-lan) IP Proto to DHCP"
    echo -e "\033[1;33m[2]\033[0m Set LAN(br-lan) Static IP"
    echo -e "\033[1;35m[3]\033[0m Show network interfaces (ifconfig)"
    echo -e "\033[1;36m[4]\033[0m Show Program Info (ps)"
    echo -e "\033[1;37m[5]\033[0m Monitor Online Clients"
    echo -e "\033[1;31m[q]\033[0m Enter FanchmWrt Shell"
    echo "--------------------------------------------------"
}

show_disks() {
    echo "Disk and Partition Information:"
    echo "-----------------------------------------------------------"

    for disk in /dev/sd?; do
        base_name=$(basename $disk)
        vendor=$(cat /sys/block/$base_name/device/vendor 2>/dev/null | tr -d ' ')
        model=$(cat /sys/block/$base_name/device/model 2>/dev/null | tr -d ' ')
        vendor_model="${vendor}, ${model}"
        size=$(fdisk -l $disk 2>/dev/null | grep "Disk $disk" | awk '{print $3, $4}' | tr -d ',')
        
        echo "Device: $disk (${vendor_model:-Unknown})"
        echo "├── Size: ${size:-Unknown}"
        
        fdisk -l $disk 2>/dev/null | awk -v prefix="    " '
        /^\/dev/ {
            dev=$1; start=$2; end=$3; sectors=$4; size=$5; type=$6;
            if (type == "") type="Unknown";
            print prefix "├── Partition: " dev;
            print prefix "│   ├── Start: " start;
            print prefix "│   ├── End: " end;
            print prefix "│   ├── Sectors: " sectors;
            print prefix "│   ├── Size: " size;
            print prefix "│   └── Type: " type;
        }
        '
        echo "-----------------------------------------------------------"
    done
}

format_rate() {
    rate=$1
    if [ -z "$rate" ] || [ "$rate" -eq 0 ]; then
        echo "0 B/s"
    elif [ "$rate" -lt 1024 ]; then
        echo "${rate} B/s"
    elif [ "$rate" -lt 1048576 ]; then
        kb=$(expr $rate / 1024)
        echo "${kb} KB/s"
    else
        mb=$(expr $rate / 1048576)
        echo "${mb} MB/s"
    fi
}

cidr_to_netmask() {
    cidr=$1
    if [ -z "$cidr" ] || ! echo "$cidr" | grep -E '^[0-9]+$' >/dev/null 2>&1; then
        echo "255.255.255.0"
        return
    fi
    
    if [ "$cidr" -lt 0 ] || [ "$cidr" -gt 32 ]; then
        echo "255.255.255.0"
        return
    fi
    
    # Calculate netmask using bitwise operations
    mask=$((0xffffffff << (32 - $cidr) & 0xffffffff))
    o1=$((($mask >> 24) & 0xff))
    o2=$((($mask >> 16) & 0xff))
    o3=$((($mask >> 8) & 0xff))
    o4=$(($mask & 0xff))
    echo "$o1.$o2.$o3.$o4"
}

check_and_init_network() {
    # Check if already initialized
    init_flag=$(uci get fwx.global.cli_init 2>/dev/null)
    if [ "$init_flag" = "1" ]; then
        return 0
    fi
    
    # Wait for br-lan interface to be up (max 30 seconds)
    wait_time=0
    max_wait=30
    while [ $wait_time -lt $max_wait ]; do
        if ifconfig br-lan >/dev/null 2>&1; then
            break
        fi
        sleep 1
        wait_time=$(expr $wait_time + 1)
    done
    
    # Check if br-lan interface is up after waiting
    if ! ifconfig br-lan >/dev/null 2>&1; then
        echo "br-lan interface is not up after waiting ${max_wait} seconds, network may not be initialized yet."
        return 0
    fi
    
    # Check WAN configuration
    wan_proto=$(uci get network.wan.proto 2>/dev/null)
    if [ -z "$wan_proto" ]; then
        uci set network.lan.proto=dhcp
        uci commit network
        uci set fwx.global.cli_init=1
        uci set fwx.network.work_mode=1
        uci commit fwx
        /etc/init.d/network reload
		/etc/init.d/fwx restart >/dev/null 2>&1
    else
        uci set fwx.global.cli_init=1
        uci commit fwx
    fi
    
    return 0
}

monitor_clients() {
    page=1
    auto_refresh=0
    refresh_interval=3
    while true; do
        clear
        echo "=========================================="
        echo "  Online Client Monitor"
        echo "=========================================="
        echo ""
        read -p "Enter page number (1-100, default: 1, 'q' to return menu): " input_page
        
        if [ "$input_page" = "q" ] || [ "$input_page" = "Q" ]; then
            return
        fi
        
        if [ -z "$input_page" ]; then
            page=1
        else
            page=$input_page
        fi
        
        if ! echo "$page" | grep -E '^[0-9]+$' >/dev/null 2>&1; then
            echo "Error: Invalid page number, please enter a number between 1-100"
            sleep 2
            continue
        fi
        
        if [ "$page" -lt 1 ] || [ "$page" -gt 100 ]; then
            echo "Error: Page number must be between 1-100"
            sleep 2
            continue
        fi
        
        while true; do
            clear
            echo "=========================================="
            echo "  Online Client Monitor - Page $page"
            echo "=========================================="
            echo ""
            
            json_data=$(ubus call fwx common "{\"api\":\"get_all_users\",\"data\":{\"flag\":3,\"page\":$page,\"page_size\":20}}" 2>/dev/null)
            if [ $? -ne 0 ] || [ -z "$json_data" ]; then
                echo "Failed to get client data"
                sleep 2
                break
            fi
            # Check response code
            if command -v jsonfilter >/dev/null 2>&1; then
                response_code=$(echo "$json_data" | jsonfilter -e '@.code' 2>/dev/null)
                if [ "$response_code" != "2000" ]; then
                    echo "Error: API returned code $response_code"
                    sleep 2
                    break
                fi
            fi
            
            printf "%-18s %-16s %-12s %-12s %-40s\n" "MAC Address" "IP Address" "Up Rate" "Down Rate" "Current URL"
            echo "--------------------------------------------------------------------------------"
            
            online_count=0
            if command -v jsonfilter >/dev/null 2>&1; then
                list_length=$(echo "$json_data" | jsonfilter -e '@.data.total_num' 2>/dev/null)
                if [ -z "$list_length" ]; then
                    list_length=0
                fi
                
                i=0
                while [ $i -lt $list_length ] && [ $online_count -lt 20 ]; do
                    online=$(echo "$json_data" | jsonfilter -e "@.data.list[$i].online" 2>/dev/null)
                    if [ "$online" = "1" ]; then
                        mac=$(echo "$json_data" | jsonfilter -e "@.data.list[$i].mac" 2>/dev/null)
                        ip=$(echo "$json_data" | jsonfilter -e "@.data.list[$i].ip" 2>/dev/null)
                        up_rate=$(echo "$json_data" | jsonfilter -e "@.data.list[$i].up_rate" 2>/dev/null)
                        down_rate=$(echo "$json_data" | jsonfilter -e "@.data.list[$i].down_rate" 2>/dev/null)
                        url=$(echo "$json_data" | jsonfilter -e "@.data.list[$i].url" 2>/dev/null)
              
                        if [ -n "$mac" ]; then
                            up_rate_str=$(format_rate ${up_rate:-0})
                            down_rate_str=$(format_rate ${down_rate:-0})
                            
                            # Handle empty or null URL
                            if [ -z "$url" ] || [ "$url" = "null" ] || [ "$url" = "::" ]; then
                                url="--"
                            fi
                            
                            # Truncate long URLs
                            url_len=${#url}
                            if [ $url_len -gt 40 ]; then
                                url=$(echo "$url" | cut -c1-37)"..."
                            fi
                            
                            printf "%-18s %-16s %-12s %-12s %-40s\n" "$mac" "${ip:---}" "$up_rate_str" "$down_rate_str" "$url"
                            online_count=$(expr $online_count + 1)
                        fi
                    fi
                    i=$(expr $i + 1)
                done
            fi
            
            if [ $online_count -eq 0 ]; then
                echo "No online clients found on page $page"
                echo ""
                echo "Press any key to return to page selection..."
                read -n 1 key 2>/dev/null
                break
            fi
            
            total_num=$(echo "$json_data" | jsonfilter -e '@.data.total_num' 2>/dev/null)
            total_page=$(echo "$json_data" | jsonfilter -e '@.data.total_page' 2>/dev/null)
            
            echo ""
            if [ -n "$total_num" ] && [ -n "$total_page" ]; then
                echo "Page $page of $total_page (Total: $total_num online clients)"
            fi
            echo ""
            echo "Options:"
            echo "  [n] Next page"
            echo "  [p] Previous page"
            echo "  [g] Go to page"
            echo "  [r] Refresh current page"
            if [ $auto_refresh -eq 1 ]; then
                echo "  [a] Auto refresh: ON (${refresh_interval}s)"
            else
                echo "  [a] Auto refresh: OFF"
            fi
            echo "  [q] Return to menu"
            echo ""
            
            if [ $auto_refresh -eq 1 ]; then
                read -t $refresh_interval -p ">> " choice 2>/dev/null
                if [ $? -ne 0 ]; then
                    # Timeout, auto refresh
                    choice=""
                fi
            else
                read -p ">> " choice
            fi
            
            # If no input and auto refresh is on, refresh
            if [ -z "$choice" ] && [ $auto_refresh -eq 1 ]; then
                clear
                continue
            fi
            
            case "$choice" in
                n|N)
                    if [ -n "$total_page" ] && [ "$page" -lt "$total_page" ]; then
                        page=$(expr $page + 1)
                    else
                        echo "Already on last page"
                        sleep 1
                    fi
                    ;;
                p|P)
                    if [ "$page" -gt 1 ]; then
                        page=$(expr $page - 1)
                    else
                        echo "Already on first page"
                        sleep 1
                    fi
                    ;;
                g|G)
                    read -p "Enter page number (1-100): " new_page
                    if echo "$new_page" | grep -E '^[0-9]+$' >/dev/null 2>&1; then
                        if [ "$new_page" -ge 1 ] && [ "$new_page" -le 100 ]; then
                            page=$new_page
                        else
                            echo "Error: Page number must be between 1-100"
                            sleep 2
                        fi
                    else
                        echo "Error: Invalid page number"
                        sleep 2
                    fi
                    ;;
                r|R)
                    clear
                    continue
                    ;;
                a|A)
                    if [ $auto_refresh -eq 1 ]; then
                        auto_refresh=0
                        echo "Auto refresh disabled"
                        sleep 1
                    else
                        auto_refresh=1
                        echo "Auto refresh enabled (${refresh_interval}s interval)"
                        sleep 1
                    fi
                    continue
                    ;;
                q|Q)
                    return
                    ;;
                "")
                    # Empty input with auto refresh on, already handled above
                    continue
                    ;;
                *)
                    continue
                    ;;
            esac
        done
    done
}



validate_ip() {
    ip=$1
    echo "$ip" | grep -E -q '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    if [ $? -eq 0 ]; then
        octet1=$(echo "$ip" | cut -d '.' -f 1)
        octet2=$(echo "$ip" | cut -d '.' -f 2)
        octet3=$(echo "$ip" | cut -d '.' -f 3)
        octet4=$(echo "$ip" | cut -d '.' -f 4)

        if [ "$octet1" -ge 0 ] && [ "$octet1" -le 255 ] && \
           [ "$octet2" -ge 0 ] && [ "$octet2" -le 255 ] && \
           [ "$octet3" -ge 0 ] && [ "$octet3" -le 255 ] && \
           [ "$octet4" -ge 0 ] && [ "$octet4" -le 255 ]; then
		return 0
        else
		return 1
        fi
    else
	return 1
    fi
}

lan_static_ip_handle()
{
    read -p "Input IP(e.g:192.168.2.1)>>" ipaddr
    validate_ip $ipaddr
    if [ $? -ne 0 ];then
       echo "error,invalid ip addr"
       return 1;
    fi
   
    read -p "Input Netmask(default:255.255.255.0)>>" netmask
    validate_ip $netmask
    if [ $? -ne 0 ];then
        netmask="255.255.255.0"
    fi
    uci set network.lan.ipaddr=$ipaddr 
    uci set network.lan.netmask=$netmask
    uci set network.lan.proto=static
    uci commit network
    /etc/init.d/network reload
}
echo 0 >/proc/sys/kernel/printk
wait_time=0

# Check and initialize network if needed
check_and_init_network

utime=`cat /proc/uptime  | awk -F. '{print $1}'`
if [ $utime -lt 60 ];then
while true;do
	hostname=`cat /proc/sys/kernel/hostname`
	if [ x"$hostname" != x"(none)" ];then
		sleep 5
		break;
	fi
	sleep 1
	wait_time=`expr $wait_time + 1`
	if [ $wait_time -gt 15 ];then
		break;
	fi
done
fi
while true; do
    refresh_system_info
    usage
    read -t 5 -p ">> " choice 2>/dev/null
    if [ $? -ne 0 ]; then
        # Timeout, auto refresh
        choice=""
    fi
    
    # If no input, auto refresh
    if [ -z "$choice" ]; then
        continue
    fi
    
    case "$choice" in
        1)
            clear
            echo "Change LAN IP Proto to DHCP"
   	    read -p "Change the LAN port IP to DHCP? (y/n)" choice
	    if [ x"$choice" == x"y" -o x"$choice" == x"Y" ];then
             echo "begin reload network,waitting..."
	    uci set network.lan.proto=dhcp
	    uci commit network
	    /etc/init.d/network reload
		show_progress 3
	    echo "set lan proto to dhcp...ok"
            else
             echo "Cancelled..."
	    fi
            sleep 1
            ;;
        2)
            clear
            echo "Set LAN IP"
            lan_static_ip_handle 
	    show_progress 3
    	    echo "set lan ip ok, ip = $ipaddr, mask = $netmask"
            sleep 1
            ;;
        3)
            clear
            ifconfig
    	    read -p "Press any key to continue " choice
            ;;
        4)
            clear
            ps
    	    read -p "Press any key to continue " choice
            ;;
        5)
            monitor_clients
            ;;
        q)
            exit 0
            ;;
        *)
            ;;
    esac
done

