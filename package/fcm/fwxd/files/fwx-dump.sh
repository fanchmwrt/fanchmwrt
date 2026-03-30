#!/bin/sh
# fwx-dump.sh - Dump kernel module configurations via /dev/fwx

DEV_FILE="/dev/fwx"

check_device() {
	if [ ! -e "$DEV_FILE" ]; then
		echo "Error: Device file $DEV_FILE does not exist" >&2
		return 1
	fi
	return 0
}

send_json() {
	local json_str="$1"
	
	if ! check_device; then
		return 1
	fi
	
	echo "$json_str" > "$DEV_FILE" 2>/dev/null
	if [ $? -ne 0 ]; then
		echo "Error: Failed to write to $DEV_FILE" >&2
		return 1
	fi

	return 0
}

dump_appfilter() {
	local json='{"api":"dump_app_filter_rule","data":{}}'
	
	echo "Dumping AppFilter rules..."
	if send_json "$json"; then
		echo "AppFilter dump command sent successfully"
		echo "Check kernel logs with: dmesg | tail -n 50"
		return 0
	else
		return 1
	fi
}

dump_macfilter() {
	local json='{"api":"dump_mac_filter_rule","data":{}}'
	
	echo "Dumping MACFilter rules..."
	if send_json "$json"; then
		echo "MACFilter dump command sent successfully"
		echo "Check kernel logs with: dmesg | tail -n 50"
		return 0
	else
		return 1
	fi
}

usage() {
	echo "Usage: $0 <command>"
	echo ""
	echo "Commands:"
	echo "  appfilter    Dump AppFilter rules from kernel"
	echo "  macfilter    Dump MACFilter rules from kernel"
	echo "  help         Show this help message"
	echo ""
	echo "Examples:"
	echo "  $0 appfilter"
	echo "  $0 macfilter"
}

main() {
	case "$1" in
		appfilter)
			dump_appfilter
			;;
		macfilter)
			dump_macfilter
			;;
		help|--help|-h)
			usage
			;;
		*)
			if [ -z "$1" ]; then
				usage
			else
				echo "Error: Unknown command '$1'" >&2
				usage
				exit 1
			fi
			;;
	esac
}

main "$@"

