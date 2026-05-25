#!/bin/sh

APP_ROOT="/fwx_data/app_list"
APP_CACHE_ROOT="/fwx_data/app_center/cache_data"
ICON_WEB_ROOT="/www/luci-static/resources/app_center"
BOOT_CODE_OK="2000"
BOOT_CODE_KERNEL_MISMATCH="4001"
BOOT_CODE_FW_MISMATCH="4002"
BOOT_CODE_UNKNOWN="4003"

read_first_line() {
	local file="$1"
	[ -f "$file" ] || return 1
	sed -n '1p' "$file" | tr -d '\r\n'
}

write_boot_code() {
	local app_dir="$1"
	local code="$2"
	echo "$code" > "$app_dir/boot_data"
}

version_is_valid() {
	local v="$1"
	echo "$v" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'
}

version_check_disabled() {
	local v="$1"
	[ -z "$v" ] && return 0
	[ "$v" = "0.0.0" ] && return 0
	return 1
}

version_ge() {
	local a="$1"
	local b="$2"
	local a1 a2 a3 b1 b2 b3
	a1=$(echo "$a" | awk -F'.' '{print $1}')
	a2=$(echo "$a" | awk -F'.' '{print $2}')
	a3=$(echo "$a" | awk -F'.' '{print $3}')
	b1=$(echo "$b" | awk -F'.' '{print $1}')
	b2=$(echo "$b" | awk -F'.' '{print $2}')
	b3=$(echo "$b" | awk -F'.' '{print $3}')
	if [ "$a1" -gt "$b1" ]; then return 0; fi
	if [ "$a1" -lt "$b1" ]; then return 1; fi
	if [ "$a2" -gt "$b2" ]; then return 0; fi
	if [ "$a2" -lt "$b2" ]; then return 1; fi
	if [ "$a3" -ge "$b3" ]; then return 0; fi
	return 1
}

current_kernel="$(uname -r 2>/dev/null | tr -d '\r\n')"
fw_raw="$(read_first_line /etc/fwx_version)"
current_fw="$fw_raw"

[ -d "$APP_ROOT" ] || exit 0

for app_dir in "$APP_ROOT"/*; do
	[ -d "$app_dir" ] || continue
	app_name="$(basename "$app_dir")"

	icon_src="$APP_CACHE_ROOT/$app_name/icon.png"
	if [ -f "$icon_src" ]; then
		icon_web_dir="$ICON_WEB_ROOT/$app_name"
		icon_link="$icon_web_dir/icon.png"
		[ -d "$icon_web_dir" ] || mkdir -p "$icon_web_dir"
		if [ ! -L "$icon_link" ] || [ ! -e "$icon_link" ]; then
			rm -rf "$icon_link"
			ln -sf "$icon_src" "$icon_link"
		fi
	fi

	required_kernel="$(read_first_line "$app_dir/required_kernel_version")"
	required_min_fw="$(read_first_line "$app_dir/required_min_fw_version")"

	if [ -z "$current_kernel" ]; then
		write_boot_code "$app_dir" "$BOOT_CODE_UNKNOWN"
		continue
	fi

	if ! version_check_disabled "$required_kernel" && [ "$current_kernel" != "$required_kernel" ]; then
		write_boot_code "$app_dir" "$BOOT_CODE_KERNEL_MISMATCH"
		continue
	fi

	if ! version_check_disabled "$required_min_fw"; then
		if ! version_is_valid "$required_min_fw" || ! version_is_valid "$current_fw"; then
			write_boot_code "$app_dir" "$BOOT_CODE_UNKNOWN"
			continue
		fi
		if ! version_ge "$current_fw" "$required_min_fw"; then
			write_boot_code "$app_dir" "$BOOT_CODE_FW_MISMATCH"
			continue
		fi
	fi

	write_boot_code "$app_dir" "$BOOT_CODE_OK"

	init_sh="$app_dir/init.sh"
	[ -f "$init_sh" ] || continue

	$init_sh start
done

exit 0
