#!/usr/bin/lua
-- Copyright (C) 2026 destan19 <www.fanchmwrt.com>

local uci = require "uci"
local os = require "os"
local io = require "io"

local CHECK_INTERVAL = 10  
local LOG_FILE = "/tmp/log/rule_manager.log" 
local SINGLE_MAC_FILTER_RULE_ID = 101  

local APPFILTER_STATE_FILE = "/tmp/appfilter_rules_state"
local MACFILTER_STATE_FILE = "/tmp/macfilter_rules_state"
local APPFILTER_WHITELIST_STATE_FILE = "/tmp/appfilter_whitelist_state"
local MACFILTER_WHITELIST_STATE_FILE = "/tmp/macfilter_whitelist_state"

local appfilter_rules_state = {} 
local macfilter_rules_state = {}

local appfilter_enable_state = nil
local macfilter_enable_state = nil
local record_enable_state = nil  

local function ensure_log_dir()
    os.execute(string.format("mkdir -p %s", string.match(LOG_FILE, "^(.*)/")))
end

local function log(message)
    ensure_log_dir()
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    local log_msg = string.format("[%s] %s\n", timestamp, message)
	-- for debug
    --local file = io.open(LOG_FILE, "a")
    --if file then
    --   file:write(log_msg)
    --  file:close()
    --end
    print(log_msg)
end

local function get_current_time_info()
    local now = os.time()
    local date = os.date("*t", now)
    
    local weekday = date.wday - 1
    
    local current_minutes = date.hour * 60 + date.min
    
    return {
        weekday = weekday,
        hour = date.hour,
        min = date.min,
        minutes = current_minutes
    }
end

local function parse_time(time_str)
    if not time_str or time_str == "" then
        return nil
    end
    
    local hour, min = time_str:match("(%d+):(%d+)")
    if hour and min then
        return tonumber(hour) * 60 + tonumber(min)
    end
    return nil
end

local function is_time_in_range(time_rules, current_info)
    if not time_rules or #time_rules == 0 then
        return false
    end
    
    for _, time_rule in ipairs(time_rules) do
        if time_rule.weekdays and time_rule.start_time and time_rule.end_time then
            local weekday_match = false
            for _, wd in ipairs(time_rule.weekdays) do
                if wd == current_info.weekday then
                    weekday_match = true
                    break
                end
            end
            
            if weekday_match then
                local start_minutes = parse_time(time_rule.start_time)
                local end_minutes = parse_time(time_rule.end_time)
                
                if start_minutes and end_minutes then
                    if start_minutes <= end_minutes then
                        if current_info.minutes >= start_minutes and current_info.minutes <= end_minutes then
                            return true
                        end
                    else
                        if current_info.minutes >= start_minutes or current_info.minutes <= end_minutes then
                            return true
                        end
                    end
                end
            end
        end
    end
    
    return false
end

local function write_to_dev_fwx(json_str)
    local dev_file = "/dev/fwx"
    local check_cmd = string.format('test -e %s', dev_file)
    local check_result = os.execute(check_cmd)
    if check_result ~= 0 then
        log(string.format("WARNING: Device file %s does not exist, skipping", dev_file))
        return false
    end
    
    local file = io.open(dev_file, "w")
    if not file then
        log(string.format("ERROR: Failed to open %s for writing", dev_file))
        return false
    end
    
    file:write(json_str)
    file:close()
    return true
end

local function delete_appfilter_rule(rule_id)
    log(string.format("AppFilter: Deleting rule %d", rule_id))
    local json_str = string.format('{"api":"del_app_filter_rule","data":{"rule_id":%d}}', rule_id)
    if write_to_dev_fwx(json_str) then
        log(string.format("AppFilter: Rule %d deleted successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: Rule %d delete failed", rule_id))
        return false
    end
end

local function create_appfilter_rule(rule_id)
    log(string.format("AppFilter: Creating rule %d", rule_id))
    local json_str = string.format('{"api":"add_app_filter_rule","data":{"rule_id":%d}}', rule_id)
    if write_to_dev_fwx(json_str) then
        log(string.format("AppFilter: Rule %d created successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: Rule %d create failed", rule_id))
        return false
    end
end


local function set_appfilter_rule_mac_list(rule_id, mac_list)
    log(string.format("AppFilter: Setting MAC list for rule %d, count=%d", rule_id, #mac_list))
    
    local mac_array_str = ""
    if #mac_list > 0 then
        local mac_strs = {}
        for _, mac in ipairs(mac_list) do
            table.insert(mac_strs, string.format('"%s"', mac))
        end
        mac_array_str = "[" .. table.concat(mac_strs, ",") .. "]"
    else
        mac_array_str = "[]"
    end
    
    local json_str = string.format('{"api":"mod_app_filter_rule","data":{"rule_id":%d,"mac_action":1,"mac_list":%s}}', 
        rule_id, mac_array_str)
    if write_to_dev_fwx(json_str) then
        log(string.format("AppFilter: MAC list for rule %d set successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: MAC list for rule %d set failed", rule_id))
        return false
    end
end

local function set_appfilter_rule_app_id_list(rule_id, app_id_list)
    log(string.format("AppFilter: Setting App ID list for rule %d, count=%d", rule_id, #app_id_list))
    
    local app_id_array_str = ""
    if #app_id_list > 0 then
        local app_id_strs = {}
        for _, app_id in ipairs(app_id_list) do
            local token = tostring(app_id)
            token = token:gsub("\\", "\\\\"):gsub("\"", "\\\"")
            table.insert(app_id_strs, string.format('"%s"', token))
        end 
        app_id_array_str = "[" .. table.concat(app_id_strs, ",") .. "]"
    else
        app_id_array_str = "[]"
    end
    
    local json_str = string.format('{"api":"mod_app_filter_rule","data":{"rule_id":%d,"app_action":1,"app_id_list":%s}}', 
        rule_id, app_id_array_str)
    if write_to_dev_fwx(json_str) then
        log(string.format("AppFilter: App ID list for rule %d set successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: App ID list for rule %d set failed", rule_id))
        return false
    end
end

local function set_appfilter_rule_filter_quic(rule_id, filter_quic)
    local filter_quic_value = tonumber(filter_quic) or 0
    if filter_quic_value ~= 1 then
        filter_quic_value = 0
    end

    log(string.format("AppFilter: Setting filter_quic for rule %d, value=%d", rule_id, filter_quic_value))
    local json_str = string.format('{"api":"mod_app_filter_rule","data":{"rule_id":%d,"filter_quic":%d}}',
        rule_id, filter_quic_value)
    if write_to_dev_fwx(json_str) then
        log(string.format("AppFilter: filter_quic for rule %d set successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: filter_quic for rule %d set failed", rule_id))
        return false
    end
end

local function apply_macfilter_rule(rule_id, enable)
    log(string.format("MACFilter: apply_macfilter_rule called but enable field is no longer sent to kernel"))
    return true
end

local function create_macfilter_rule(rule_id)
    log(string.format("MACFilter: Creating rule %d", rule_id))
    local json_str = string.format('{"api":"add_mac_filter_rule","data":{"rule_id":%d}}', rule_id)
    if write_to_dev_fwx(json_str) then
        log(string.format("MACFilter: Rule %d created successfully", rule_id))
        return true
    else
        log(string.format("MACFilter: Rule %d create failed", rule_id))
        return false
    end
end

local function delete_macfilter_rule(rule_id)
    log(string.format("MACFilter: Deleting rule %d", rule_id))
    local json_str = string.format('{"api":"del_mac_filter_rule","data":{"rule_id":%d}}', rule_id)
    if write_to_dev_fwx(json_str) then
        log(string.format("MACFilter: Rule %d deleted successfully", rule_id))
        return true
    else
        log(string.format("MACFilter: Rule %d delete failed", rule_id))
        return false
    end
end

local function set_macfilter_rule_mac_list(rule_id, mac_list)
    log(string.format("MACFilter: Setting MAC list for rule %d, count=%d", rule_id, #mac_list))
    
    local clear_json = string.format('{"api":"mod_mac_filter_rule","data":{"rule_id":%d,"mac_action":0}}', rule_id)
    if not write_to_dev_fwx(clear_json) then
        log(string.format("MACFilter: Failed to clear MAC list for rule %d", rule_id))
        return false
    end
    
    if #mac_list == 0 then
        log(string.format("MACFilter: MAC list for rule %d cleared (empty list, no MACs to set)", rule_id))
        return true
    end
    
    local mac_strs = {}
    for _, mac in ipairs(mac_list) do
        table.insert(mac_strs, string.format('"%s"', mac))
    end
    local mac_array_str = "[" .. table.concat(mac_strs, ",") .. "]"
    
    local json_str = string.format('{"api":"mod_mac_filter_rule","data":{"rule_id":%d,"mac_action":1,"mac_list":%s}}', 
        rule_id, mac_array_str)
    if write_to_dev_fwx(json_str) then
        log(string.format("MACFilter: MAC list for rule %d set successfully", rule_id))
        return true
    else
        log(string.format("MACFilter: MAC list for rule %d set failed", rule_id))
        return false
    end
end

local function uci_get_all_sections(config, section_type)
    local sections = {}
    local cmd = string.format("uci show %s.@%s 2>/dev/null | grep -E '^%s\\.@%s\\[\\-?\\d+\\]'", config, section_type, config, section_type)
    local handle = io.popen(cmd)
    if not handle then
        return sections
    end
    
    local seen_ids = {}
    for line in handle:lines() do
        local section_path = line:match("^([^=]+)=")
        if section_path then
            local section_index = section_path:match("%[([%d%-]+)%]")
            if section_index then
                local index = tonumber(section_index)
                if index and index >= 0 and not seen_ids[index] then
                    seen_ids[index] = true
                    table.insert(sections, index)
                end
            end
        end
    end
    handle:close()
    
    table.sort(sections)
    return sections
end

local function load_appfilter_rules()
    log("=== Loading AppFilter rules from UCI ===")
    
    local uci_cursor = uci.cursor()
    local rules = {}
    
    uci_cursor:foreach("appfilter", "rule", function(section)
        local rule = {
            id = tonumber(section.id) or 0,
            name = section.name or "",
            mode = tonumber(section.mode) or 1,
            enabled = tonumber(section.enabled) or 1,
            filter_quic = tonumber(section.filter_quic) or 0,
            user_mac = section.user_mac or "",
            time_rules = {},
            app_ids = {}
        }
        
        if section.app_id then
            local app_ids = type(section.app_id) == "table" and section.app_id or {section.app_id}
            for _, app_id_token in ipairs(app_ids) do
                if app_id_token and app_id_token ~= "" then
                    table.insert(rule.app_ids, tostring(app_id_token))
                end
            end
        end
        
        if section.time_rule then
            local time_rules = type(section.time_rule) == "table" and section.time_rule or {section.time_rule}
            for _, time_rule_str in ipairs(time_rules) do
                if time_rule_str and time_rule_str ~= "" then
                    local parts = {}
                    for part in time_rule_str:gmatch("[^,]+") do
                        table.insert(parts, part)
                    end
                    
                    if #parts >= 3 then
                        local weekdays = {}
                        local start_time = nil
                        local end_time = nil
                        
                        for i, part in ipairs(parts) do
                            if part:match(":") then
                                if not start_time then
                                    start_time = part
                                else
                                    end_time = part
                                end
                            else
                                local wd = tonumber(part)
                                if wd then
                                    table.insert(weekdays, wd)
                                end
                            end
                        end
                        
                        if start_time and end_time and #weekdays > 0 then
                            table.insert(rule.time_rules, {
                                weekdays = weekdays,
                                start_time = start_time,
                                end_time = end_time
                            })
                        end
                    end
                end
            end
        end
        
        table.insert(rules, rule)
    end)
    
    uci_cursor:unload("appfilter")
    
    log(string.format("Loaded %d AppFilter rules", #rules))
    return rules
end

local function load_macfilter_rules()
    local uci_cursor = uci.cursor()
    local rules = {}
    
    uci_cursor:foreach("macfilter", "rule", function(section)
        local rule = {
            id = tonumber(section.id) or 0,
            name = section.name or "",
            mode = tonumber(section.mode) or 1,
            enabled = tonumber(section.enabled) or 1,
            user_mac = section.user_mac or "",
            time_rules = {}
        }
        
        if section.time_rule then
            local time_rules = type(section.time_rule) == "table" and section.time_rule or {section.time_rule}
            for _, time_rule_str in ipairs(time_rules) do
                if time_rule_str and time_rule_str ~= "" then
                    local parts = {}
                    for part in time_rule_str:gmatch("[^,]+") do
                        table.insert(parts, part)
                    end
                    
                    if #parts >= 3 then
                        local weekdays = {}
                        local start_time = nil
                        local end_time = nil
                        
                        for i, part in ipairs(parts) do
                            if part:match(":") then
                                if not start_time then
                                    start_time = part
                                else
                                    end_time = part
                                end
                            else
                                local wd = tonumber(part)
                                if wd then
                                    table.insert(weekdays, wd)
                                end
                            end
                        end
                        
                        if start_time and end_time and #weekdays > 0 then
                            table.insert(rule.time_rules, {
                                weekdays = weekdays,
                                start_time = start_time,
                                end_time = end_time
                            })
                        end
                    end
                end
            end
        end
        
        table.insert(rules, rule)
    end)
    
    uci_cursor:unload("macfilter")
    
    log(string.format("Loaded %d MACFilter rules", #rules))
    return rules
end

local function init_single_mac_rule()
    if create_macfilter_rule(SINGLE_MAC_FILTER_RULE_ID) then
        log("Single-user MACFilter rule initialized successfully")
        return true
    else
        log("Single-user MACFilter rule initialization failed")
        return false
    end
end

local function process_appfilter_rules(current_info)
    log(string.format("=== Processing AppFilter rules (time: %02d:%02d, weekday: %d) ===", 
        current_info.hour, current_info.min, current_info.weekday))
    
    local rules = load_appfilter_rules()
    
    for _, rule in ipairs(rules) do
        local time_match = is_time_in_range(rule.time_rules, current_info)
        local should_active = (rule.enabled == 1) and time_match
        local current_state = appfilter_rules_state[rule.id]
        local is_active = current_state and current_state.active or false
        
        log(string.format("AppFilter rule %d (%s): enabled=%d, time_match=%s, should_active=%s, is_active=%s", 
            rule.id, rule.name, rule.enabled, tostring(time_match), tostring(should_active), tostring(is_active)))
        
        if should_active then
            local mac_list = {}
            if rule.mode == 2 and rule.user_mac and rule.user_mac ~= "" then
                table.insert(mac_list, rule.user_mac)
            elseif rule.mode == 1 then
            end
            
            local app_id_list = rule.app_ids or {}
            
            local config_changed = false
            if not current_state then
                config_changed = true
            else
                if #mac_list ~= (current_state.mac_list and #current_state.mac_list or 0) then
                    config_changed = true
                else
                    local old_mac_set = {}
                    if current_state.mac_list then
                        for _, mac in ipairs(current_state.mac_list) do
                            old_mac_set[mac] = true
                        end
                    end
                    for _, mac in ipairs(mac_list) do
                        if not old_mac_set[mac] then
                            config_changed = true
                            break
                        end
                    end
                end
                
                if not config_changed then
                    if #app_id_list ~= (current_state.app_id_list and #current_state.app_id_list or 0) then
                        config_changed = true
                    else
                        local old_app_id_set = {}
                        if current_state.app_id_list then
                            for _, app_id in ipairs(current_state.app_id_list) do
                                old_app_id_set[app_id] = true
                            end
                        end
                        for _, app_id in ipairs(app_id_list) do
                            if not old_app_id_set[app_id] then
                                config_changed = true
                                break
                            end
                        end
                    end
                end

                if not config_changed then
                    if (tonumber(rule.filter_quic) or 0) ~= (tonumber(current_state.filter_quic) or 0) then
                        config_changed = true
                    end
                end
            end
            
            if not is_active or config_changed then
                if is_active then
                    log(string.format("AppFilter rule %d (%s): config changed, recreating", rule.id, rule.name))
                    delete_appfilter_rule(rule.id)
                else
                    log(string.format("AppFilter rule %d (%s): activating", rule.id, rule.name))
                end
                
                if create_appfilter_rule(rule.id) then
                    if not appfilter_rules_state[rule.id] then
                        appfilter_rules_state[rule.id] = {}
                    end
                    
                    if set_appfilter_rule_mac_list(rule.id, mac_list) then
                        appfilter_rules_state[rule.id].mac_list = mac_list
                    end
                    
                    if set_appfilter_rule_app_id_list(rule.id, app_id_list) then
                        appfilter_rules_state[rule.id].app_id_list = app_id_list
                    end

                    if set_appfilter_rule_filter_quic(rule.id, rule.filter_quic) then
                        appfilter_rules_state[rule.id].filter_quic = tonumber(rule.filter_quic) or 0
                    end
                    
                    appfilter_rules_state[rule.id].active = true
                    appfilter_rules_state[rule.id].name = rule.name
                    appfilter_rules_state[rule.id].mode = rule.mode
                    appfilter_rules_state[rule.id].enabled = rule.enabled
                    log(string.format("AppFilter rule %d: activated successfully", rule.id))
                end
            else
                log(string.format("AppFilter rule %d: no changes needed", rule.id))
            end
        else
            if is_active then
                log(string.format("AppFilter rule %d (%s): deactivating (enabled=%d, time_match=%s)", 
                    rule.id, rule.name, rule.enabled, tostring(time_match)))
                if delete_appfilter_rule(rule.id) then
                    appfilter_rules_state[rule.id].active = false
                    log(string.format("AppFilter rule %d: deactivated", rule.id))
                end
            end
        end
    end
    
    for rule_id, state in pairs(appfilter_rules_state) do
        local found = false
        for _, rule in ipairs(rules) do
            if rule.id == rule_id then
                found = true
                break
            end
        end
        if not found then
            if state.active then
                log(string.format("AppFilter rule %d: removed from UCI, deleting", rule_id))
                if delete_appfilter_rule(rule_id) then
                    appfilter_rules_state[rule_id] = nil
                end
            else
                appfilter_rules_state[rule_id] = nil
            end
        end
    end
end

local function process_macfilter_rules(current_info)
    log(string.format("=== Processing MACFilter rules (time: %02d:%02d, weekday: %d) ===", 
        current_info.hour, current_info.min, current_info.weekday))
    
    local rules = load_macfilter_rules()
    
    local all_user_rules = {}  
    local single_user_rules = {}
    
    for _, rule in ipairs(rules) do
        if rule.enabled == 1 then
            local should_active = is_time_in_range(rule.time_rules, current_info)
            if should_active then
                if rule.mode == 1 then
                    table.insert(all_user_rules, rule)
                elseif rule.mode == 2 then
                    table.insert(single_user_rules, rule)
                end
            end
        end
    end
    
    log(string.format("MACFilter: Found %d all-user rules, %d single-user rules (active)", 
        #all_user_rules, #single_user_rules))
    
    for _, rule in ipairs(all_user_rules) do
        local current_state = macfilter_rules_state[rule.id]
        local is_active = current_state and current_state.active or false
        
        if not is_active then
            log(string.format("MACFilter rule %d (%s): activating (all-user mode, mac_list=empty)", 
                rule.id, rule.name))
            
            if create_macfilter_rule(rule.id) then
                if set_macfilter_rule_mac_list(rule.id, {}) then
                    if not macfilter_rules_state[rule.id] then
                        macfilter_rules_state[rule.id] = {}
                    end
                    macfilter_rules_state[rule.id].active = true
                    macfilter_rules_state[rule.id].mode = 1
                    macfilter_rules_state[rule.id].name = rule.name
                    log(string.format("MACFilter rule %d: activated successfully", rule.id))
                end
            end
        end
    end
    
    local mac_set = {}
    for _, rule in ipairs(single_user_rules) do
        if rule.enabled == 1 and rule.user_mac and rule.user_mac ~= "" then
            mac_set[rule.user_mac] = true
        end
    end
    
    local mac_list = {}
    for mac, _ in pairs(mac_set) do
        table.insert(mac_list, mac)
    end
    
    log(string.format("MACFilter: Merging %d single-user rules (enabled) into single MAC rule, total MACs: %d", 
        #single_user_rules, #mac_list))
    
    local single_mac_state = macfilter_rules_state[SINGLE_MAC_FILTER_RULE_ID]
    local single_mac_active = single_mac_state and single_mac_state.active or false
    
    local mac_list_changed = true
    if single_mac_state and single_mac_state.mac_list then
        local old_mac_set = {}
        for _, mac in ipairs(single_mac_state.mac_list) do
            old_mac_set[mac] = true
        end
        
        if #mac_list == #single_mac_state.mac_list then
            mac_list_changed = false
            for _, mac in ipairs(mac_list) do
                if not old_mac_set[mac] then
                    mac_list_changed = true
                    break
                end
            end
        end
    end
    
    local need_update = false
    if single_mac_active then
        need_update = mac_list_changed
    else
        need_update = (#mac_list > 0) or mac_list_changed
    end
    
    if need_update then
        log(string.format("MACFilter single-user rule: updating (active=%s, mac_list_changed=%s, mac_count=%d)", 
            tostring(single_mac_active), tostring(mac_list_changed), #mac_list))
        
        if set_macfilter_rule_mac_list(SINGLE_MAC_FILTER_RULE_ID, mac_list) then
            if not macfilter_rules_state[SINGLE_MAC_FILTER_RULE_ID] then
                macfilter_rules_state[SINGLE_MAC_FILTER_RULE_ID] = {}
            end
            macfilter_rules_state[SINGLE_MAC_FILTER_RULE_ID].active = (#mac_list > 0)
            macfilter_rules_state[SINGLE_MAC_FILTER_RULE_ID].mode = 2
            macfilter_rules_state[SINGLE_MAC_FILTER_RULE_ID].mac_list = mac_list
            macfilter_rules_state[SINGLE_MAC_FILTER_RULE_ID].name = "Time-based MAC Filter (Single User)"
            if #mac_list > 0 then
                log("MACFilter single-user rule: updated successfully")
            else
                log("MACFilter single-user rule: cleared (no enabled single-user rules)")
            end
        end
    else
        log(string.format("MACFilter single-user rule: no changes needed (active=%s, mac_list_changed=%s, mac_count=%d), skipping update", 
            tostring(single_mac_active), tostring(mac_list_changed), #mac_list))
    end
    
    for rule_id, state in pairs(macfilter_rules_state) do
        if rule_id ~= SINGLE_MAC_FILTER_RULE_ID and state.mode == 1 then
            local found = false
            for _, rule in ipairs(all_user_rules) do
                if rule.id == rule_id then
                    found = true
                    break
                end
            end
            if not found and state.active then
                log(string.format("MACFilter rule %d: no longer active (enable=0 or time mismatch), deleting", rule_id))
                if delete_macfilter_rule(rule_id) then
                    macfilter_rules_state[rule_id] = nil
                    log(string.format("MACFilter rule %d: deleted successfully", rule_id))
                else
                    log(string.format("MACFilter rule %d: delete failed", rule_id))
                end
            end
        end
    end
    
    for rule_id, state in pairs(macfilter_rules_state) do
        if rule_id ~= SINGLE_MAC_FILTER_RULE_ID then
            local found = false
            for _, rule in ipairs(rules) do
                if rule.id == rule_id then
                    found = true
                    break
                end
            end
            if not found then
                log(string.format("MACFilter rule %d: removed from UCI, cleaning up state", rule_id))
                macfilter_rules_state[rule_id] = nil
            end
        end
    end
end

local function get_uci_enable(config, section, option)
    local uci_cursor = uci.cursor()
    local value = tonumber(uci_cursor:get(config, section, option)) or 0
    uci_cursor:unload(config)
    return value
end

local function apply_appfilter_enable(enable)
    log(string.format("=== Applying AppFilter enable: %d ===", enable))
    local proc_file = "/proc/sys/fwx/appfilter_enable"
    local file = io.open(proc_file, "w")
    if file then
        file:write(tostring(enable))
        file:close()
        log(string.format("AppFilter enable set to %d successfully", enable))
        return true
    else
        log(string.format("Failed to open %s for writing", proc_file))
        return false
    end
end

local function apply_macfilter_enable(enable)
    log(string.format("=== Applying MACFilter enable: %d ===", enable))
    local proc_file = "/proc/sys/fwx/macfilter_enable"
    local file = io.open(proc_file, "w")
    if file then
        file:write(tostring(enable))
        file:close()
        log(string.format("MACFilter enable set to %d successfully", enable))
        return true
    else
        log(string.format("Failed to open %s for writing", proc_file))
        return false
    end
end

local function check_and_apply_appfilter_enable()
    local current_enable = get_uci_enable("fwx", "appfilter", "enable")
    if appfilter_enable_state == nil or appfilter_enable_state ~= current_enable then
        log(string.format("AppFilter enable changed: %s -> %d", 
            appfilter_enable_state == nil and "nil" or tostring(appfilter_enable_state), current_enable))
        if apply_appfilter_enable(current_enable) then
            appfilter_enable_state = current_enable
        end
    end
end

local function check_and_apply_macfilter_enable()
    local current_enable = get_uci_enable("fwx", "macfilter", "enable")
    if macfilter_enable_state == nil or macfilter_enable_state ~= current_enable then
        log(string.format("MACFilter enable changed: %s -> %d", 
            macfilter_enable_state == nil and "nil" or tostring(macfilter_enable_state), current_enable))
        if apply_macfilter_enable(current_enable) then
            macfilter_enable_state = current_enable
        end
    end
end

local function apply_record_enable(enable)
    log(string.format("=== Applying Record enable: %d ===", enable))
    local proc_file = "/proc/sys/fwx/record_enable"
    local file = io.open(proc_file, "w")
    if file then
        file:write(tostring(enable))
        file:close()
        log(string.format("Record enable set to %d successfully", enable))
        return true
    else
        log(string.format("Failed to open %s for writing", proc_file))
        return false
    end
end

local function check_and_apply_record_enable()
    local current_enable = get_uci_enable("fwx", "record", "enable")
    if record_enable_state == nil or record_enable_state ~= current_enable then
        log(string.format("Record enable changed: %s -> %d", 
            record_enable_state == nil and "nil" or tostring(record_enable_state), current_enable))
        if apply_record_enable(current_enable) then
            record_enable_state = current_enable
        end
    end
end

local function check_state_file(file_path)
    local file = io.open(file_path, "r")
    if not file then
        return false
    end
    
    local content = file:read("*line")
    file:close()
    
    return (content == "1")
end

local function reset_state_file(file_path)
    local file = io.open(file_path, "w")
    if file then
        file:write("0")
        file:close()
        return true
    end
    return false
end

local function check_reinit_flags()
    local appfilter_reinit = check_state_file(APPFILTER_STATE_FILE)
    local macfilter_reinit = check_state_file(MACFILTER_STATE_FILE)
    local appfilter_whitelist_reinit = check_state_file(APPFILTER_WHITELIST_STATE_FILE)
    local macfilter_whitelist_reinit = check_state_file(MACFILTER_WHITELIST_STATE_FILE)
    
    return appfilter_reinit, macfilter_reinit, appfilter_whitelist_reinit, macfilter_whitelist_reinit
end

local function flush_appfilter_rules()
    log("=== Flushing AppFilter rules ===")
    local json_str = '{"api":"flush_app_filter_rule","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("AppFilter rules flushed successfully")
        return true
    else
        log("Failed to flush AppFilter rules")
        return false
    end
end

local function flush_macfilter_rules()
    log("=== Flushing MACFilter rules ===")
    local json_str = '{"api":"flush_mac_filter_rule","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("MACFilter rules flushed successfully")
        return true
    else
        log("Failed to flush MACFilter rules")
        return false
    end
end

local function flush_appfilter_whitelist()
    log("=== Flushing AppFilter whitelist ===")
    local json_str = '{"api":"flush_app_filter_whitelist","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("AppFilter whitelist flushed successfully")
        return true
    else
        log("Failed to flush AppFilter whitelist")
        return false
    end
end

local function flush_macfilter_whitelist()
    log("=== Flushing MACFilter whitelist ===")
    local json_str = '{"api":"flush_mac_filter_whitelist","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("MACFilter whitelist flushed successfully")
        return true
    else
        log("Failed to flush MACFilter whitelist")
        return false
    end
end

local function load_appfilter_whitelist()
    log("=== Loading AppFilter whitelist from UCI ===")
    
    local uci_cursor = uci.cursor()
    local mac_list = {}
    
    uci_cursor:foreach("appfilter_whitelist", "whitelist_mac", function(section)
        local mac = section.mac or ""
        if mac and mac ~= "" then
            table.insert(mac_list, mac)
        end
    end)
    
    uci_cursor:unload("appfilter_whitelist")
    
    log(string.format("AppFilter whitelist: loaded %d MAC addresses", #mac_list))
    return mac_list
end

local function load_macfilter_whitelist()
    log("=== Loading MACFilter whitelist from UCI ===")
    
    local uci_cursor = uci.cursor()
    local mac_list = {}
    
    uci_cursor:foreach("macfilter_whitelist", "whitelist_mac", function(section)
        local mac = section.mac or ""
        if mac and mac ~= "" then
            table.insert(mac_list, mac)
        end
    end)
    
    uci_cursor:unload("macfilter_whitelist")
    
    log(string.format("MACFilter whitelist: loaded %d MAC addresses", #mac_list))
    return mac_list
end

local function apply_appfilter_whitelist(mac_list)
    log(string.format("=== Applying AppFilter whitelist, count=%d ===", #mac_list))
    
    flush_appfilter_whitelist()
    
    if #mac_list > 0 then
        local mac_strs = {}
        for _, mac in ipairs(mac_list) do
            table.insert(mac_strs, string.format('"%s"', mac))
        end
        local mac_array_str = "[" .. table.concat(mac_strs, ",") .. "]"
        
        local json_str = string.format('{"api":"add_app_filter_whitelist","data":{"mac_list":%s}}', mac_array_str)
        if write_to_dev_fwx(json_str) then
            log(string.format("AppFilter whitelist applied successfully: %d MACs", #mac_list))
            return true
        else
            log("Failed to apply AppFilter whitelist")
            return false
        end
    else
        log("AppFilter whitelist is empty, no MACs to add")
        return true
    end
end

local function apply_macfilter_whitelist(mac_list)
    log(string.format("=== Applying MACFilter whitelist, count=%d ===", #mac_list))
    
    flush_macfilter_whitelist()
    
    if #mac_list > 0 then
        local mac_strs = {}
        for _, mac in ipairs(mac_list) do
            table.insert(mac_strs, string.format('"%s"', mac))
        end
        local mac_array_str = "[" .. table.concat(mac_strs, ",") .. "]"
        
        local json_str = string.format('{"api":"add_mac_filter_whitelist","data":{"mac_list":%s}}', mac_array_str)
        if write_to_dev_fwx(json_str) then
            log(string.format("MACFilter whitelist applied successfully: %d MACs", #mac_list))
            return true
        else
            log("Failed to apply MACFilter whitelist")
            return false
        end
    else
        log("MACFilter whitelist is empty, no MACs to add")
        return true
    end
end

local function interruptible_sleep(seconds)
    for i = 1, seconds do
        local result = os.execute("sleep 1")
        if result ~= 0 and result ~= true then
            return
        end
    end
end

local function flush_all_rules()
    log("=== Flushing all rules before initialization ===")
    
    local json_str = '{"api":"flush_mac_filter_rule","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("MAC filter rules flushed")
    else
        log("Failed to flush MAC filter rules")
    end
    
    json_str = '{"api":"flush_app_filter_rule","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("App filter rules flushed")
    else
        log("Failed to flush App filter rules")
    end
    
    json_str = '{"api":"flush_mac_filter_whitelist","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("MAC filter whitelist flushed")
    else
        log("Failed to flush MAC filter whitelist")
    end
    
    json_str = '{"api":"flush_app_filter_whitelist","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("App filter whitelist flushed")
    else
        log("Failed to flush App filter whitelist")
    end
    
    log("All rules flushed successfully")
    return true
end

local function initialize_rules()
    flush_all_rules()
    check_and_apply_appfilter_enable()
    check_and_apply_macfilter_enable()
    check_and_apply_record_enable()  
    
    init_single_mac_rule()
    
    local appfilter_rules = load_appfilter_rules()
    for _, rule in ipairs(appfilter_rules) do
        appfilter_rules_state[rule.id] = {
            active = false,
            name = rule.name,
            mode = rule.mode,
            filter_quic = tonumber(rule.filter_quic) or 0
        }
    end
    
    local macfilter_rules = load_macfilter_rules()
    for _, rule in ipairs(macfilter_rules) do
        macfilter_rules_state[rule.id] = {
            active = false,
            mode = rule.mode,
            name = rule.name,
            user_mac = rule.user_mac
        }
    end
    
    log(string.format("Initialized: %d AppFilter rules, %d MACFilter rules", 
        #appfilter_rules, #macfilter_rules))
    
    log("=== Loading whitelists ===")
    local appfilter_whitelist = load_appfilter_whitelist()
    apply_appfilter_whitelist(appfilter_whitelist)
    
    local macfilter_whitelist = load_macfilter_whitelist()
    apply_macfilter_whitelist(macfilter_whitelist)
    
    log("Whitelists initialized successfully")
end

local function main_loop()
    log("Rule manager started")
    
    initialize_rules()
    
    local running = true
    
    while running do
        local appfilter_reinit, macfilter_reinit, appfilter_whitelist_reinit, macfilter_whitelist_reinit = check_reinit_flags()
        
        if appfilter_whitelist_reinit then
            log("=== AppFilter whitelist state file detected change, reloading ===")
            local appfilter_whitelist = load_appfilter_whitelist()
            apply_appfilter_whitelist(appfilter_whitelist)
            if reset_state_file(APPFILTER_WHITELIST_STATE_FILE) then
                log("AppFilter whitelist state file reset to 0")
            else
                log("Failed to reset AppFilter whitelist state file")
            end
        end
        
        if macfilter_whitelist_reinit then
            log("=== MACFilter whitelist state file detected change, reloading ===")
            local macfilter_whitelist = load_macfilter_whitelist()
            apply_macfilter_whitelist(macfilter_whitelist)
            if reset_state_file(MACFILTER_WHITELIST_STATE_FILE) then
                log("MACFilter whitelist state file reset to 0")
            else
                log("Failed to reset MACFilter whitelist state file")
            end
        end
        
        if appfilter_reinit then
            log("=== AppFilter rules state file detected change, reinitializing ===")
            flush_appfilter_rules()
            
            check_and_apply_appfilter_enable()
            
            appfilter_rules_state = {}
            local appfilter_rules = load_appfilter_rules()
            for _, rule in ipairs(appfilter_rules) do
                appfilter_rules_state[rule.id] = {
                    active = false,
                    name = rule.name,
                    mode = rule.mode,
                    filter_quic = tonumber(rule.filter_quic) or 0
                }
            end
            log(string.format("AppFilter rules reinitialized: %d rules", #appfilter_rules))
            if reset_state_file(APPFILTER_STATE_FILE) then
                log("AppFilter state file reset to 0")
            else
                log("Failed to reset AppFilter state file")
            end
        end
        
        if macfilter_reinit then
            flush_macfilter_rules()
            
            check_and_apply_macfilter_enable()
            
            init_single_mac_rule()
            macfilter_rules_state = {}
            local macfilter_rules = load_macfilter_rules()
            for _, rule in ipairs(macfilter_rules) do
                macfilter_rules_state[rule.id] = {
                    active = false,
                    mode = rule.mode,
                    name = rule.name,
                    user_mac = rule.user_mac
                }
            end
            log(string.format("MACFilter rules reinitialized: %d rules", #macfilter_rules))
            if reset_state_file(MACFILTER_STATE_FILE) then
                log("MACFilter state file reset to 0")
            else
                log("Failed to reset MACFilter state file")
            end
        end
        
        local current_info = get_current_time_info()
        
        local ok, err = pcall(function()
            process_appfilter_rules(current_info)
            process_macfilter_rules(current_info)
        end)
        
        if not ok then
            log("ERROR processing rules: " .. tostring(err))
        end
        interruptible_sleep(CHECK_INTERVAL)
    end
end

if arg[0] and arg[0]:match("rule_manager") then
    main_loop()
end
