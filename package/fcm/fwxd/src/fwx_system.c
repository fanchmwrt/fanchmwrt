
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#include <uci.h>
#include "fwx.h"
#include "fwx_user.h"
#include "fwx_netlink.h"
#include "fwx_ubus.h"
#include "fwx_config.h"
#include "fwx_utils.h"
#include "fwx_uci.h"

struct json_object *fwx_api_get_system_info(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    struct json_object *fwx_obj = json_object_new_object();
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        json_object_put(fwx_obj);
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    char lan_ifname[32] = {0};
    int ret = fwx_uci_get_value(uci_ctx, "fwx.global.lan_ifname", lan_ifname, sizeof(lan_ifname) - 1);
    if (ret != 0) {
        strncpy(lan_ifname, "br-lan", sizeof(lan_ifname) - 1);
    }
    
    char theme_mode_str[8] = {0};
    int theme_mode = 0; // 默认值为0（light）
    ret = fwx_uci_get_value(uci_ctx, "fwx.global.theme_mode", theme_mode_str, sizeof(theme_mode_str) - 1);
    if (ret == 0) {
        theme_mode = atoi(theme_mode_str);
    }
    
    json_object_object_add(fwx_obj, "lan_ifname", json_object_new_string(lan_ifname));
    json_object_object_add(fwx_obj, "theme_mode", json_object_new_int(theme_mode));
    json_object_object_add(data_obj, "fwx", fwx_obj);
    uci_free_context(uci_ctx);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_set_system_info(struct json_object *req_obj) {
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *fwx_obj = json_object_object_get(req_obj, "fwx");
    if (!fwx_obj) {
        LOG_ERROR("Missing fwx parameter\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *lan_ifname_obj = json_object_object_get(fwx_obj, "lan_ifname");
    if (!lan_ifname_obj) {
        LOG_ERROR("Missing lan_ifname parameter\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *lan_ifname = json_object_get_string(lan_ifname_obj);
    if (!lan_ifname || strlen(lan_ifname) == 0) {
        LOG_ERROR("Invalid lan_ifname value\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    if (strlen(lan_ifname) < 2 || strlen(lan_ifname) > 16) {
        LOG_ERROR("lan_ifname length invalid\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *theme_mode_obj = json_object_object_get(fwx_obj, "theme_mode");
    int theme_mode = 0; // 默认值为0（light）
    if (theme_mode_obj) {
        if (json_object_get_type(theme_mode_obj) == json_type_int) {
            theme_mode = json_object_get_int(theme_mode_obj);
        } else if (json_object_get_type(theme_mode_obj) == json_type_string) {
            theme_mode = atoi(json_object_get_string(theme_mode_obj));
        }
        // 验证值只能是0或1
        if (theme_mode != 0 && theme_mode != 1) {
            LOG_ERROR("Invalid theme_mode value, must be 0 or 1\n");
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    }
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    fwx_uci_set_value(uci_ctx, "fwx.global.lan_ifname", (char *)lan_ifname);
    
    char theme_mode_str[8] = {0};
    snprintf(theme_mode_str, sizeof(theme_mode_str), "%d", theme_mode);
    fwx_uci_set_value(uci_ctx, "fwx.global.theme_mode", theme_mode_str);
    
    fwx_uci_commit(uci_ctx, "fwx");
	
	update_fwx_proc_value("lan_ifname", lan_ifname);
    
    uci_free_context(uci_ctx);
    LOG_DEBUG("Set system config: lan_ifname=%s, theme_mode=%d\n", lan_ifname, theme_mode);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}
