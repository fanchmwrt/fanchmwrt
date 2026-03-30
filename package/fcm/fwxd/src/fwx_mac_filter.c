// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include "fwx_user.h"
#include "fwx_netlink.h"
#include "fwx_ubus.h"
#include "fwx_config.h"
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "fwx.h"
#include <stdio.h>
#include <json-c/json.h>
#include "fwx_utils.h"
#include "fwx_mac_filter.h"


#define MACFILTER_RULES_STATE_FILE "/tmp/macfilter_rules_state"
#define MACFILTER_WHITELIST_STATE_FILE "/tmp/macfilter_whitelist_state"


static void set_state_file(const char *file_path) {
    FILE *fd = fopen(file_path, "w");
    if (fd) {
        fprintf(fd, "1");
        fclose(fd);
        LOG_DEBUG("Set state file: %s\n", file_path);
    } else {
        LOG_ERROR("Failed to set state file: %s\n", file_path);
    }
}


static int find_mac_filter_rule_index_by_id(struct uci_context *uci_ctx, int id) {
	int i;
    char id_str_uci[32];
    int num = fwx_uci_get_list_num(uci_ctx, "macfilter", "rule");
    for (i = 0; i < num; i++) {
        char buf[128];
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].id", i);
        if (fwx_uci_get_value(uci_ctx, buf, id_str_uci, sizeof(id_str_uci)) != 0) {
            continue;
        }
        if (atoi(id_str_uci) == id) {
            return i;
        }
    }
    return -1; // Not found
}


struct json_object *fwx_api_get_mac_filter_rules(struct json_object *req_obj) {
    int i;
    struct json_object *data_obj = json_object_new_object();
    struct json_object *rules_array = json_object_new_array();
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    int num = fwx_uci_get_list_num(uci_ctx, "macfilter", "rule");
    LOG_DEBUG("Found %d rules in macfilter\n", num);
    
    for (i = 0; i < num; i++) {
        char buf[256];
        char name_str[128] = {0};
        char mode_str[16] = {0};
        char user_mac_str[32] = {0};
        char user_name_str[128] = {0};
        char enabled_str[16] = {0};
        char id_str[32] = {0};
        

        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].id", i);
        if (fwx_uci_get_value(uci_ctx, buf, id_str, sizeof(id_str)) != 0) {
            LOG_ERROR("Failed to get id for rule[%d], skipping\n", i);
            continue; 
        }
        
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].name", i);
        fwx_uci_get_value(uci_ctx, buf, name_str, sizeof(name_str));
        
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].mode", i);
        if (fwx_uci_get_value(uci_ctx, buf, mode_str, sizeof(mode_str)) != 0) {
            strcpy(mode_str, "1");
        }
        
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].user_mac", i);
        fwx_uci_get_value(uci_ctx, buf, user_mac_str, sizeof(user_mac_str));
        
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].user_name", i);
        fwx_uci_get_value(uci_ctx, buf, user_name_str, sizeof(user_name_str)); 
        
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].enabled", i);
        if (fwx_uci_get_value(uci_ctx, buf, enabled_str, sizeof(enabled_str)) != 0) {
            strcpy(enabled_str, "1"); 
        }
        
        struct json_object *rule_obj = json_object_new_object();
        if (!rule_obj) {
            LOG_ERROR("Failed to create rule_obj for rule[%d]\n", i);
            continue;
        }
        
        json_object_object_add(rule_obj, "id", json_object_new_int(atoi(id_str)));
        json_object_object_add(rule_obj, "name", json_object_new_string(name_str));
        json_object_object_add(rule_obj, "mode", json_object_new_int(atoi(mode_str)));
        json_object_object_add(rule_obj, "user_mac", json_object_new_string(user_mac_str));
        json_object_object_add(rule_obj, "user_name", json_object_new_string(user_name_str));
        json_object_object_add(rule_obj, "enabled", json_object_new_int(atoi(enabled_str)));
        

        struct json_object *time_rules_array = json_object_new_array();
        char time_rule_list_buf[1024] = {0};
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_rule", i);
        if (fwx_uci_get_list_value(uci_ctx, buf, time_rule_list_buf, sizeof(time_rule_list_buf), " ") == 0) {

            char *p = strtok(time_rule_list_buf, " ");
            while (p) {
                struct json_object *time_rule_obj = json_object_new_object();
                struct json_object *weekdays_array = json_object_new_array();
                

                char *saveptr;
                char *token = strtok_r(p, ",", &saveptr);
                char *start_time = NULL;
                char *end_time = NULL;
                

                while (token) {

                    if (strchr(token, ':') != NULL) {

                        if (start_time == NULL) {
                            start_time = token;
                        } else if (end_time == NULL) {
                            end_time = token;
                            break; 
                        }
                    } else {

                        int weekday = atoi(token);
                        if (weekday >= 0 && weekday <= 6) {
                            json_object_array_add(weekdays_array, json_object_new_int(weekday));
                        }
                    }
                    token = strtok_r(NULL, ",", &saveptr);
                }
                

                if (start_time) {
                    json_object_object_add(time_rule_obj, "start_time", json_object_new_string(start_time));
                }
                if (end_time) {
                    json_object_object_add(time_rule_obj, "end_time", json_object_new_string(end_time));
                }
                
                json_object_object_add(time_rule_obj, "weekdays", weekdays_array);
                json_object_array_add(time_rules_array, time_rule_obj);
                
                p = strtok(NULL, " ");
            }
        }
        json_object_object_add(rule_obj, "time_rules", time_rules_array);
        
        json_object_array_add(rules_array, rule_obj);
        LOG_DEBUG("Successfully loaded macfilter rule[%d]: id=%s, name=%s\n", i, id_str, name_str);
    }
    
    json_object_object_add(data_obj, "list", rules_array);
    uci_free_context(uci_ctx);
    
    LOG_DEBUG("Returning %d macfilter rules\n", json_object_array_length(rules_array));

    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_add_mac_filter_rule(struct json_object *req_obj) {
    struct json_object *name_obj = json_object_object_get(req_obj, "name");
    struct json_object *mode_obj = json_object_object_get(req_obj, "mode");
    struct json_object *user_mac_obj = json_object_object_get(req_obj, "user_mac");
    struct json_object *user_name_obj = json_object_object_get(req_obj, "user_name");
    struct json_object *enabled_obj = json_object_object_get(req_obj, "enabled");
    struct json_object *time_rules_obj = json_object_object_get(req_obj, "time_rules");
	int i, j;
    
    if (!name_obj || !mode_obj || !time_rules_obj) {
        LOG_ERROR("Missing required fields\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    int rule_id = (int)time(NULL);
    

    fwx_uci_add_section(uci_ctx, "macfilter", "rule");
    
    char buf[256];
    snprintf(buf, sizeof(buf), "macfilter.@rule[-1].id");
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", rule_id);
    fwx_uci_set_value(uci_ctx, buf, id_str);
    
    snprintf(buf, sizeof(buf), "macfilter.@rule[-1].name");
    fwx_uci_set_value(uci_ctx, buf, json_object_get_string(name_obj));
    
    snprintf(buf, sizeof(buf), "macfilter.@rule[-1].mode");
    char mode_str[16];
    snprintf(mode_str, sizeof(mode_str), "%d", json_object_get_int(mode_obj));
    fwx_uci_set_value(uci_ctx, buf, mode_str);
    
    if (user_mac_obj) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[-1].user_mac");
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(user_mac_obj));
    }
    
    if (user_name_obj) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[-1].user_name");
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(user_name_obj));
    }
    
    snprintf(buf, sizeof(buf), "macfilter.@rule[-1].enabled");
    char enabled_str[16];
    int enabled = enabled_obj ? json_object_get_int(enabled_obj) : 1;
    snprintf(enabled_str, sizeof(enabled_str), "%d", enabled);
    fwx_uci_set_value(uci_ctx, buf, enabled_str);
    

    int time_rules_len = json_object_array_length(time_rules_obj);
    for (i = 0; i < time_rules_len; i++) {
        struct json_object *time_rule_obj = json_object_array_get_idx(time_rules_obj, i);
        struct json_object *weekdays_obj = json_object_object_get(time_rule_obj, "weekdays");
        struct json_object *start_time_obj = json_object_object_get(time_rule_obj, "start_time");
        struct json_object *end_time_obj = json_object_object_get(time_rule_obj, "end_time");
        
        if (!weekdays_obj || !start_time_obj || !end_time_obj) {
            continue;
        }
        

        char time_rule_str[256] = {0};
        int weekdays_len = json_object_array_length(weekdays_obj);
        for (j = 0; j < weekdays_len; j++) {
            struct json_object *weekday_obj = json_object_array_get_idx(weekdays_obj, j);
            char weekday_str[16];
            snprintf(weekday_str, sizeof(weekday_str), "%d", json_object_get_int(weekday_obj));
            if (j > 0) strcat(time_rule_str, ",");
            strcat(time_rule_str, weekday_str);
        }
        strcat(time_rule_str, ",");
        strcat(time_rule_str, json_object_get_string(start_time_obj));
        strcat(time_rule_str, ",");
        strcat(time_rule_str, json_object_get_string(end_time_obj));
        
        snprintf(buf, sizeof(buf), "macfilter.@rule[-1].time_rule");
        fwx_uci_add_list(uci_ctx, buf, time_rule_str);
    }
    
    fwx_uci_commit(uci_ctx, "macfilter");
    uci_free_context(uci_ctx);
    

    set_state_file(MACFILTER_RULES_STATE_FILE);
    
    LOG_DEBUG("Added macfilter rule: id=%d, name=%s\n", rule_id, json_object_get_string(name_obj));
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *fwx_api_update_mac_filter_rule(struct json_object *req_obj) {
	int i, j;
    struct json_object *id_obj = json_object_object_get(req_obj, "id");
    if (!id_obj) {
        LOG_ERROR("Missing id field\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int rule_id = json_object_get_int(id_obj);
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int index = find_mac_filter_rule_index_by_id(uci_ctx, rule_id);
    if (index < 0) {
        LOG_ERROR("Rule not found: id=%d\n", rule_id);
        uci_free_context(uci_ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    char buf[256];
    

    struct json_object *name_obj = json_object_object_get(req_obj, "name");
    if (name_obj) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].name", index);
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(name_obj));
    }
    
    struct json_object *mode_obj = json_object_object_get(req_obj, "mode");
    if (mode_obj) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].mode", index);
        char mode_str[16];
        snprintf(mode_str, sizeof(mode_str), "%d", json_object_get_int(mode_obj));
        fwx_uci_set_value(uci_ctx, buf, mode_str);
    }
    
    struct json_object *user_mac_obj = json_object_object_get(req_obj, "user_mac");
    if (user_mac_obj) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].user_mac", index);
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(user_mac_obj));
    }
    
    struct json_object *user_name_obj = json_object_object_get(req_obj, "user_name");
    if (user_name_obj) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].user_name", index);
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(user_name_obj));
    }
    
    struct json_object *enabled_obj = json_object_object_get(req_obj, "enabled");
    if (enabled_obj) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].enabled", index);
        char enabled_str[16];
        snprintf(enabled_str, sizeof(enabled_str), "%d", json_object_get_int(enabled_obj));
        fwx_uci_set_value(uci_ctx, buf, enabled_str);
    }
    

    snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_rule", index);
    fwx_uci_delete(uci_ctx, buf);
    

    struct json_object *time_rules_obj = json_object_object_get(req_obj, "time_rules");
    if (time_rules_obj) {
        int time_rules_len = json_object_array_length(time_rules_obj);
        for (i = 0; i < time_rules_len; i++) {
            struct json_object *time_rule_obj = json_object_array_get_idx(time_rules_obj, i);
            struct json_object *weekdays_obj = json_object_object_get(time_rule_obj, "weekdays");
            struct json_object *start_time_obj = json_object_object_get(time_rule_obj, "start_time");
            struct json_object *end_time_obj = json_object_object_get(time_rule_obj, "end_time");
            
            if (!weekdays_obj || !start_time_obj || !end_time_obj) {
                continue;
            }
            
            char time_rule_str[256] = {0};
            int weekdays_len = json_object_array_length(weekdays_obj);
            for (j = 0; j < weekdays_len; j++) {
                struct json_object *weekday_obj = json_object_array_get_idx(weekdays_obj, j);
                char weekday_str[16];
                snprintf(weekday_str, sizeof(weekday_str), "%d", json_object_get_int(weekday_obj));
                if (j > 0) strcat(time_rule_str, ",");
                strcat(time_rule_str, weekday_str);
            }
            strcat(time_rule_str, ",");
            strcat(time_rule_str, json_object_get_string(start_time_obj));
            strcat(time_rule_str, ",");
            strcat(time_rule_str, json_object_get_string(end_time_obj));
            
            snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_rule", index);
            fwx_uci_add_list(uci_ctx, buf, time_rule_str);
        }
    }
    
    fwx_uci_commit(uci_ctx, "macfilter");
    uci_free_context(uci_ctx);
    

    set_state_file(MACFILTER_RULES_STATE_FILE);
    
    LOG_DEBUG("Updated macfilter rule: id=%d\n", rule_id);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *fwx_api_delete_mac_filter_rule(struct json_object *req_obj) {
    struct json_object *id_obj = json_object_object_get(req_obj, "id");
    if (!id_obj) {
        LOG_ERROR("Missing id field\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int rule_id = json_object_get_int(id_obj);
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int index = find_mac_filter_rule_index_by_id(uci_ctx, rule_id);
    if (index < 0) {
        LOG_ERROR("Rule not found: id=%d\n", rule_id);
        uci_free_context(uci_ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    char buf[128];
    snprintf(buf, sizeof(buf), "macfilter.@rule[%d]", index);
    fwx_uci_delete(uci_ctx, buf);
    
    fwx_uci_commit(uci_ctx, "macfilter");
    uci_free_context(uci_ctx);
    

    set_state_file(MACFILTER_RULES_STATE_FILE);
    
    LOG_DEBUG("Deleted macfilter rule: id=%d\n", rule_id);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *fwx_api_get_mac_filter_whitelist(struct json_object *req_obj) {
	int i;
    struct json_object *data_obj = json_object_new_object();
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    struct json_object *mac_array = json_object_new_array();
    char mac_str[128] = {0};
    int num = fwx_uci_get_list_num(uci_ctx, "macfilter_whitelist", "whitelist_mac");
    for (i = 0; i < num; i++) {
        fwx_uci_get_array_value(uci_ctx, "macfilter_whitelist.@whitelist_mac[%d].mac", i, mac_str, sizeof(mac_str));
        
        struct json_object *mac_obj = json_object_new_object();
        json_object_object_add(mac_obj, "mac", json_object_new_string(mac_str));
        client_node_t *dev = find_client_node(mac_str);
        if (dev) {
            json_object_object_add(mac_obj, "nickname", json_object_new_string(dev->nickname));
            json_object_object_add(mac_obj, "hostname", json_object_new_string(dev->hostname));
        } else {
            json_object_object_add(mac_obj, "nickname", json_object_new_string(""));
            json_object_object_add(mac_obj, "hostname", json_object_new_string(""));
        }
        json_object_array_add(mac_array, mac_obj);
    }

    json_object_object_add(data_obj, "list", mac_array);
    uci_free_context(uci_ctx);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_del_mac_filter_whitelist(struct json_object *req_obj) {
	int i;
    LOG_DEBUG("fwx_api_del_mac_filter_whitelist\n");
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        LOG_ERROR("mac_obj is NULL\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    LOG_DEBUG("mac: %s\n", json_object_get_string(mac_obj));

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    char mac_str[128] = {0};
    int num = fwx_uci_get_list_num(uci_ctx, "macfilter_whitelist", "whitelist_mac");
    for (i = 0; i < num; i++) {
        fwx_uci_get_array_value(uci_ctx, "macfilter_whitelist.@whitelist_mac[%d].mac", i, mac_str, sizeof(mac_str));
        if (strcmp(mac_str, json_object_get_string(mac_obj)) == 0) {
            LOG_DEBUG("delete macfilter_whitelist_mac[%d]\n", i);
            char buf[128] = {0};
            sprintf(buf, "macfilter_whitelist.@whitelist_mac[%d]", i);
            fwx_uci_delete(uci_ctx, buf);
            break;
        }
    }

    fwx_uci_commit(uci_ctx, "macfilter_whitelist");
    uci_free_context(uci_ctx);
    

    set_state_file(MACFILTER_WHITELIST_STATE_FILE);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

struct json_object *fwx_api_add_mac_filter_whitelist(struct json_object *req_obj) {
	int i, j;
    LOG_DEBUG("fwx_api_add_mac_filter_whitelist\n");
    struct json_object *mac_list_obj = json_object_object_get(req_obj, "mac_list");
    if (!mac_list_obj) {
        LOG_ERROR("mac_list_obj is NULL\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    int mac_list_len = json_object_array_length(mac_list_obj);
    for (i = 0; i < mac_list_len; i++) {
        struct json_object *mac_item = json_object_array_get_idx(mac_list_obj, i);
        const char *mac = json_object_get_string(mac_item);
        if (!mac || strlen(mac) == 0) {
            continue;
        }
        

        char mac_str[128] = {0};
        int num = fwx_uci_get_list_num(uci_ctx, "macfilter_whitelist", "whitelist_mac");
        int exists = 0;
        for (j = 0; j < num; j++) {
            fwx_uci_get_array_value(uci_ctx, "macfilter_whitelist.@whitelist_mac[%d].mac", j, mac_str, sizeof(mac_str));
            if (strcmp(mac_str, mac) == 0) {
                exists = 1;
                break;
            }
        }
        
        if (!exists) {
            fwx_uci_add_section(uci_ctx, "macfilter_whitelist", "whitelist_mac");
            char buf[128];
            snprintf(buf, sizeof(buf), "macfilter_whitelist.@whitelist_mac[-1].mac");
            fwx_uci_set_value(uci_ctx, buf, mac);
            LOG_DEBUG("Added macfilter whitelist: %s\n", mac);
        }
    }

    fwx_uci_commit(uci_ctx, "macfilter_whitelist");
    uci_free_context(uci_ctx);
    

    set_state_file(MACFILTER_WHITELIST_STATE_FILE);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

struct json_object *fwx_api_get_mac_filter_adv(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int enable = fwx_uci_get_int_value(uci_ctx, "fwx.macfilter.enable");
    json_object_object_add(data_obj, "enable", json_object_new_int(enable));
    uci_free_context(uci_ctx);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_set_mac_filter_adv(struct json_object *req_obj) {
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *enable_obj = json_object_object_get(req_obj, "enable");
    if (!enable_obj) {
        LOG_ERROR("Missing enable parameter\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int enable_value = json_object_get_int(enable_obj);
    fwx_uci_set_int_value(uci_ctx, "fwx.macfilter.enable", enable_value);
    fwx_uci_commit(uci_ctx, "fwx");

    set_state_file(MACFILTER_RULES_STATE_FILE);
    uci_free_context(uci_ctx);
    LOG_DEBUG("Set macfilter advanced settings\n");
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}
