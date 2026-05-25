
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fwx_config.h"
#include "fwx.h"
#include <uci.h>

app_name_info_t app_name_table[MAX_SUPPORT_APP_NUM];
int g_app_count = 0;
int g_cur_class_num = 0;
char CLASS_NAME_TABLE[MAX_APP_TYPE][MAX_CLASS_NAME_LEN];

char *get_app_name_by_id(int id)
{
    int i;
    for (i = 0; i < g_app_count; i++)
    {
        if (id == app_name_table[i].id)
            return app_name_table[i].name;
    }
    return "";
}

void init_app_name_table(void)
{
    int count = 0;
    char line_buf[2048] = {0};

    FILE *fp = fopen("/tmp/feature.cfg", "r");
    if (!fp)
    {
        printf("open file failed\n");
        return;
    }
    g_app_count = 0;
    while (fgets(line_buf, sizeof(line_buf), fp))
    {
        if (strstr(line_buf, "#"))
            continue;
        if (strlen(line_buf) < 10)
            continue;
        if (!strstr(line_buf, ":"))
            continue;
        char *pos1 = strstr(line_buf, ":");
        char app_info_buf[128] = {0};
        int app_id;
        char app_name[64] = {0};
        memset(app_name, 0x0, sizeof(app_name));
        strncpy(app_info_buf, line_buf, pos1 - line_buf);
        sscanf(app_info_buf, "%d %s", &app_id, app_name);
        app_name_table[g_app_count].id = app_id;
        strcpy(app_name_table[g_app_count].name, app_name);
        g_app_count++;
    }
    fclose(fp);
}

void init_app_class_name_table(void)
{
    char line_buf[2048] = {0};
    int class_id;
    char class_name[64] = {0};
    FILE *fp = fopen("/tmp/app_class.txt", "r");
    if (!fp)
    {
        printf("open file failed\n");
        return;
    }
    g_cur_class_num = 0;
    while (fgets(line_buf, sizeof(line_buf), fp))
    {
        sscanf(line_buf, "%d %*s %s", &class_id, class_name);
        strcpy(CLASS_NAME_TABLE[class_id - 1], class_name);
        g_cur_class_num++;
    }
    fclose(fp);
}

int check_time_valid(char *t)
{
    if (!t)
        return 0;
    if (strlen(t) < 3 || strlen(t) > 5 || (!strstr(t, ":")))
        return 0;
    else
        return 1;
}


int config_get_appfilter_enable(void)
{
    int enable = 0;
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return -1;
	enable = fwx_uci_get_int_value(ctx, "appfilter.global.enable");
    if (enable < 0)
        enable = 0;
    
	uci_free_context(ctx);
    return enable;
}

int config_get_lan_ip(char *lan_ip, int len)
{
    int ret = 0;
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    ret = fwx_uci_get_value(ctx, "network.lan.ipaddr", lan_ip, len);
    uci_free_context(ctx);
    return ret;
}

int config_get_lan_mask(char *lan_mask, int len)
{
    int ret = 0;
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    ret = fwx_uci_get_value(ctx, "network.lan.netmask", lan_mask, len);
    uci_free_context(ctx);
    return ret;
}
