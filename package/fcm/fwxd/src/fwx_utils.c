
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "fwx_utils.h"

char *str_trim(char *s) {
    char *start, *last, *bk;
    int len;

    start = s;
    while (isspace(*start))
        start++;

    bk = last = s + strlen(s) - 1;
    while (last > start && isspace(*last))
        last--;

    if ((s != start) || (bk != last)) {
        len = last - start + 1;
        strncpy(s, start, len);
        s[len] = '\0';
    }   
    return s;
}

int exec_with_result_line(char *cmd, char *result, int len)
{
    FILE *fp = NULL;
	if (!cmd || !result || !len)
		return -1;
    fp = popen(cmd, "r");
    if (!fp) 
        return -1;
    fgets(result, len, fp);   
    str_trim(result);
    pclose(fp);
	return 0;
}

int fwx_send_msg_to_kernel(char *buf){

    if (access("/dev/fwx", F_OK) != 0) {
        return 0; // Device doesn't exist, silently skip
    }
    
    FILE *fp = fopen("/dev/fwx", "w");
    if (fp) {
        fprintf(fp, "%s", buf);
        fclose(fp);
    }
    return 0;
}

int check_same_network(char *ip1, char *netmask, char *ip2) {
    struct in_addr addr1, addr2, mask;

    if (inet_pton(AF_INET, ip1, &addr1) != 1) {
        printf("Invalid IP address: %s\n", ip1);
        return -1;
    }
    if (inet_pton(AF_INET, netmask, &mask) != 1) {
        printf("Invalid netmask: %s\n", netmask);
        return -1;
    }
    if (inet_pton(AF_INET, ip2, &addr2) != 1) {
        printf("Invalid IP address: %s\n", ip2);
        return -1;
    }

    if ((addr1.s_addr & mask.s_addr) == (addr2.s_addr & mask.s_addr)) {
        return 1;
    } else {
        return 0;
    }
}


int af_read_file_value(const char *file_path, char *value, int value_len) {
    FILE *file = fopen(file_path, "r");
    if (!file) {
        perror("Failed to open file");
        return -1;
    }

    if (fgets(value, value_len, file) == NULL) {
        perror("Failed to read line from file");
        fclose(file);
        return -1;
    }

    size_t len = strlen(value);
    if (len > 0 && value[len - 1] == '\n') {
        value[len - 1] = '\0';
    }

    fclose(file);
    return 0;
}

int af_read_file_int_value(const char *file_path, int *value) {
    char line_buf[128] = {0};
    if (af_read_file_value(file_path, line_buf, sizeof(line_buf)) < 0){
        return -1;
    }
    *value = atoi(line_buf);
    return 0;
}

/**
 * Parse time_str from UCI format into time period structures
 * Format: "HH:MM-HH:MM-w1,w2,w3 HH:MM-HH:MM-w4,w5 ..."
 * Example: "00:00-23:59-2,3,6 00:00-02:05-1,2,3,0"
 */
int fwx_parse_time_str(const char *time_str, fwx_time_period_t *periods, int max_periods) {
    if (!time_str || !periods || max_periods <= 0) {
        return -1;
    }

    int period_count = 0;
    char *save_ptr1 = NULL;
    char *save_ptr2 = NULL;
    
    
    char time_str_copy[512] = {0};
    strncpy(time_str_copy, time_str, sizeof(time_str_copy) - 1);
    
    
    char *time_period = strtok_r(time_str_copy, " ", &save_ptr1);
    while (time_period && period_count < max_periods) {
        fwx_time_period_t *period = &periods[period_count];
        memset(period, 0, sizeof(fwx_time_period_t));
        
        char start[16] = {0};
        char end[16] = {0};
        char weekdays[64] = {0};
        
        
        char *first_delim = strchr(time_period, '-');
        if (!first_delim) {
            
            time_period = strtok_r(NULL, " ", &save_ptr1);
            continue;
        }
        
        
        strncpy(start, time_period, first_delim - time_period);
        start[first_delim - time_period] = '\0';
        
        
        char *second_delim = strchr(first_delim + 1, '-');
        if (second_delim) {
            
            strncpy(end, first_delim + 1, second_delim - first_delim - 1);
            end[second_delim - first_delim - 1] = '\0';
            strncpy(weekdays, second_delim + 1, sizeof(weekdays) - 1);
        } else {
            
            strncpy(end, first_delim + 1, sizeof(end) - 1);
        }
        
        
        strncpy(period->start_time, start, sizeof(period->start_time) - 1);
        strncpy(period->end_time, end, sizeof(period->end_time) - 1);
        
        
        if (strlen(weekdays) > 0) {
            char weekdays_copy[64] = {0};
            strncpy(weekdays_copy, weekdays, sizeof(weekdays_copy) - 1);
            
            char *weekday_str = strtok_r(weekdays_copy, ",", &save_ptr2);
            while (weekday_str && period->weekday_count < MAX_WEEKDAYS) {
                int weekday = atoi(weekday_str);
                if (weekday >= 0 && weekday <= 6) {
                    period->weekdays[period->weekday_count] = weekday;
                    period->weekday_count++;
                }
                weekday_str = strtok_r(NULL, ",", &save_ptr2);
            }
        }
        
        period_count++;
        time_period = strtok_r(NULL, " ", &save_ptr1);
    }
    
    return period_count;
}


void update_fwx_proc_value(char *key, char *value){
    char cmd_buf[128] = {0};
    char file_path[128] = {0};
    char old_value[128] = {0};
    sprintf(file_path, "/proc/sys/fwx/%s", key);

    af_read_file_value(file_path, old_value, sizeof(old_value));    
    if (strcmp(old_value, value) != 0){
        sprintf(cmd_buf, "echo %s >/proc/sys/fwx/%s", value, key);
        system(cmd_buf);
    }
}

void update_fwx_proc_u32_value(char *key, u_int32_t value){
    char buf[32] = {0};
    sprintf(buf, "%u", value);
    update_fwx_proc_value(key, buf);
}
