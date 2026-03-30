
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __FWX_SYSTEM_H__
#define __FWX_SYSTEM_H__

#include <json-c/json.h>

struct json_object *get_system_status(void);
struct json_object *fwx_api_get_system_info(struct json_object *req_obj);
struct json_object *fwx_api_set_system_info(struct json_object *req_obj);

#endif
