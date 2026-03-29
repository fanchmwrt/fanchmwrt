// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <uapi/linux/ipv6.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/etherdevice.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/timer.h>
#include <linux/ktime.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include "fwx.h"
#include "fwx_utils.h"
#include "fwx_log.h"
#include "fwx_client.h"
#include "fwx_client_fs.h"
#include "k_json.h"
#include "fwx_conntrack.h"
#include "fwx_config.h"
#include "fwx_mac_filter.h"
#include "fwx_app_filter.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("www.fanchmwrt.com");
MODULE_DESCRIPTION("fwx module");
MODULE_VERSION(AF_VERSION);
struct list_head af_feature_head = LIST_HEAD_INIT(af_feature_head);

DEFINE_RWLOCK(af_feature_lock);




static LIST_HEAD(active_app_list);
static DEFINE_SPINLOCK(active_app_list_lock);


static LIST_HEAD(active_host_list);
static DEFINE_SPINLOCK(active_host_list_lock);

u_int32_t fwx_log_level = 3;  

#define feature_list_read_lock() read_lock_bh(&af_feature_lock);
#define feature_list_read_unlock() read_unlock_bh(&af_feature_lock);
#define feature_list_write_lock() write_lock_bh(&af_feature_lock);
#define feature_list_write_unlock() write_unlock_bh(&af_feature_lock);


#define SET_APPID(ct, appid) ((ct)->fwx_data.app_id = (appid))
#define GET_APPID(ct) ((ct)->fwx_data.app_id)
#define MAX_OAF_NETLINK_MSG_LEN 1024
#define MAX_AF_SUPPORT_DATA_LEN 3000

#if LINUX_VERSION_CODE > KERNEL_VERSION(5,10,197)
extern void nf_send_reset(struct net *net, struct sock *sk, struct sk_buff *oldskb, int hook);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(4,4,1)
extern void nf_send_reset(struct net *net,  struct sk_buff *oldskb, int hook);
#else
extern void nf_send_reset(sk_buff *oldskb, int hook);
#endif

char *ipv6_to_str(const struct in6_addr *addr, char *str)
{
	sprintf(str, "%pI6c", addr);
	return str;
}


int __add_app_feature(char *feature, int appid, char *name, int proto, int src_port,
					  port_info_t dport_info, char *host_url, char *request_url, char *dict, char *search_str, int ignore)
{
	af_feature_node_t *node = NULL;
	char *p = dict;
	char *begin = dict;
	char pos[64] = {0};
	int index = 0;
	int value = 0;
	node = kzalloc(sizeof(af_feature_node_t), GFP_ATOMIC);
	if (node == NULL)
	{
		printk("malloc feature memory error\n");
		return -1;
	}
	else
	{
		node->app_id = appid;
		strcpy(node->app_name, name);
		node->proto = proto;
		node->dport_info = dport_info;
		node->sport = src_port;
		strcpy(node->host_url, host_url);
		strcpy(node->request_url, request_url);
		strcpy(node->search_str, search_str);
		node->ignore = ignore;
		strcpy(node->feature, feature);
		if (ignore)
			AF_DEBUG("add feature %s, ignore = %d\n", feature, ignore);

		p = dict;
		begin = dict;
		index = 0;
		value = 0;
		while (*p++)
		{
			if (*p == '|')
			{
				memset(pos, 0x0, sizeof(pos));
				strncpy(pos, begin, p - begin);
				k_sscanf(pos, "%d:%x", &index, &value);
				begin = p + 1;
				node->pos_info[node->pos_num].pos = index;
				node->pos_info[node->pos_num].value = value;
				node->pos_num++;
				if (node->pos_num >= MAX_POS_INFO_PER_FEATURE - 1)
					break;
			}
		}

		if (begin != dict)
			strncpy(pos, begin, p - begin);
		else
			strcpy(pos, dict);

		int ret = k_sscanf(pos, "%d:%x", &index, &value);
		if (ret == 2){
			node->pos_info[node->pos_num].pos = index;
			node->pos_info[node->pos_num].value = value;
			node->pos_num++;
		}
	
		feature_list_write_lock();
		list_add(&(node->head), &af_feature_head);
		feature_list_write_unlock();
	}
	return 0;
}
int validate_range_value(char *range_str)
{
	if (!range_str)
		return 0;
	char *p = range_str;
	while (*p)
	{
		if (*p == ' ' || *p == '!' || *p == '-' ||
			((*p >= '0') && (*p <= '9')))
		{
			p++;
			continue;
		}
		else
		{
			return 0;
		}
	}
	return 1;
}

int parse_range_value(char *range_str, range_value_t *range)
{
	char pure_range[128] = {0};
	if (!validate_range_value(range_str))
	{
		printk("validate range str failed, value = %s\n", range_str);
		return -1;
	}
	k_trim(range_str);
	if (range_str[0] == '!')
	{
		range->not = 1;
		strcpy(pure_range, range_str + 1);
	}
	else
	{
		range->not = 0;
		strcpy(pure_range, range_str);
	}
	k_trim(pure_range);
	int start, end;
	if (strstr(pure_range, "-"))
	{
		if (2 != sscanf(pure_range, "%d-%d", &start, &end))
			return -1;
	}
	else
	{
		if (1 != sscanf(pure_range, "%d", &start))
			return -1;
		end = start;
	}
	range->start = start;
	range->end = end;
	return 0;
}

int parse_port_info(char *port_str, port_info_t *info)
{
	char *p = port_str;
	char *begin = port_str;
	int param_num = 0;
	char one_port_buf[128] = {0};
	k_trim(port_str);
	if (strlen(port_str) == 0)
		return -1;

	while (*p++)
	{
		if (*p != '|')
			continue;
		memset(one_port_buf, 0x0, sizeof(one_port_buf));
		strncpy(one_port_buf, begin, p - begin);
		if (0 == parse_range_value(one_port_buf, &info->range_list[info->num]))
		{
			info->num++;
		}
		param_num++;
		begin = p + 1;
	}
	memset(one_port_buf, 0x0, sizeof(one_port_buf));
	strncpy(one_port_buf, begin, p - begin);
	if (0 == parse_range_value(one_port_buf, &info->range_list[info->num]))
	{
		info->num++;
	}
	return 0;
}

int af_match_port(port_info_t *info, int port)
{
	int i;
	int with_not = 0;
	if (info->num == 0)
		return 1;
	for (i = 0; i < info->num; i++)
	{
		if (info->range_list[i].not )
		{
			with_not = 1;
			break;
		}
	}
	for (i = 0; i < info->num; i++)
	{
		if (with_not)
		{
			if (info->range_list[i].not &&port >= info->range_list[i].start && port <= info->range_list[i].end)
			{
				return 0;
			}
		}
		else
		{
			if (port >= info->range_list[i].start && port <= info->range_list[i].end)
			{
				return 1;
			}
		}
	}
	if (with_not)
		return 1;
	else
		return 0;
}

int add_app_feature(int appid, char *name, char *feature)
{
	char proto_str[16] = {0};
	char src_port_str[16] = {0};
	port_info_t dport_info;
	char dst_port_str[16] = {0};
	char host_url[32] = {0};
	char request_url[128] = {0};
	char dict[128] = {0};
	int proto = IPPROTO_TCP;
	int param_num = 0;
	int dst_port = 0;
	int src_port = 0;
	char tmp_buf[128] = {0};
	int ignore = 0;
	char search_str[128] = {0};
	char *p = feature;
	char *begin = feature;

	if (!name || !feature)
	{
		AF_ERROR("error, name or feature is null\n");
		return -1;
	}
	
	if (strlen(feature) < MIN_FEATURE_STR_LEN){
		return -1;
	}

	memset(&dport_info, 0x0, sizeof(dport_info));
	while (*p++)
	{
		if (*p != ';')
			continue;

		switch (param_num)
		{

		case AF_PROTO_PARAM_INDEX:
			strncpy(proto_str, begin, p - begin);
			break;
		case AF_SRC_PORT_PARAM_INDEX:
			strncpy(src_port_str, begin, p - begin);
			break;
		case AF_DST_PORT_PARAM_INDEX:
			strncpy(dst_port_str, begin, p - begin);
			break;

		case AF_HOST_URL_PARAM_INDEX:
			strncpy(host_url, begin, p - begin);
			break;

		case AF_REQUEST_URL_PARAM_INDEX:
			strncpy(request_url, begin, p - begin);
			break;
		case AF_DICT_PARAM_INDEX:
			strncpy(dict, begin, p - begin);
			break;
		case AF_STR_PARAM_INDEX:
			strncpy(search_str, begin, p - begin);
			break;
		case AF_IGNORE_PARAM_INDEX:
			strncpy(tmp_buf, begin, p - begin);
			ignore = k_atoi(tmp_buf);
			break;
		}
		param_num++;
		begin = p + 1;
	}



	if (param_num == AF_DICT_PARAM_INDEX){
		strncpy(dict, begin, p - begin);
	}

	if (param_num == AF_IGNORE_PARAM_INDEX){
		strncpy(tmp_buf, begin, p - begin);
		ignore = k_atoi(tmp_buf);
	}

	if (0 == strcmp(proto_str, "tcp"))
		proto = IPPROTO_TCP;
	else if (0 == strcmp(proto_str, "udp"))
		proto = IPPROTO_UDP;
	else
	{
		printk("proto %s is not support, feature = %s\n", proto_str, feature);
		return -1;
	}
	sscanf(src_port_str, "%d", &src_port);

	parse_port_info(dst_port_str, &dport_info);
	AF_DEBUG("host_url = %s, request = %s, dict = %s\n",  host_url, request_url, dict);

	__add_app_feature(feature, appid, name, proto, src_port, dport_info, host_url, request_url, dict, search_str, ignore);
	AF_DEBUG("id = %d name = %s, add feature %s, ignore = %d\n", appid, name, feature, ignore);
	return 0;
}

void af_init_feature(char *feature_str)
{
	int app_id;
	char app_name[128] = {0};
	char *feature_buf = NULL;
	char feature[MAX_FEATURE_STR_LEN] = {0};
	char *p = feature_str;
	char *pos = NULL;
	int len = 0;
	char *begin = NULL;

	feature_buf = kmalloc(MAX_FEATURE_LINE_LEN, GFP_KERNEL);
	if (!feature_buf) {
		AF_ERROR("Failed to allocate memory for feature_buf\n");
		return;
	}
	memset(feature_buf, 0, MAX_FEATURE_LINE_LEN);

	if (strstr(feature_str, "#"))
		return;

	k_sscanf(feature_str, "%d%[^:]", &app_id, app_name);
	while (*p++)
	{
		if (*p == '[')
		{
			pos = p + 1;
			continue;
		}
		if (*p == ']' && pos != NULL)
		{
			len = p - pos;
		}
	}

	if (pos && len)
		strncpy(feature_buf, pos, len);
	p = feature_buf;
	begin = feature_buf;

	while (*p++)
	{
		if (*p == ',')
		{
			if (p - begin > MAX_FEATURE_STR_LEN){
				printk("error, feature len error %d\n", p - len);
				break;
			}
			memcpy((char *)feature, begin, p - begin);
			feature[p - begin] = '\0';
			add_app_feature(app_id, app_name, feature);
			begin = p + 1;
		}
	}
	if (p != begin)
	{
		
		if (p - begin > MAX_FEATURE_STR_LEN){
			printk("error, feature len error %d\n", p - len);
		}
		else{
			memcpy((char *)feature, begin, p - begin);
			feature[p - begin] = '\0';
			add_app_feature(app_id, app_name, feature);
		}
	}
	g_feature_count++;  // 增加特征码计数

	if (feature_buf)
		kfree(feature_buf);
}

void load_feature_buf_from_file(char **config_buf)
{
	struct inode *inode = NULL;
	struct file *fp = NULL;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 7, 19)
	mm_segment_t fs;
#endif
	off_t size;
	fp = filp_open(AF_FEATURE_CONFIG_FILE, O_RDONLY, 0);
	

	if (IS_ERR(fp))
	{
		return;
	}

	inode = fp->f_inode;
	size = inode->i_size;
	if (size == 0)
	{
		return;
	}
	*config_buf = (char *)kzalloc(sizeof(char) * size, GFP_ATOMIC);
	if (NULL == *config_buf)
	{
		AF_ERROR("alloc buf fail\n");
		filp_close(fp, NULL);
		return;
	}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 7, 19)
	fs = get_fs();
	set_fs(KERNEL_DS);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	kernel_read(fp, *config_buf, size, &(fp->f_pos));
#else
	vfs_read(fp, *config_buf, size, &(fp->f_pos));
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 7, 19)
	set_fs(fs);
#endif
	filp_close(fp, NULL);
}

int load_feature_config(void)
{
	char *feature_buf = NULL;
	char *p;
	char *begin;
	char line[MAX_FEATURE_LINE_LEN] = {0};

	load_feature_buf_from_file(&feature_buf);
	if (!feature_buf)
	{
		return -1;
	}
	p = begin = feature_buf;
	while (*p++)
	{
		if (*p == '\n')
		{
			if (p - begin < MIN_FEATURE_LINE_LEN || p - begin > MAX_FEATURE_LINE_LEN)
			{
				begin = p + 1;
				continue;
			}
			memset(line, 0x0, sizeof(line));
			strncpy(line, begin, p - begin);
			af_init_feature(line);
			begin = p + 1;
		}
	}

	if (p != begin)
	{
		if (p - begin < MIN_FEATURE_LINE_LEN || p - begin > MAX_FEATURE_LINE_LEN)
			return 0;
		memset(line, 0x0, sizeof(line));
		strncpy(line, begin, p - begin);
		af_init_feature(line);
		begin = p + 1;
	}
	if (feature_buf)
		kfree(feature_buf);
	return 0;
}

static void af_clean_feature_list(void)
{
	af_feature_node_t *node;
	feature_list_write_lock();
	while (!list_empty(&af_feature_head))
	{
		node = list_first_entry(&af_feature_head, af_feature_node_t, head);
		list_del(&(node->head));
		kfree(node);
	}
	g_feature_count = 0;  // 清零特征码计数
	feature_list_write_unlock();
}

void af_add_feature_msg_handle(char *data, int len)
{
	char feature[MAX_FEATURE_LINE_LEN] = {0};
	if (len <= 0 || len >= MAX_FEATURE_LINE_LEN){
		printk("warn, feature data len = %d\n", len);
		return;
	}
	strncpy(feature, data, len);
	AF_INFO("add feature %s\n", feature);
	af_init_feature(feature);
}

static unsigned char *read_skb(struct sk_buff *skb, unsigned int from, unsigned int len)
{
	struct skb_seq_state state;
	unsigned char *msg_buf = NULL;
	unsigned int consumed = 0;

	msg_buf = kmalloc(len, GFP_KERNEL);
	if (!msg_buf)
		return NULL;

	skb_prepare_seq_read(skb, from, from + len, &state);
	while (1)
	{
		unsigned int avail;
		const u8 *ptr;
		avail = skb_seq_read(consumed, &ptr, &state);
		if (avail == 0)
		{
			break;
		}
		memcpy(msg_buf + consumed, ptr, avail);
		consumed += avail;
		if (consumed >= len)
		{
			skb_abort_seq_read(&state);
			break;
		}
	}
	return msg_buf;
}

int parse_flow_proto(struct sk_buff *skb, flow_info_t *flow)
{
	unsigned char *ipp;
	int ipp_len;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct nf_conn *ct = NULL;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	if (!skb)
		return -1;
	switch (skb->protocol)
	{
	case htons(ETH_P_IP):
		iph = ip_hdr(skb);
		flow->src = iph->saddr;
		flow->dst = iph->daddr;
		flow->l4_protocol = iph->protocol;
		ipp = ((unsigned char *)iph) + iph->ihl * 4;
		ipp_len = ((unsigned char *)iph) + ntohs(iph->tot_len) - ipp;
		break;
	case htons(ETH_P_IPV6):
		ip6h = ipv6_hdr(skb);
		flow->src6 = &ip6h->saddr;
		flow->dst6 = &ip6h->daddr;
		flow->l4_protocol = ip6h->nexthdr;
		ipp = ((unsigned char *)ip6h) + sizeof(struct ipv6hdr);
		ipp_len = ntohs(ip6h->payload_len);
		break;
	default:
		return -1;
	}

	switch (flow->l4_protocol)
	{
	case IPPROTO_TCP:
		tcph = (struct tcphdr *)ipp;
		flow->l4_len = ipp_len - tcph->doff * 4;
		flow->l4_data = ipp + tcph->doff * 4;
		flow->dport = ntohs(tcph->dest);
		flow->sport = ntohs(tcph->source);
		return 0;
	case IPPROTO_UDP:
		udph = (struct udphdr *)ipp;
		flow->l4_len = ntohs(udph->len) - 8;
		flow->l4_data = ipp + 8;
		flow->dport = ntohs(udph->dest);
		flow->sport = ntohs(udph->source);
		return 0;
	case IPPROTO_ICMP:
		break;
	default:
		return -1;
	}
	return -1;
}

int check_domain(char *h, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		if ((h[i] >= 'a' && h[i] <= 'z') || (h[i] >= 'A' && h[i] <= 'Z') ||
			(h[i] >= '0' && h[i] <= '9') || h[i] == '.' || h[i] == '-' ||  h[i] == ':')
		{
			continue;
		}
		else
			return 0;
	}
	return 1;
}

int dpi_https_proto(flow_info_t *flow)
{
	int i;
	short url_len = 0;
	char *p = flow->l4_data;
	int data_len = flow->l4_len;

	if (NULL == flow)
	{
		AF_ERROR("flow is NULL\n");
		return -1;
	}
	if (NULL == p || data_len < 16)
	{
		return -1;
	}
	if (!((p[0] == 0x16 && p[1] == 0x03 && p[5] == 0x01) || flow->client_hello))
		return -1;

	for (i = 0; i < data_len; i++)
	{
		if (i + HTTPS_URL_OFFSET >= data_len)
		{
			AF_LMT_DEBUG("match https host failed, data_len = %d, sport:%d, dport:%d\n", data_len, flow->sport,flow->dport);
			if ((TEST_MODE())){
 				print_hex_ascii(flow->l4_data,  flow->l4_len);
			}
			flow->client_hello = 1;	
			return -1;
		}

		if (p[i] == 0x0 && p[i + 1] == 0x0 && p[i + 2] == 0x0 && p[i + 3] != 0x0)
		{

			memcpy(&url_len, p + i + HTTPS_LEN_OFFSET, 2);

			if (ntohs(url_len) <= MIN_HOST_LEN || ntohs(url_len) > data_len || ntohs(url_len) > MAX_HOST_LEN)
			{
				continue;
			}

			if (i + HTTPS_URL_OFFSET + ntohs(url_len) < data_len)
			{
				if (!check_domain( p + i + HTTPS_URL_OFFSET, ntohs(url_len))){
					AF_INFO("invalid url, len = %d\n", ntohs(url_len));
					continue;
				}
				flow->https.match = AF_TRUE;
				flow->https.url_pos = p + i + HTTPS_URL_OFFSET;
				flow->https.url_len = ntohs(url_len);
				flow->client_hello = 0;
				return 0;
			}
		}
	}
	return -1;
}

void dpi_http_proto(flow_info_t *flow)
{
	int i = 0;
	int start = 0;
	char *data = NULL;
	int data_len = 0;
	if (!flow)
	{
		AF_ERROR("flow is null\n");
		return;
	}
	if (flow->l4_protocol != IPPROTO_TCP)
	{
		return;
	}

	data = flow->l4_data;
	data_len = flow->l4_len;
	if (data_len < MIN_HTTP_DATA_LEN)
	{
		return;
	}

	for (i = 0; i < data_len; i++)
	{
		if (data[i] == 0x0d && data[i + 1] == 0x0a)
		{
			if (0 == memcmp(&data[start], "POST ", 5))
			{
				flow->http.match = AF_TRUE;
				flow->http.method = HTTP_METHOD_POST;
				flow->http.url_pos = data + start + 5;
				flow->http.url_len = i - start - 5;
			}
			else if (0 == memcmp(&data[start], "GET ", 4))
			{
				flow->http.match = AF_TRUE;
				flow->http.method = HTTP_METHOD_GET;
				flow->http.url_pos = data + start + 4;
				flow->http.url_len = i - start - 4;
			}
			else if (0 == memcmp(&data[start], "Host:", 5))
			{
				flow->http.host_pos = data + start + 6;
				flow->http.host_len = i - start - 6;
			}
			if (data[i + 2] == 0x0d && data[i + 3] == 0x0a)
			{
				flow->http.data_pos = data + i + 4;
				flow->http.data_len = data_len - i - 4;
				break;
			}

			start = i + 2;
		}
	}
}

static void dump_http_flow_info(http_proto_t *http)
{
	if (!http)
	{
		AF_ERROR("http ptr is NULL\n");
		return;
	}
	if (!http->match)
		return;
	if (http->method == HTTP_METHOD_GET)
	{
		printk("Http method: " HTTP_GET_METHOD_STR "\n");
	}
	else if (http->method == HTTP_METHOD_POST)
	{
		printk("Http method: " HTTP_POST_METHOD_STR "\n");
	}
	if (http->url_len > 0 && http->url_pos)
	{
		dump_str("Request url", http->url_pos, http->url_len);
	}

	if (http->host_len > 0 && http->host_pos)
	{
		dump_str("Host", http->host_pos, http->host_len);
	}

	printk("--------------------------------------------------------\n\n\n");
}

static void dump_https_flow_info(https_proto_t *https)
{
	if (!https)
	{
		AF_ERROR("https ptr is NULL\n");
		return;
	}
	if (!https->match)
		return;

	if (https->url_len > 0 && https->url_pos)
	{
		dump_str("https server name", https->url_pos, https->url_len);
	}

	printk("--------------------------------------------------------\n\n\n");
}
static void dump_flow_info(flow_info_t *flow)
{
	if (!flow)
	{
		AF_ERROR("flow is null\n");
		return;
	}
	if (flow->l4_len > 0)
	{
		AF_LMT_INFO("src=" NIPQUAD_FMT ",dst=" NIPQUAD_FMT ",sport: %d, dport: %d, data_len: %d\n",
					NIPQUAD(flow->src), NIPQUAD(flow->dst), flow->sport, flow->dport, flow->l4_len);
	}

	if (flow->l4_protocol == IPPROTO_TCP)
	{
		if (AF_TRUE == flow->http.match)
		{
			printk("-------------------http protocol-------------------------\n");
			printk("protocol:TCP , sport: %-8d, dport: %-8d, data_len: %-8d\n",
				   flow->sport, flow->dport, flow->l4_len);
			dump_http_flow_info(&flow->http);
		}
		if (AF_TRUE == flow->https.match)
		{
			printk("-------------------https protocol-------------------------\n");
			dump_https_flow_info(&flow->https);
		}
	}
}


char *k_memstr(char *data, char *str, int size)
{
	char *p;
	char len = strlen(str);
	for (p = data; p <= (data - len + size); p++)
	{
		if (memcmp(p, str, len) == 0)
			return p; 
	}
	return NULL;
}

int af_match_by_pos(flow_info_t *flow, af_feature_node_t *node)
{
	int i;
	unsigned int pos = 0;

	if (!flow || !node)
		return AF_FALSE;
	if (node->pos_num > 0)
	{
		
		for (i = 0; i < node->pos_num && i < MAX_POS_INFO_PER_FEATURE; i++)
		{

			if (node->pos_info[i].pos < 0)
			{
				pos = flow->l4_len + node->pos_info[i].pos;
			}
			else
			{
				pos = node->pos_info[i].pos;
			}
			if (pos >= flow->l4_len)
			{
				return AF_FALSE;
			}
			if (flow->l4_data[pos] != node->pos_info[i].value)
			{
				return AF_FALSE;
			}
			else{
				AF_DEBUG("match pos[%d] = %x\n", pos, node->pos_info[i].value);
			}
		}
		if (strlen(node->search_str) > 0){
			if (k_memstr(flow->l4_data, node->search_str, flow->l4_len)){
				AF_DEBUG("match by search str, appid=%d, search_str=%s\n", node->app_id, node->search_str);
				return AF_TRUE;
			}
			else{
				return AF_FALSE;
			}
		}
		return AF_TRUE;
	}
	return AF_FALSE;
}

int af_match_by_url(flow_info_t *flow, af_feature_node_t *node)
{
	char reg_url_buf[MAX_URL_MATCH_LEN] = {0};

	if (!flow || !node)
		return AF_FALSE;

	if (flow->https.match == AF_TRUE && flow->https.url_pos)
	{
		if (flow->https.url_len >= MAX_URL_MATCH_LEN)
			strncpy(reg_url_buf, flow->https.url_pos, MAX_URL_MATCH_LEN - 1);
		else
			strncpy(reg_url_buf, flow->https.url_pos, flow->https.url_len);
	}
	else if (flow->http.match == AF_TRUE && flow->http.host_pos)
	{
		if (flow->http.host_len >= MAX_URL_MATCH_LEN)
			strncpy(reg_url_buf, flow->http.host_pos, MAX_URL_MATCH_LEN - 1);
		else
			strncpy(reg_url_buf, flow->http.host_pos, flow->http.host_len);
	}
	if (strlen(reg_url_buf) > 0 && strlen(node->host_url) > 0 && regexp_match(node->host_url, reg_url_buf))
	{
		AF_DEBUG("match url:%s	 reg = %s, appid=%d\n",
				 reg_url_buf, node->host_url, node->app_id);
		return AF_TRUE;
	}


	if (flow->http.match == AF_TRUE && flow->http.url_pos)
	{
		memset(reg_url_buf, 0x0, sizeof(reg_url_buf));
		if (flow->http.url_len >= MAX_URL_MATCH_LEN)
			strncpy(reg_url_buf, flow->http.url_pos, MAX_URL_MATCH_LEN - 1);
		else
			strncpy(reg_url_buf, flow->http.url_pos, flow->http.url_len);
		if (strlen(reg_url_buf) > 0 && strlen(node->request_url) && regexp_match(node->request_url, reg_url_buf))
		{
			AF_DEBUG("match request:%s   reg:%s appid=%d\n",
					 reg_url_buf, node->request_url, node->app_id);
			return AF_TRUE;
		}
	}
	return AF_FALSE;
}

int af_match_one(flow_info_t *flow, af_feature_node_t *node)
{
	int ret = AF_FALSE;
	if (!flow || !node)
	{
		AF_ERROR("node or flow is NULL\n");
		return AF_FALSE;
	}
	if (node->proto > 0 && flow->l4_protocol != node->proto)
		return AF_FALSE;
	if (flow->l4_len == 0)
		return AF_FALSE;

	if (node->sport != 0 && flow->sport != node->sport)
	{
		return AF_FALSE;
	}

	if (!af_match_port(&node->dport_info, flow->dport))
	{
		return AF_FALSE;
	}

	if (strlen(node->request_url) > 0 ||
		strlen(node->host_url) > 0)
	{
		ret = af_match_by_url(flow, node);
	}
	else if (node->pos_num > 0)
	{
		
		ret = af_match_by_pos(flow, node);
	}
	else
	{
		AF_DEBUG("node is empty, match sport:%d,dport:%d, appid = %d\n",
				 node->sport, node->dport, node->app_id);
		return AF_TRUE;
	}

	return ret;
}


int is_quic_flow(flow_info_t *flow)
{
	unsigned char *data;
	unsigned char first_byte;
	unsigned int version;
	
	if (flow->l4_protocol != IPPROTO_UDP) {
		return AF_FALSE;
	}
	
	if (!flow->l4_data || flow->l4_len < 8) {
		return AF_FALSE;
	}
	
	data = flow->l4_data;
	first_byte = data[0];
	
	if (first_byte & 0x80) {
		if (flow->l4_len >= 5) {
			version = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];

			if (version == 0x00000001 ||
				version == 0x00000000 ||  
				version == 0x6b3343cf || 
				(version >= 0xff000000 && version <= 0xffffffff)) { 
				AF_LMT_DEBUG("match quic, version = %x\n", version);
				return AF_TRUE;
			}
		}
		if (flow->dport == 443) {
			return AF_TRUE;
		}
		return AF_FALSE;
	}
	return AF_FALSE;
}

int fwx_match_feature(flow_info_t *flow)
{
	af_feature_node_t *n, *node;
	feature_list_read_lock();
	if (!list_empty(&af_feature_head))
	{
		list_for_each_entry_safe(node, n, &af_feature_head, head)
		{
			if (af_match_one(flow, node))
			{
				AF_LMT_INFO("match feature, appid=%d, feature = %s\n", node->app_id, node->feature);
				flow->app_id = node->app_id;
				flow->feature = node;
				strncpy(flow->app_name, node->app_name, sizeof(flow->app_name) - 1);
				feature_list_read_unlock();
				return AF_TRUE;
			}
		}
	}
	if (is_quic_flow(flow)) {
		AF_LMT_INFO("match quic flow...\n");
		flow->app_id = FWX_QUIC_PROTO;
		strcpy(flow->app_name, "QUIC");
		feature_list_read_unlock();
		return AF_TRUE;
	}
	feature_list_read_unlock();
	return AF_FALSE;
}

int match_app_filter_rule(int appid, af_client_info_t *client)
{

	if (!g_appfilter_enable) {
		return AF_FALSE;
	}
	
	if (fwx_match_app_filter_whitelist(client->mac)){
		AF_LMT_DEBUG("match appfilter whitelist mac = " MAC_FMT "\n", MAC_ARRAY(client->mac));
		return AF_FALSE;
	}

	app_filter_rule_t *rule = fwx_match_app_filter_rule(appid, client->mac);
	if (rule) {
		AF_LMT_INFO("drop appid = %d, rule_id = %d\n", appid, rule->rule_id);
		return AF_TRUE;
	}
	return AF_FALSE;
}

int match_mac_filter_rule(af_client_info_t *client)
{

	if (!g_mac_filter_enable) {
		return AF_FALSE;
	}
	
	if (fwx_match_mac_filter_whitelist(client->mac)){
		AF_LMT_DEBUG("match macfilter whitelist mac = " MAC_FMT "\n", MAC_ARRAY(client->mac));
		return AF_FALSE;
	}

	mac_filter_rule_t *rule = fwx_match_mac_filter_rule(client->mac);
	if (rule) {
		AF_LMT_INFO("drop mac, rule_id = %d, mac = " MAC_FMT "\n", rule->rule_id, MAC_ARRAY(client->mac));
		return AF_TRUE;
	}
	return AF_FALSE;
}

int af_update_client_app_info(af_client_info_t *node, int app_id, int drop, int from_conntrack, int is_http)
{
	app_visit_info_t *info;
	if (!node || app_id <= 0)
		return -1;

	spin_lock_bh(&node->visit_info_lock);

	info = get_or_create_visit_info(node, app_id);
	if (!info){
		spin_unlock_bh(&node->visit_info_lock);
		return -1;
	}
	
	info->total_num++;
	if (drop)
		info->drop_num++;
	info->latest_time = af_get_timestamp_sec();
	info->latest_action = drop;

	

	if (!from_conntrack) {
		info->conn_count++;
		info->is_http = is_http;
	}

	if ((info->is_http && info->conn_count >= 3) || (!info->is_http)){
		node->visiting.app_time = af_get_timestamp_sec();
		node->visiting.visiting_app = app_id;
	}
	
	spin_unlock_bh(&node->visit_info_lock);
	return 0;
}

int af_send_msg_to_user(char *pbuf, uint16_t len);
int af_match_bcast_packet(flow_info_t *f)
{
	if (!f)
		return 0;
	if (0 == f->src || 0 == f->dst || 0xffffffff == f->dst || 0 == f->dst)
		return 1;
	return 0;
}

int af_match_local_packet(flow_info_t *f)
{
	if (!f)
		return 0;
	if (0x0100007f == f->src || 0x0100007f == f->dst)
	{
		return 1;
	}
	return 0;
}

int update_url_visiting_info(af_client_info_t *client, flow_info_t *flow)
{
	char *host = NULL;
	unsigned int len = 0;
	if (!client || !flow)
		return -1;
	
	if (flow->https.match){
		host = flow->https.url_pos;

		len = flow->https.url_len;
	}
	else if (flow->http.match){
		host = flow->http.host_pos;
		len = flow->http.host_len;
	}
	if (!host || len < MIN_REPORT_URL_LEN || len >= MAX_REPORT_URL_LEN)
		return -1;

	memcpy(client->visiting.visiting_url, host, len);
	client->visiting.visiting_url[len] = 0x0; 
	client->visiting.url_time = af_get_timestamp_sec();
	return 0;
}


int dpi_main(struct sk_buff *skb, flow_info_t *flow)
{
	dpi_http_proto(flow);
	dpi_https_proto(flow);
	if (TEST_MODE())
		dump_flow_info(flow);


	return 0;
}

void af_get_smac(struct sk_buff *skb, u_int8_t *smac)
{
	struct ethhdr *ethhdr = NULL;
	ethhdr = eth_hdr(skb);
	if (ethhdr)
		memcpy(smac, ethhdr->h_source, ETH_ALEN);
	else
		memcpy(smac, &skb->cb[40], ETH_ALEN);
}
int is_ipv4_broadcast(uint32_t ip)
{
	return (ip & 0x00FFFFFF) == 0x00FFFFFF;
}

int is_ipv4_multicast(uint32_t ip)
{
	return (ip & 0xF0000000) == 0xE0000000;
}
int af_check_bcast_ip(flow_info_t *f)
{

	if (0 == f->src || 0 == f->dst)
		return 1;
	if (is_ipv4_broadcast(ntohl(f->src)) || is_ipv4_broadcast(ntohl(f->dst)))
	{
		return 1;
	}
	if (is_ipv4_multicast(ntohl(f->src)) || is_ipv4_multicast(ntohl(f->dst)))
	{
		return 1;
	}

	return 0;
}

void send_reset_packet(struct sk_buff *skb, flow_info_t *flow){

	if (g_tcp_rst && flow->l4_protocol == IPPROTO_TCP){
		if (skb->protocol == htons(ETH_P_IP) && g_tcp_rst){
			#if LINUX_VERSION_CODE > KERNEL_VERSION(5,10,197)
				nf_send_reset(&init_net, skb->sk, skb, NF_INET_PRE_ROUTING);
			#elif LINUX_VERSION_CODE > KERNEL_VERSION(4,4,1)


			#else
				nf_send_reset(skb, NF_INET_PRE_ROUTING);
			#endif	
		}
	}
}


u_int32_t check_app_action_changed(int action, u_int32_t app_id, af_client_info_t *client)
{
	u_int8_t drop = 0;
	int changed = 0;
	u_int32_t max_jiffies = 30 * HZ;
	u_int32_t interval_jiffies = jiffies - g_appfilter_update_jiffies;

	if (interval_jiffies < max_jiffies){     
		AF_LMT_DEBUG("config changed, update app action\n");
		if (match_app_filter_rule(app_id, client)){
			AF_LMT_DEBUG("match appid = %d, action = %d\n", app_id, action);
			if (!action) // accept --> drop
				changed = 1;
		}    
		else{
			if (action) // drop --> accept
				changed = 1;
		}    
	} 
	return changed;
}

u_int32_t fwx_hook_bypass_handle(struct sk_buff *skb, struct net_device *dev)
{
	flow_info_t flow;
	af_conn_t *conn;
	u_int8_t smac[ETH_ALEN];
	af_client_info_t *client = NULL;
	u_int32_t ret = NF_ACCEPT;
	u_int8_t malloc_data = 0;

	if (!skb || !dev)
		return NF_ACCEPT;
	if (0 == fwx_lan_ip || 0 == fwx_lan_mask)
		return NF_ACCEPT;
	if (strstr(dev->name, "docker"))
		return NF_ACCEPT;

	memset((char *)&flow, 0x0, sizeof(flow_info_t));
	if (parse_flow_proto(skb, &flow) < 0)
		return NF_ACCEPT;

	if (flow.src || flow.dst)
	{
		if (fwx_lan_ip == flow.src || fwx_lan_ip == flow.dst)
		{
			return NF_ACCEPT;
		}
		if (af_check_bcast_ip(&flow) || af_match_local_packet(&flow))
			return NF_ACCEPT;

		if ((flow.src & fwx_lan_mask) != (fwx_lan_ip & fwx_lan_mask))
		{
			return NF_ACCEPT;
		}
	}
	else
	{
		return NF_ACCEPT;
	}
	af_get_smac(skb, smac);

	AF_CLIENT_LOCK_W();
	client = find_and_add_af_client(smac);
	if (!client)
	{
		AF_CLIENT_UNLOCK_W();
		return NF_ACCEPT;
	}
	client->update_jiffies = jiffies;
	if (flow.src)
		client->ip = flow.src;
	AF_CLIENT_UNLOCK_W();


	spin_lock(&af_conn_lock);
   	conn = af_conn_find_and_add(flow.src, flow.dst, flow.sport, flow.dport, flow.l4_protocol);
	if (!conn){
		return NF_ACCEPT;
	}

	conn->last_jiffies = jiffies;
	conn->total_pkts++;
	spin_unlock(&af_conn_lock);


	if (conn->app_id == 0 && conn->drop == 1){
		send_reset_packet(skb, &flow);
		return NF_DROP;
	}
	if (conn->app_id != 0)
	{
		flow.app_id = conn->app_id;
		flow.drop = conn->drop;
		if (flow.app_id > 1000){
			if (check_app_action_changed(flow.drop, flow.app_id, client)){
				flow.drop = !flow.drop;
				AF_LMT_DEBUG("update appid %d action, new action = %s\n", flow.app_id, flow.drop ? "drop" : "accept");
			}
		}
	}
	else{
		if (g_by_pass_accl) {
			if (conn->total_pkts > 256)	{
				return NF_ACCEPT;
			}
		}
		if (skb_is_nonlinear(skb) && flow.l4_len < MAX_AF_SUPPORT_DATA_LEN)
		{
			flow.l4_data = read_skb(skb, flow.l4_data - skb->data, flow.l4_len);
			if (!flow.l4_data)
				return NF_ACCEPT;
			AF_LMT_DEBUG("##match nonlinear skb, len = %d\n", flow.l4_len);
			malloc_data = 1;
		}
		flow.client_hello = conn->client_hello;
		if (flow.client_hello > 0)
			AF_LMT_DEBUG("client hello is %d\n", flow.client_hello);

		dpi_main(skb, &flow);
		conn->client_hello = flow.client_hello;
		update_url_visiting_info(client, &flow);
		af_update_active_host_list(client, &flow);

	 	if (fwx_match_feature(&flow)){
			conn->app_id = flow.app_id;
			conn->drop = flow.drop;
			if (flow.app_id < 1000){ 
				conn->ignore = 1;
			}
			else{
				if (flow.feature && flow.feature->ignore){
					AF_LMT_DEBUG("match ignore feature, feature = %s, appid = %d\n", flow.feature->feature ,flow.app_id);
					conn->ignore = 1;
				}
				else{
					conn->ignore = 0;
				}
	 		}
			conn->state = AF_CONN_DPI_FINISHED;
			if (!conn->ignore)
				af_update_active_app_list(client, &flow);
			if (match_app_filter_rule(flow.app_id, client)) {
				flow.drop = 1;
				conn->drop = 1;
				AF_LMT_INFO("##Drop App filter rule, appid = %d, mac = " MAC_FMT "\n", 
						flow.app_id, MAC_ARRAY(client->mac));
				send_reset_packet(skb, &flow);
			}
		}
		
	}

	

	if (!flow.drop && match_mac_filter_rule(client)) {
		flow.drop = 1;
		conn->drop = 1;
		AF_LMT_INFO("##Drop MAC filter rule, mac = " MAC_FMT "\n", 
				MAC_ARRAY(client->mac));
		send_reset_packet(skb, &flow);
	}

	if (g_record_enable	){
		if (!conn->ignore){
			int is_http = (flow.http.match || flow.https.match) ? 1 : 0;
			af_update_client_app_info(client, flow.app_id, flow.drop, 0, is_http);
		}
	} 


	if (flow.drop)
	{
		AF_LMT_INFO("drop appid = %d\n", flow.app_id);
		ret = NF_DROP;
	}

	if (malloc_data)
	{
		if (flow.l4_data)
		{
			kfree(flow.l4_data);
		}
	}
	return ret;
}

u_int32_t fwx_hook_gateway_handle(struct sk_buff *skb, struct net_device *dev)
{
	unsigned long long total_packets = 0;
	flow_info_t flow;
	u_int8_t smac[ETH_ALEN];
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = NULL;
	struct nf_conn_acct *acct;
	af_client_info_t *client = NULL;
	u_int32_t ret = NF_ACCEPT;
	u_int32_t app_id = 0;
	u_int8_t drop = 0;
	u_int8_t malloc_data = 0;
	if (!strstr(dev->name, g_lan_ifname))
		return NF_ACCEPT;

	memset((char *)&flow, 0x0, sizeof(flow_info_t));
	if (parse_flow_proto(skb, &flow) < 0)
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (ct == NULL)
		return NF_ACCEPT;

	if (flow.l4_protocol == IPPROTO_TCP && !nf_ct_is_confirmed(ct)){
		return NF_ACCEPT;
	}

	AF_CLIENT_LOCK_R();
	if (flow.src){
		client = find_af_client_by_ip(flow.src);
	}
	else if (flow.src6){
		client = find_af_client_by_ipv6(flow.src6);
	}

	if (!client)
	{
		AF_CLIENT_UNLOCK_R();
		return NF_ACCEPT;
	}
	client->update_jiffies = jiffies;
	AF_CLIENT_UNLOCK_R();

	if (ct->fwx_data.app_id != 0)
	{
		app_id = ct->fwx_data.app_id;
		
		AF_LMT_DEBUG("ct appid = %d\n", app_id);
		u_int32_t orig_action = ct->fwx_data.action;

		int ct_action = ct->fwx_data.action;
		flow.ignore = (ct->fwx_data.match_status & 0x1) ? 1 : 0;


		if (app_id > 0 && app_id < 1000){
			if (g_appfilter_enable && ct_action) {
				AF_LMT_DEBUG("ct drop appid = %d\n", app_id);
				return NF_DROP;
			}
		}

		if (app_id > 1000 && app_id < 32000)
		{
			if (check_app_action_changed(ct_action, app_id, client)){
				ct_action = !ct_action;
				ct->fwx_data.action = ct_action;
				AF_LMT_DEBUG("update appid %d action to %s, action = %d-->%d\n",
					 app_id, ct_action ? "drop" : "accept", orig_action, ct->fwx_data.action);
			}
		
			if (g_record_enable){
				if (!flow.ignore){
					af_update_client_app_info(client, app_id, ct_action, 1, 0);
				}
			}
			if (g_appfilter_enable && ct_action) {
				AF_LMT_DEBUG("drop appid = %d, ct_action = %d\n", app_id, ct_action);
				return NF_DROP;
			}
		}

	}

	if (ct->fwx_data.action){
		AF_LMT_DEBUG("ct drop\n");
		return NF_DROP;
	}

	if (ct->fwx_data.app_id != 0)
		return NF_ACCEPT;


	if (ct->fwx_data.match_status & 0x2) {	
		flow.client_hello = 1;
	}


	acct = nf_conn_acct_find(ct);
	if (!acct)
		return NF_ACCEPT;
	total_packets = (unsigned long long)atomic64_read(&acct->counter[IP_CT_DIR_ORIGINAL].packets) + (unsigned long long)atomic64_read(&acct->counter[IP_CT_DIR_REPLY].packets);

	if (total_packets > MAX_DPI_PKT_NUM)
		return NF_ACCEPT;

	if (skb_is_nonlinear(skb) && flow.l4_len < MAX_AF_SUPPORT_DATA_LEN)
	{
		flow.l4_data = read_skb(skb, flow.l4_data - skb->data, flow.l4_len);
		if (!flow.l4_data)
			return NF_ACCEPT;
		malloc_data = 1;
	}
	dpi_main(skb, &flow);

	update_url_visiting_info(client, &flow);
	if (flow.client_hello) {
		ct->fwx_data.match_status |= 0x2;  
	}
	else {
		ct->fwx_data.match_status &= ~0x2;
	}


	if (fwx_match_feature(&flow)){
		ct->fwx_data.app_id = flow.app_id;
		if (flow.app_id < 1000){
			flow.ignore = 1;
		}
		else if (flow.feature && flow.feature->ignore){
			ct->fwx_data.match_status |= 0x1;  
			flow.ignore = 1;
			AF_LMT_DEBUG("gateway set ignore bit, match_status = %u\n", ct->fwx_data.match_status);
		}
		
		if (match_app_filter_rule(flow.app_id, client)) {
			flow.drop = 1;
			ct->fwx_data.action = 1;  
			AF_LMT_INFO("##Drop App filter rule, appid = %d, mac = " MAC_FMT "\n", 
					flow.app_id, MAC_ARRAY(client->mac));
			if (skb->protocol == htons(ETH_P_IP) && g_tcp_rst){
			#if LINUX_VERSION_CODE > KERNEL_VERSION(5,10,197)
				nf_send_reset(&init_net, skb->sk, skb, NF_INET_PRE_ROUTING);
			#elif LINUX_VERSION_CODE > KERNEL_VERSION(4,4,1)


			#else
				nf_send_reset(skb, NF_INET_PRE_ROUTING);
			#endif
			}
			ret = NF_DROP;
		}
	}
	
	if (ret != NF_DROP){
		if (match_mac_filter_rule(client)) {
			flow.drop = 1;
			ct->fwx_data.action = 1;  
			AF_LMT_WARN("##Drop MAC filter rule, mac = " MAC_FMT "\n", 
					MAC_ARRAY(client->mac));
			if (skb->protocol == htons(ETH_P_IP) && g_tcp_rst){
			#if LINUX_VERSION_CODE > KERNEL_VERSION(5,10,197)
				nf_send_reset(&init_net, skb->sk, skb, NF_INET_PRE_ROUTING);
			#elif LINUX_VERSION_CODE > KERNEL_VERSION(4,4,1)


			#else
				nf_send_reset(skb, NF_INET_PRE_ROUTING);
			#endif
			}
			ret = NF_DROP;
		}
	}

	if (g_record_enable){
		if (!flow.ignore){
			int is_http = (flow.http.match || flow.https.match) ? 1 : 0;
			af_update_client_app_info(client, flow.app_id, flow.drop, 0, is_http);
			if (flow.app_id > 0) {
				af_update_active_app_list(client, &flow);
			}
		}

	
		
		af_update_active_host_list(client, &flow);
		
		AF_LMT_INFO("match %s %pI4(%d)--> %pI4(%d) len = %d, %d\n ", IPPROTO_TCP == flow.l4_protocol ? "tcp" : "udp",
					&flow.src, flow.sport, &flow.dst, flow.dport, skb->len, flow.app_id);
	}
	
	if (malloc_data)
	{
		if (flow.l4_data)
		{
			kfree(flow.l4_data);
		}
	}
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static u_int32_t fwx_hook(void *priv,
								 struct sk_buff *skb,
								 const struct nf_hook_state *state)
{
#else
static u_int32_t fwx_hook(unsigned int hook,
								 struct sk_buff *skb,
								 const struct net_device *in,
								 const struct net_device *out,
								 int (*okfn)(struct sk_buff *))
{
#endif

	if (AF_MODE_BYPASS == af_work_mode)
		return NF_ACCEPT;
	return fwx_hook_gateway_handle(skb, skb->dev);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static u_int32_t fwx_by_pass_hook(void *priv,
										 struct sk_buff *skb,
										 const struct nf_hook_state *state)
{
#else
static u_int32_t fwx_by_pass_hook(unsigned int hook,
										 struct sk_buff *skb,
										 const struct net_device *in,
										 const struct net_device *out,
										 int (*okfn)(struct sk_buff *))
{
#endif
	if (AF_MODE_GATEWAY == af_work_mode)
		return NF_ACCEPT;
	return fwx_hook_bypass_handle(skb, skb->dev);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
static struct nf_hook_ops fwx_ops[] __read_mostly = {
	{
		.hook = fwx_hook,
		.pf = NFPROTO_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_MANGLE + 1,

	},
	{
		.hook = fwx_by_pass_hook,
		.pf = NFPROTO_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
};
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static struct nf_hook_ops fwx_ops[] __read_mostly = {
	{
		.hook = fwx_hook,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
	{
		.hook = fwx_by_pass_hook,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
	{
		.hook = fwx_hook,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_MANGLE + 1,

	},
	{
		.hook = fwx_by_pass_hook,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
};
#else
static struct nf_hook_ops fwx_ops[] __read_mostly = {
	{
		.hook = fwx_hook,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
	{
		.hook = fwx_hook,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
};
#endif

struct timer_list fwx_timer;
int report_flag = 0;
#define FWX_TIMER_INTERVAL 1
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
static void fwx_timer_func(struct timer_list *t)
#else
static void fwx_timer_func(unsigned long ptr)
#endif
{
	static int count = 0;
	if (count % 60 == 0)
		check_client_expire();

	count++;
	af_conn_clean_timeout();

	mod_timer(&fwx_timer, jiffies + FWX_TIMER_INTERVAL * HZ);
}

void init_fwx_timer(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
	timer_setup(&fwx_timer, fwx_timer_func, 0);
#else
	setup_timer(&fwx_timer, fwx_timer_func, FWX_TIMER_INTERVAL * HZ);
#endif
	mod_timer(&fwx_timer, jiffies + FWX_TIMER_INTERVAL * HZ);
	AF_INFO("init fwx timer...ok");
}

void fini_fwx_timer(void)
{
	del_timer_sync(&fwx_timer);
	AF_INFO("del fwx timer...ok");
}

	static struct sock *fwx_sock = NULL;

#define FWX_EXTRA_MSG_BUF_LEN 128
int af_send_msg_to_user(char *pbuf, uint16_t len)
{
	struct sk_buff *nl_skb;
	struct nlmsghdr *nlh;
	int buf_len = FWX_EXTRA_MSG_BUF_LEN + len;
	char *msg_buf = NULL;
	struct af_msg_hdr *hdr = NULL;
	char *p_data = NULL;
	int ret;
	if (len >= MAX_FWX_NL_MSG_LEN)
		return -1;

	msg_buf = kmalloc(buf_len, GFP_ATOMIC);
	if (!msg_buf)
		return -1;

	memset(msg_buf, 0x0, buf_len);
	nl_skb = nlmsg_new(len + sizeof(struct af_msg_hdr), GFP_ATOMIC);
	if (!nl_skb)
	{
		ret = -1;
		goto fail;
	}

	nlh = nlmsg_put(nl_skb, 0, 0, FWX_NETLINK_ID, len + sizeof(struct af_msg_hdr), 0);
	if (nlh == NULL)
	{
		nlmsg_free(nl_skb);
		ret = -1;
		goto fail;
	}

	hdr = (struct af_msg_hdr *)msg_buf;
	hdr->magic = 0xa0b0c0d0;
	hdr->len = len;
	p_data = msg_buf + sizeof(struct af_msg_hdr);
	memcpy(p_data, pbuf, len);
	memcpy(nlmsg_data(nlh), msg_buf, len + sizeof(struct af_msg_hdr));
	ret = netlink_unicast(fwx_sock, nl_skb, 999, MSG_DONTWAIT);

fail:
	kfree(msg_buf);
	return ret;
}

static void fwx_user_msg_handle(char *data, int len)
{
	char *msg_data = data + sizeof(af_msg_t);
	if (len < sizeof(af_msg_t))
		return;
	af_msg_t *msg = (af_msg_t *)data;
	switch (msg->action)
	{
	case FWX_NL_MSG_INIT:
		af_client_list_reset_report_num();
		report_flag = 1;
		break;
	case FWX_NL_MSG_ADD_FEATURE:
		af_add_feature_msg_handle(msg_data, len - sizeof(af_msg_t));
		break;
	case FWX_NL_MSG_CLEAN_FEATURE:
		AF_INFO("clean feature\n");
		af_clean_feature_list();
		break;
	default:
		break;
	}
}
static void fwx_netlink_msg_rcv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = NULL;
	char *umsg = NULL;
	void *udata = NULL;
	struct af_msg_hdr *af_hdr = NULL;
	if (skb->len >= nlmsg_total_size(0))
	{
		nlh = nlmsg_hdr(skb);
		umsg = NLMSG_DATA(nlh);
		af_hdr = (struct af_msg_hdr *)umsg;
		if (af_hdr->magic != 0xa0b0c0d0)
			return;
		if (af_hdr->len <= 0 || af_hdr->len >= MAX_FWX_NETLINK_MSG_LEN)
			return;
		udata = umsg + sizeof(struct af_msg_hdr);

		if (udata)
			fwx_user_msg_handle(udata, af_hdr->len);
	}
}

int netlink_fwx_init(void)
{
	struct netlink_kernel_cfg nl_cfg = {0};
	nl_cfg.input = fwx_netlink_msg_rcv;
	fwx_sock = netlink_kernel_create(&init_net, FWX_NETLINK_ID, &nl_cfg);

	if (NULL == fwx_sock)
	{
		AF_ERROR("init fwx netlink failed, id=%d\n", FWX_NETLINK_ID);
		return -1;
	}
	AF_INFO("init fwx netlink ok, id = %d\n", FWX_NETLINK_ID);
	return 0;
}


int af_active_app_init_procfs(void);
void af_active_app_clean_procfs(void);
int af_active_host_init_procfs(void);
void af_active_host_clean_procfs(void);

static int __init fwx_init(void)
{
	int err;
	af_conn_init();
	netlink_fwx_init();
	af_log_init();
	init_af_client_procfs();
	af_client_init();
	af_active_app_init_procfs();
	af_active_host_init_procfs();
	fwx_register_dev();
	fwx_mac_filter_init();
	fwx_app_filter_init();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	err = nf_register_net_hooks(&init_net, fwx_ops, ARRAY_SIZE(fwx_ops));
#else
	err = nf_register_hooks(fwx_ops, ARRAY_SIZE(fwx_ops));
#endif
	if (err)
	{
		AF_ERROR("fwx register filter hooks failed!\n");
	}
	init_fwx_timer();
	printk("fwx: Driver ver. %s - Copyright(c) 2025, fanchmwrt, <www.fanchmwrt.com>\n", AF_VERSION);
	printk("fwx: init ok\n");
	return 0;
}

static void fwx_fini(void)
{
	AF_INFO("fwx module exit\n");
	fini_fwx_timer();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	nf_unregister_net_hooks(&init_net, fwx_ops, ARRAY_SIZE(fwx_ops));
#else
	nf_unregister_hooks(fwx_ops, ARRAY_SIZE(fwx_ops));
#endif
	finit_af_client_procfs();
	af_active_app_clean_procfs();
	af_active_host_clean_procfs();
	af_clean_feature_list();
	af_clear_active_app_list();
	af_clear_active_host_list();
	af_log_exit();
	af_client_exit();
	fwx_app_filter_exit();
	fwx_mac_filter_exit();
	fwx_unregister_dev();
	if (fwx_sock)
		netlink_kernel_release(fwx_sock);
	af_conn_exit();
	return;
}


void af_update_active_app_list(af_client_info_t *client, flow_info_t *flow)
{
	active_app_node_t *node = NULL, *tmp_node = NULL;
	active_app_node_t *new_node = NULL;
	int found = 0;
	int list_count = 0;
	
	if (!client || !flow || flow->app_id == 0)
		return;
	
	spin_lock_bh(&active_app_list_lock);
	
	
	list_for_each_entry_safe(node, tmp_node, &active_app_list, list) {
		list_count++;
		if (node->app_id == flow->app_id) {
			
			memcpy(node->mac, client->mac, MAC_ADDR_LEN);
			node->src_ip = flow->src;
			node->dst_ip = flow->dst;
			if (flow->src6) {
				memcpy(&node->src_ip6, flow->src6, sizeof(struct in6_addr));
			}
			if (flow->dst6) {
				memcpy(&node->dst_ip6, flow->dst6, sizeof(struct in6_addr));
			}
			node->src_port = flow->sport;
			node->dst_port = flow->dport;
			node->l4_protocol = flow->l4_protocol;
			node->drop = flow->drop;
			
			
			if (flow->http.match) {
				node->proto_type = 1;  
				if (flow->http.host_pos && flow->http.host_len > 0) {
					int copy_len = (flow->http.host_len > 31) ? 31 : flow->http.host_len;
					memcpy(node->host, flow->http.host_pos, copy_len);
					node->host[copy_len] = '\0';
				} else {
					node->host[0] = '\0';
				}
				
				if (flow->http.url_pos && flow->http.url_len > 0) {
					int copy_len = (flow->http.url_len > 31) ? 31 : flow->http.url_len;
					memcpy(node->uri, flow->http.url_pos, copy_len);
					node->uri[copy_len] = '\0';
				} else {
					node->uri[0] = '\0';
				}
			} else if (flow->https.match) {
				node->proto_type = 2;  
				if (flow->https.url_pos && flow->https.url_len > 0) {
					int copy_len = (flow->https.url_len > 31) ? 31 : flow->https.url_len;
					memcpy(node->host, flow->https.url_pos, copy_len);
					node->host[copy_len] = '\0';
				} else {
					node->host[0] = '\0';
				}
				
				node->uri[0] = '\0';
			} else {
				node->proto_type = 0;  
				node->host[0] = '\0';
				node->uri[0] = '\0';
			}
			
			node->update_time = ktime_get_real_seconds();
			
			
			list_move(&node->list, &active_app_list);
			
			found = 1;
			break;
		}
	}
	
	
	if (!found) {
		
		if (list_count >= MAX_ACTIVE_APP_LIST_SIZE) {
			if (!list_empty(&active_app_list)) {
				node = list_last_entry(&active_app_list, active_app_node_t, list);
				list_del(&node->list);
				kfree(node);
			}
		}
		
		
		new_node = kzalloc(sizeof(active_app_node_t), GFP_ATOMIC);
		if (new_node) {
			INIT_LIST_HEAD(&new_node->list);
			new_node->app_id = flow->app_id;
			memcpy(new_node->mac, client->mac, MAC_ADDR_LEN);
			new_node->src_ip = flow->src;
			new_node->dst_ip = flow->dst;
			if (flow->src6) {
				memcpy(&new_node->src_ip6, flow->src6, sizeof(struct in6_addr));
			}
			if (flow->dst6) {
				memcpy(&new_node->dst_ip6, flow->dst6, sizeof(struct in6_addr));
			}
			new_node->src_port = flow->sport;
			new_node->dst_port = flow->dport;
			new_node->l4_protocol = flow->l4_protocol;
			new_node->drop = flow->drop;
			
			
			if (flow->http.match) {
				new_node->proto_type = 1;  
				if (flow->http.host_pos && flow->http.host_len > 0) {
					int copy_len = (flow->http.host_len > 31) ? 31 : flow->http.host_len;
					memcpy(new_node->host, flow->http.host_pos, copy_len);
					new_node->host[copy_len] = '\0';
				}
				
				if (flow->http.url_pos && flow->http.url_len > 0) {
					int copy_len = (flow->http.url_len > 31) ? 31 : flow->http.url_len;
					memcpy(new_node->uri, flow->http.url_pos, copy_len);
					new_node->uri[copy_len] = '\0';
				}
			} else if (flow->https.match) {
				new_node->proto_type = 2;  
				if (flow->https.url_pos && flow->https.url_len > 0) {
					int copy_len = (flow->https.url_len > 31) ? 31 : flow->https.url_len;
					memcpy(new_node->host, flow->https.url_pos, copy_len);
					new_node->host[copy_len] = '\0';
				}
				
				new_node->uri[0] = '\0';
			} else {
				new_node->proto_type = 0;  
				new_node->host[0] = '\0';
				new_node->uri[0] = '\0';
			}
			
			new_node->update_time = ktime_get_real_seconds();
			
			
			list_add(&new_node->list, &active_app_list);
		}
	}
	
	spin_unlock_bh(&active_app_list_lock);
}


active_app_node_t *af_find_active_app(u_int32_t app_id)
{
	active_app_node_t *node = NULL;
	
	if (app_id == 0)
		return NULL;
	
	spin_lock_bh(&active_app_list_lock);
	list_for_each_entry(node, &active_app_list, list) {
		if (node->app_id == app_id) {
			spin_unlock_bh(&active_app_list_lock);
			return node;
		}
	}
	spin_unlock_bh(&active_app_list_lock);
	
	return NULL;
}


void af_clear_active_app_list(void)
{
	active_app_node_t *node = NULL, *tmp_node = NULL;
	
	spin_lock_bh(&active_app_list_lock);
	list_for_each_entry_safe(node, tmp_node, &active_app_list, list) {
		list_del(&node->list);
		kfree(node);
	}
	spin_unlock_bh(&active_app_list_lock);
}


void af_update_active_host_list(af_client_info_t *client, flow_info_t *flow)
{
	active_host_node_t *node = NULL, *tmp_node = NULL;
	active_host_node_t *new_node = NULL;
	int found = 0;
	int list_count = 0;
	char host_buf[64] = {0};
	int host_len = 0;
	
	if (!client || !flow)
		return;
	
	
	if (!flow->http.match && !flow->https.match)
		return;
	
	
	if (flow->http.match && flow->http.host_pos && flow->http.host_len > 0) {
		host_len = (flow->http.host_len > 63) ? 63 : flow->http.host_len;
		memcpy(host_buf, flow->http.host_pos, host_len);
		host_buf[host_len] = '\0';
	} else if (flow->https.match && flow->https.url_pos && flow->https.url_len > 0) {
		host_len = (flow->https.url_len > 63) ? 63 : flow->https.url_len;
		memcpy(host_buf, flow->https.url_pos, host_len);
		host_buf[host_len] = '\0';
	} else {
		return;  
	}
	
	spin_lock_bh(&active_host_list_lock);
	
	
	list_for_each_entry_safe(node, tmp_node, &active_host_list, list) {
		list_count++;
		if (strncmp(node->host, host_buf, 64) == 0) {
			
			memcpy(node->mac, client->mac, MAC_ADDR_LEN);
			node->src_ip = flow->src;
			node->dst_ip = flow->dst;
			if (flow->src6) {
				memcpy(&node->src_ip6, flow->src6, sizeof(struct in6_addr));
			}
			if (flow->dst6) {
				memcpy(&node->dst_ip6, flow->dst6, sizeof(struct in6_addr));
			}
			node->src_port = flow->sport;
			node->dst_port = flow->dport;
			node->l4_protocol = flow->l4_protocol;
			node->drop = flow->drop;
			
			
			if (flow->http.match) {
				node->proto_type = 1;  
			} else if (flow->https.match) {
				node->proto_type = 2;  
			} else {
				node->proto_type = 0;  
			}
			
			node->update_time = ktime_get_real_seconds();
			
			
			list_move(&node->list, &active_host_list);
			
			found = 1;
			break;
		}
	}
	
	
	if (!found) {
		
		if (list_count >= MAX_ACTIVE_HOST_LIST_SIZE) {
			if (!list_empty(&active_host_list)) {
				node = list_last_entry(&active_host_list, active_host_node_t, list);
				list_del(&node->list);
				kfree(node);
			}
		}
		
		
		new_node = kzalloc(sizeof(active_host_node_t), GFP_ATOMIC);
		if (new_node) {
			INIT_LIST_HEAD(&new_node->list);
			strncpy(new_node->host, host_buf, 63);
			new_node->host[63] = '\0';
			memcpy(new_node->mac, client->mac, MAC_ADDR_LEN);
			new_node->src_ip = flow->src;
			new_node->dst_ip = flow->dst;
			if (flow->src6) {
				memcpy(&new_node->src_ip6, flow->src6, sizeof(struct in6_addr));
			}
			if (flow->dst6) {
				memcpy(&new_node->dst_ip6, flow->dst6, sizeof(struct in6_addr));
			}
			new_node->src_port = flow->sport;
			new_node->dst_port = flow->dport;
			new_node->l4_protocol = flow->l4_protocol;
			new_node->drop = flow->drop;
			
			
			if (flow->http.match) {
				new_node->proto_type = 1;  
			} else if (flow->https.match) {
				new_node->proto_type = 2;  
			} else {
				new_node->proto_type = 0;  
			}
			
			new_node->update_time = ktime_get_real_seconds();
			
			
			list_add(&new_node->list, &active_host_list);
		}
	}
	
	spin_unlock_bh(&active_host_list_lock);
}


active_host_node_t *af_find_active_host(const char *host)
{
	active_host_node_t *node = NULL;
	
	if (!host || strlen(host) == 0)
		return NULL;
	
	spin_lock_bh(&active_host_list_lock);
	list_for_each_entry(node, &active_host_list, list) {
		if (strncmp(node->host, host, 64) == 0) {
			spin_unlock_bh(&active_host_list_lock);
			return node;
		}
	}
	spin_unlock_bh(&active_host_list_lock);
	
	return NULL;
}


void af_clear_active_host_list(void)
{
	active_host_node_t *node = NULL, *tmp_node = NULL;
	
	spin_lock_bh(&active_host_list_lock);
	list_for_each_entry_safe(node, tmp_node, &active_host_list, list) {
		list_del(&node->list);
		kfree(node);
	}
	spin_unlock_bh(&active_host_list_lock);
}


static void print_active_app_header(struct seq_file *s)
{
	seq_printf(s, "%-6s %-18s %-16s %-8s %-16s %-8s %-6s %-8s %-5s %-32s %-12s %-32s\n",
	           "AppID", "MAC", "SrcIP", "SrcPort", "DstIP", "DstPort", "Proto", "AppProto", "Drop", "Host", "LastUpdate", "URI");
}

static void *af_active_app_seq_start(struct seq_file *s, loff_t *pos)
{
	spin_lock_bh(&active_app_list_lock);
	return seq_list_start(&active_app_list, *pos);
}

static void *af_active_app_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	return seq_list_next(v, &active_app_list, pos);
}

static void af_active_app_seq_stop(struct seq_file *s, void *v)
{
	spin_unlock_bh(&active_app_list_lock);
}

static int af_active_app_seq_show(struct seq_file *s, void *v)
{
	char mac_str[32] = {0};
	char src_ip_str[64] = {0};
	char dst_ip_str[64] = {0};
	char proto_str[8] = {0};
	
	active_app_node_t *node = list_entry(v, active_app_node_t, list);
	
	
	if (v == active_app_list.next)
		print_active_app_header(s);
	
	
	sprintf(mac_str, MAC_FMT, MAC_ARRAY(node->mac));
	
	
	if (node->src_ip != 0) {
		sprintf(src_ip_str, "%pI4", &node->src_ip);
	} else {
		char ip6_str[64] = {0};
		ipv6_to_str(&node->src_ip6, ip6_str);
		sprintf(src_ip_str, "[%s]", ip6_str);
	}
	
	
	if (node->dst_ip != 0) {
		sprintf(dst_ip_str, "%pI4", &node->dst_ip);
	} else {
		char ip6_str[64] = {0};
		ipv6_to_str(&node->dst_ip6, ip6_str);
		sprintf(dst_ip_str, "[%s]", ip6_str);
	}
	
	
	switch (node->l4_protocol) {
		case IPPROTO_TCP:
			strcpy(proto_str, "TCP");
			break;
		case IPPROTO_UDP:
			strcpy(proto_str, "UDP");
			break;
		default:
			sprintf(proto_str, "%d", node->l4_protocol);
			break;
	}
	
	
	seq_printf(s, "%-6u %-18s %-16s %-8u %-16s %-8u %-6s %-8u %-5u %-32s  %-12u  %-32s\n",
	           node->app_id,
	           mac_str,
	           src_ip_str,
	         	 node->src_port,
	           dst_ip_str,
	           node->dst_port,
	           proto_str,
	           node->proto_type,  
	           node->drop,
	           node->host[0] ? node->host : "-",
	           node->update_time,
			
			   (node->proto_type == 1 && node->uri[0]) ? node->uri : "-"  

			);
	
	return 0;
}

static const struct seq_operations af_active_app_seq_ops = {
	.start = af_active_app_seq_start,
	.next = af_active_app_seq_next,
	.stop = af_active_app_seq_stop,
	.show = af_active_app_seq_show
};

static int af_active_app_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &af_active_app_seq_ops);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
static const struct file_operations af_active_app_fops = {
	.owner = THIS_MODULE,
	.open = af_active_app_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};
#else
static const struct proc_ops af_active_app_fops = {
	.proc_flags = PROC_ENTRY_PERMANENT,
	.proc_read = seq_read,
	.proc_open = af_active_app_open,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release_private,
};
#endif

#define AF_ACTIVE_APP_PROC_STR "af_active_app"


int af_active_app_init_procfs(void)
{
	struct proc_dir_entry *pde;
	struct net *net = &init_net;
	
	pde = proc_create(AF_ACTIVE_APP_PROC_STR, 0444, net->proc_net, &af_active_app_fops);
	if (!pde) {
		AF_ERROR("af_active_app proc file created error\n");
		return -1;
	}
	return 0;
}


void af_active_app_clean_procfs(void)
{
	struct net *net = &init_net;
	remove_proc_entry(AF_ACTIVE_APP_PROC_STR, net->proc_net);
}


static void print_active_host_header(struct seq_file *s)
{
	seq_printf(s, "%-48s %-18s %-16s %-8s %-16s %-8s %-6s %-8s %-5s %-12s\n",
	           "Host", "MAC", "SrcIP", "SrcPort", "DstIP", "DstPort", "Proto", "AppProto", "Drop", "LastUpdate");
}

static void *af_active_host_seq_start(struct seq_file *s, loff_t *pos)
{
	spin_lock_bh(&active_host_list_lock);
	return seq_list_start(&active_host_list, *pos);
}

static void *af_active_host_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	return seq_list_next(v, &active_host_list, pos);
}

static void af_active_host_seq_stop(struct seq_file *s, void *v)
{
	spin_unlock_bh(&active_host_list_lock);
}

static int af_active_host_seq_show(struct seq_file *s, void *v)
{
	char mac_str[32] = {0};
	char src_ip_str[64] = {0};
	char dst_ip_str[64] = {0};
	char proto_str[8] = {0};
	
	active_host_node_t *node = list_entry(v, active_host_node_t, list);
	
	
	if (v == active_host_list.next)
		print_active_host_header(s);
	
	
	sprintf(mac_str, MAC_FMT, MAC_ARRAY(node->mac));
	
	
	if (node->src_ip != 0) {
		sprintf(src_ip_str, "%pI4", &node->src_ip);
	} else {
		char ip6_str[64] = {0};
		ipv6_to_str(&node->src_ip6, ip6_str);
		sprintf(src_ip_str, "[%s]", ip6_str);
	}
	
	
	if (node->dst_ip != 0) {
		sprintf(dst_ip_str, "%pI4", &node->dst_ip);
	} else {
		char ip6_str[64] = {0};
		ipv6_to_str(&node->dst_ip6, ip6_str);
		sprintf(dst_ip_str, "[%s]", ip6_str);
	}
	
	
	switch (node->l4_protocol) {
		case IPPROTO_TCP:
			strcpy(proto_str, "TCP");
			break;
		case IPPROTO_UDP:
			strcpy(proto_str, "UDP");
			break;
		default:
			sprintf(proto_str, "%d", node->l4_protocol);
			break;
	}
	
	
	seq_printf(s, "%-48s %-18s %-16s %-8u %-16s %-8u %-6s %-8u %-5u %-12u\n",
	           node->host,
	           mac_str,
	           src_ip_str,
	           node->src_port,
	           dst_ip_str,
	           node->dst_port,
	           proto_str,
	           node->proto_type,  
	           node->drop,
	           node->update_time);
	
	return 0;
}

static const struct seq_operations af_active_host_seq_ops = {
	.start = af_active_host_seq_start,
	.next = af_active_host_seq_next,
	.stop = af_active_host_seq_stop,
	.show = af_active_host_seq_show
};

static int af_active_host_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &af_active_host_seq_ops);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
static const struct file_operations af_active_host_fops = {
	.owner = THIS_MODULE,
	.open = af_active_host_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};
#else
static const struct proc_ops af_active_host_fops = {
	.proc_flags = PROC_ENTRY_PERMANENT,
	.proc_read = seq_read,
	.proc_open = af_active_host_open,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release_private,
};
#endif

#define AF_ACTIVE_HOST_PROC_STR "af_active_host"


int af_active_host_init_procfs(void)
{
	struct proc_dir_entry *pde;
	struct net *net = &init_net;
	
	pde = proc_create(AF_ACTIVE_HOST_PROC_STR, 0444, net->proc_net, &af_active_host_fops);
	if (!pde) {
		AF_ERROR("af_active_host proc file created error\n");
		return -1;
	}
	return 0;
}


void af_active_host_clean_procfs(void)
{
	struct net *net = &init_net;
	remove_proc_entry(AF_ACTIVE_HOST_PROC_STR, net->proc_net);
}

module_init(fwx_init);
module_exit(fwx_fini);

