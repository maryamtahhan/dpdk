/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 *
 * This file contain the application main file
 * This application provides the user the ability to test the
 * insertion rate for specific rte_flow rule under stress state ~4M rule/
 *
 * Then it will also provide packet per second measurement after installing
 * all rules, the user may send traffic to test the PPS that match the rules
 * after all rules are installed, to check performance or functionality after
 * the stress.
 *
 * The flows insertion will go for all ports first, then it will print the
 * results, after that the application will go into forwarding packets mode
 * it will start receiving traffic if any and then forwarding it back and
 * gives packet per second measurement.
 */

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>

#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
//#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mtr.h>

#include "config.h"
#include "actions_gen.h"
#include "flow_gen.h"

#define MAX_BATCHES_COUNT          100
#define DEFAULT_RULES_COUNT    4000000
#define DEFAULT_RULES_BATCH     100000
#define DEFAULT_GROUP                0

#define HAIRPIN_RX_CONF_FORCE_MEMORY  (0x0001)
#define HAIRPIN_TX_CONF_FORCE_MEMORY  (0x0002)

#define HAIRPIN_RX_CONF_LOCKED_MEMORY (0x0010)
#define HAIRPIN_RX_CONF_RTE_MEMORY    (0x0020)

#define HAIRPIN_TX_CONF_LOCKED_MEMORY (0x0100)
#define HAIRPIN_TX_CONF_RTE_MEMORY    (0x0200)

struct rte_flow *flow;
struct rte_flow_item *flow_template_item;
uint8_t flow_group;

uint64_t encap_data;
uint64_t decap_data;
uint64_t all_actions[RTE_COLORS][MAX_ACTIONS_NUM];
char *actions_str[RTE_COLORS];

uint64_t flow_items[MAX_ITEMS_NUM];
uint64_t flow_actions[MAX_ACTIONS_NUM];
uint64_t flow_attrs[MAX_ATTRS_NUM];
uint32_t policy_id[MAX_PORTS];
uint8_t items_idx, actions_idx, attrs_idx;

uint64_t ports_mask;
uint64_t hairpin_conf_mask;
uint16_t dst_ports[RTE_MAX_ETHPORTS];
volatile bool force_quit;
bool dump_iterations;
bool delete_flag;
bool dump_socket_mem_flag;
bool enable_fwd;
bool unique_data;
bool policy_mtr;
bool packet_mode;

uint8_t rx_queues_count;
uint8_t tx_queues_count;
uint8_t rxd_count;
uint8_t txd_count;
uint32_t mbuf_size;
uint32_t mbuf_cache_size;
uint32_t total_mbuf_num;

struct rte_mempool *mbuf_mp;
uint32_t nb_lcores;
uint32_t rules_count;
uint32_t rules_batch;
uint32_t hairpin_queues_num; /* total hairpin q number - default: 0 */
uint32_t use_template;
uint32_t nb_lcores;
uint8_t max_priority;
uint32_t rand_seed;
uint64_t meter_profile_values[3]; /* CIR CBS EBS values. */

#define MAX_PKT_BURST    32
#define LCORE_MODE_PKT    1
#define LCORE_MODE_STATS  2
#define MAX_STREAMS      64
#define METER_CREATE	  1
#define METER_DELETE	  2

struct stream {
	int tx_port;
	int tx_queue;
	int rx_port;
	int rx_queue;
};

struct lcore_info {
	int mode;
	int streams_nb;
	struct stream streams[MAX_STREAMS];
	/* stats */
	uint64_t tx_pkts;
	uint64_t tx_drops;
	uint64_t rx_pkts;
	struct rte_mbuf *pkts[MAX_PKT_BURST];
} __rte_cache_aligned;

struct lcore_info lcore_infos[RTE_MAX_LCORE];

struct used_cpu_time {
	double insertion[MAX_PORTS][RTE_MAX_LCORE];
	double deletion[MAX_PORTS][RTE_MAX_LCORE];
};

struct multi_cores_pool {
	uint32_t cores_count;
	uint32_t rules_count;
	struct used_cpu_time meters_record;
	struct used_cpu_time flows_record;
	int64_t last_alloc[RTE_MAX_LCORE];
	int64_t current_alloc[RTE_MAX_LCORE];
} __rte_cache_aligned;

static const struct option_dict {
	const char *str;
	const uint64_t mask;
	uint64_t *map;
	uint8_t *map_idx;

} flow_options[] = {
	{
		.str = "ether",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "ipv4",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV4),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "ipv6",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV6),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "vlan",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_VLAN),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "tcp",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_TCP),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "udp",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_UDP),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "vxlan",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_VXLAN),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "vxlan-gpe",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_VXLAN_GPE),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "gre",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_GRE),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "geneve",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_GENEVE),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "gtp",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_GTP),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "meta",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_META),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "tag",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_TAG),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "icmpv4",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ICMP),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "icmpv6",
		.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ICMP6),
		.map = &flow_items[0],
		.map_idx = &items_idx
	},
	{
		.str = "ingress",
		.mask = INGRESS,
		.map = &flow_attrs[0],
		.map_idx = &attrs_idx
	},
	{
		.str = "egress",
		.mask = EGRESS,
		.map = &flow_attrs[0],
		.map_idx = &attrs_idx
	},
	{
		.str = "transfer",
		.mask = TRANSFER,
		.map = &flow_attrs[0],
		.map_idx = &attrs_idx
	},
	{
		.str = "port-id",
		.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_PORT_ID),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "rss",
		.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_RSS),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "queue",
		.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_QUEUE),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "jump",
		.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_JUMP),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "mark",
		.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_MARK),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "count",
		.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_COUNT),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "set-meta",
		.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_META),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "set-tag",
		.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_TAG),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "drop",
		.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_DROP),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "set-src-mac",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_SET_MAC_SRC
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "set-dst-mac",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_SET_MAC_DST
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "set-src-ipv4",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "set-dst-ipv4",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_SET_IPV4_DST
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "set-src-ipv6",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "set-dst-ipv6",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_SET_IPV6_DST
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "set-src-tp",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_SET_TP_SRC
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "set-dst-tp",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_SET_TP_DST
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "inc-tcp-ack",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_INC_TCP_ACK
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "dec-tcp-ack",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "inc-tcp-seq",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "dec-tcp-seq",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "set-ttl",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_SET_TTL
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "dec-ttl",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_DEC_TTL
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "set-ipv4-dscp",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_SET_IPV4_DSCP
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "set-ipv6-dscp",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_SET_IPV6_DSCP
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "flag",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_FLAG
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "meter",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_METER
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "vxlan-encap",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
	{
		.str = "vxlan-decap",
		.mask = FLOW_ACTION_MASK(
			RTE_FLOW_ACTION_TYPE_VXLAN_DECAP
		),
		.map = &flow_actions[0],
		.map_idx = &actions_idx
	},
};

const char *rsstypes_to_str(uint64_t rss_type);

/** Information for a given RSS type. */
typedef struct rss_type_info {
	const char *str; /**< Type name. */
	uint64_t rss_type; /**< Type value. */
} rss_type_info_t;

// /** Descriptor for a flow table. */
// struct port_table {
// 	struct port_table *next; /**< Next table in list. */
// 	struct port_table *tmp; /**< Temporary linking. */
// 	uint32_t id; /**< Table ID. */
// 	uint32_t nb_pattern_templates; /**< Number of pattern templates. */
// 	uint32_t nb_actions_templates; /**< Number of actions templates. */
// 	struct rte_flow_attr flow_attr; /**< Flow attributes. */
// 	struct rte_flow_template_table *table; /**< PMD opaque template object */
// };

/** Descriptor for a template. */
struct port_template {
	struct port_template *next; /**< Next template in list. */
	struct port_template *tmp; /**< Temporary linking. */
	uint32_t id; /**< Template ID. */
	union {
		struct rte_flow_pattern_template *pattern_template;
		struct rte_flow_actions_template *actions_template;
	} template; /**< PMD opaque template object */
};


enum print_warning {
	ENABLED_WARN = 0,
	DISABLED_WARN
};

#define RTE_PORT_ALL            (~(uint16_t)0x0)

void init_port(void) ;
int port_flow_get_info(uint16_t port_id);
int port_flow_get_info_all(void);
int
port_flow_configure(uint16_t port_id,
	const struct rte_flow_port_attr *port_attr,
	uint16_t nb_queue,
	const struct rte_flow_queue_attr *queue_attr);

int port_id_is_invalid(uint16_t port_id, enum print_warning warning);
void print_dev_capabilities(uint64_t capabilities);
void rss_offload_types_display(uint64_t offload_types,
                      uint16_t char_num_per_line);
int port_flow_complain(struct rte_flow_error *error);
int port_flow_pattern_template_create(uint16_t port_id, uint32_t id,
				      const struct rte_flow_pattern_template_attr *attr,
				      const struct rte_flow_item *pattern,
                      struct port_template *pattern_templ_list);
int
port_flow_pattern_template_destroy(uint16_t port_id, uint32_t n,
				   const uint32_t *template,
                   struct port_template *pattern_templ_list);
int
port_flow_pattern_template_flush(uint16_t port_id,
                                 struct port_template *pattern_templ_list);
#if 0
int port_flow_actions_template_create(uint16_t port_id, uint32_t id,
				      const struct rte_flow_actions_template_attr *attr,
				      const struct rte_flow_action *actions,
				      const struct rte_flow_action *masks,
                      struct port_template *actions_templ_list);
int port_flow_actions_template_destroy(uint16_t port_id, uint32_t n,
				       const uint32_t *template);
int port_flow_actions_template_flush(uint16_t port_id);
int port_flow_template_table_create(uint16_t port_id, uint32_t id,
		   const struct rte_flow_template_table_attr *table_attr,
		   uint32_t nb_pattern_templates, uint32_t *pattern_templates,
		   uint32_t nb_actions_templates, uint32_t *actions_templates);
int port_flow_template_table_destroy(uint16_t port_id,
			    uint32_t n, const uint32_t *table);
int port_flow_template_table_flush(uint16_t port_id);
#endif
