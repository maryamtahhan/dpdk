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
static uint8_t flow_group;

static uint64_t encap_data;
static uint64_t decap_data;
static uint64_t all_actions[RTE_COLORS][MAX_ACTIONS_NUM];
static char *actions_str[RTE_COLORS];

static uint64_t flow_items[MAX_ITEMS_NUM];
static uint64_t flow_actions[MAX_ACTIONS_NUM];
static uint64_t flow_attrs[MAX_ATTRS_NUM];
static uint32_t policy_id[MAX_PORTS];
static uint8_t items_idx, actions_idx, attrs_idx;

static uint64_t ports_mask;
static uint64_t hairpin_conf_mask;
static uint16_t dst_ports[RTE_MAX_ETHPORTS];
static volatile bool force_quit;
static bool dump_iterations;
static bool delete_flag;
static bool dump_socket_mem_flag;
static bool enable_fwd;
static bool unique_data;
static bool policy_mtr;
static bool packet_mode;

static uint8_t rx_queues_count;
static uint8_t tx_queues_count;
static uint8_t rxd_count;
static uint8_t txd_count;
static uint32_t mbuf_size;
static uint32_t mbuf_cache_size;
static uint32_t total_mbuf_num;

static struct rte_mempool *mbuf_mp;
static uint32_t nb_lcores;
static uint32_t rules_count;
static uint32_t rules_batch;
static uint32_t hairpin_queues_num; /* total hairpin q number - default: 0 */
static uint32_t nb_lcores;
static uint8_t max_priority;
static uint32_t rand_seed;
static uint64_t meter_profile_values[3]; /* CIR CBS EBS values. */

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

static struct lcore_info lcore_infos[RTE_MAX_LCORE];

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

static struct multi_cores_pool mc_pool = {
	.cores_count = 1,
};

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

rss_type_info_t rss_type_table[] = {
	/* Group types */
	{ "all", RTE_ETH_RSS_ETH | RTE_ETH_RSS_VLAN | RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP |
		RTE_ETH_RSS_UDP | RTE_ETH_RSS_SCTP | RTE_ETH_RSS_L2_PAYLOAD |
		RTE_ETH_RSS_L2TPV3 | RTE_ETH_RSS_ESP | RTE_ETH_RSS_AH | RTE_ETH_RSS_PFCP |
		RTE_ETH_RSS_GTPU | RTE_ETH_RSS_ECPRI | RTE_ETH_RSS_MPLS | RTE_ETH_RSS_L2TPV2},
	{ "none", 0 },
	{ "ip", RTE_ETH_RSS_IP },
	{ "udp", RTE_ETH_RSS_UDP },
	{ "tcp", RTE_ETH_RSS_TCP },
	{ "sctp", RTE_ETH_RSS_SCTP },
	{ "tunnel", RTE_ETH_RSS_TUNNEL },
	{ "vlan", RTE_ETH_RSS_VLAN },

	/* Individual type */
	{ "ipv4", RTE_ETH_RSS_IPV4 },
	{ "ipv4-frag", RTE_ETH_RSS_FRAG_IPV4 },
	{ "ipv4-tcp", RTE_ETH_RSS_NONFRAG_IPV4_TCP },
	{ "ipv4-udp", RTE_ETH_RSS_NONFRAG_IPV4_UDP },
	{ "ipv4-sctp", RTE_ETH_RSS_NONFRAG_IPV4_SCTP },
	{ "ipv4-other", RTE_ETH_RSS_NONFRAG_IPV4_OTHER },
	{ "ipv6", RTE_ETH_RSS_IPV6 },
	{ "ipv6-frag", RTE_ETH_RSS_FRAG_IPV6 },
	{ "ipv6-tcp", RTE_ETH_RSS_NONFRAG_IPV6_TCP },
	{ "ipv6-udp", RTE_ETH_RSS_NONFRAG_IPV6_UDP },
	{ "ipv6-sctp", RTE_ETH_RSS_NONFRAG_IPV6_SCTP },
	{ "ipv6-other", RTE_ETH_RSS_NONFRAG_IPV6_OTHER },
	{ "l2-payload", RTE_ETH_RSS_L2_PAYLOAD },
	{ "ipv6-ex", RTE_ETH_RSS_IPV6_EX },
	{ "ipv6-tcp-ex", RTE_ETH_RSS_IPV6_TCP_EX },
	{ "ipv6-udp-ex", RTE_ETH_RSS_IPV6_UDP_EX },
	{ "port", RTE_ETH_RSS_PORT },
	{ "vxlan", RTE_ETH_RSS_VXLAN },
	{ "geneve", RTE_ETH_RSS_GENEVE },
	{ "nvgre", RTE_ETH_RSS_NVGRE },
	{ "gtpu", RTE_ETH_RSS_GTPU },
	{ "eth", RTE_ETH_RSS_ETH },
	{ "s-vlan", RTE_ETH_RSS_S_VLAN },
	{ "c-vlan", RTE_ETH_RSS_C_VLAN },
	{ "esp", RTE_ETH_RSS_ESP },
	{ "ah", RTE_ETH_RSS_AH },
	{ "l2tpv3", RTE_ETH_RSS_L2TPV3 },
	{ "pfcp", RTE_ETH_RSS_PFCP },
	{ "pppoe", RTE_ETH_RSS_PPPOE },
	{ "ecpri", RTE_ETH_RSS_ECPRI },
	{ "mpls", RTE_ETH_RSS_MPLS },
	{ "ipv4-chksum", RTE_ETH_RSS_IPV4_CHKSUM },
	{ "l4-chksum", RTE_ETH_RSS_L4_CHKSUM },
	{ "l2tpv2", RTE_ETH_RSS_L2TPV2 },
	{ "l3-pre96", RTE_ETH_RSS_L3_PRE96 },
	{ "l3-pre64", RTE_ETH_RSS_L3_PRE64 },
	{ "l3-pre56", RTE_ETH_RSS_L3_PRE56 },
	{ "l3-pre48", RTE_ETH_RSS_L3_PRE48 },
	{ "l3-pre40", RTE_ETH_RSS_L3_PRE40 },
	{ "l3-pre32", RTE_ETH_RSS_L3_PRE32 },
	{ "l2-dst-only", RTE_ETH_RSS_L2_DST_ONLY },
	{ "l2-src-only", RTE_ETH_RSS_L2_SRC_ONLY },
	{ "l4-dst-only", RTE_ETH_RSS_L4_DST_ONLY },
	{ "l4-src-only", RTE_ETH_RSS_L4_SRC_ONLY },
	{ "l3-dst-only", RTE_ETH_RSS_L3_DST_ONLY },
	{ "l3-src-only", RTE_ETH_RSS_L3_SRC_ONLY },
	{ NULL, 0},
};
