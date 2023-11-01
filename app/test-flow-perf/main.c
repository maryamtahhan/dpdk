#include "main.h"

static void
usage(char *progname)
{
	printf("\nusage: %s\n", progname);
	printf("\nControl configurations:\n");
	printf("  --rules-count=N: to set the number of needed"
		" rules to insert, default is %d\n", DEFAULT_RULES_COUNT);
	printf("  --rules-batch=N: set number of batched rules,"
		" default is %d\n", DEFAULT_RULES_BATCH);
	printf("  --dump-iterations: To print rates for each"
		" iteration\n");
	printf("  --deletion-rate: Enable deletion rate"
		" calculations\n");
	printf("  --dump-socket-mem: To dump all socket memory\n");
	printf("  --enable-fwd: To enable packets forwarding"
		" after insertion\n");
	printf("  --portmask=N: hexadecimal bitmask of ports used\n");
	printf("  --hairpin-conf=0xXXXX: hexadecimal bitmask of hairpin queue configuration\n");
	printf("  --random-priority=N,S: use random priority levels "
		"from 0 to (N - 1) for flows "
		"and S as seed for pseudo-random number generator\n");
	printf("  --unique-data: flag to set using unique data for all"
		" actions that support data, such as header modify and encap actions\n");
	printf("  --meter-profile=cir,cbs,ebs: set CIR CBS EBS parameters in meter"
		" profile, default values are %d,%d,%d\n", METER_CIR,
		METER_CIR / 8, 0);
	printf("  --packet-mode: to enable packet mode for meter profile\n");

	printf("To set flow attributes:\n");
	printf("  --ingress: set ingress attribute in flows\n");
	printf("  --egress: set egress attribute in flows\n");
	printf("  --transfer: set transfer attribute in flows\n");
	printf("  --group=N: set group for all flows,"
		" default is %d\n", DEFAULT_GROUP);
	printf("  --cores=N: to set the number of needed "
		"cores to insert rte_flow rules, default is 1\n");
	printf("  --rxq=N: to set the count of receive queues\n");
	printf("  --txq=N: to set the count of send queues\n");
	printf("  --rxd=N: to set the count of rxd\n");
	printf("  --txd=N: to set the count of txd\n");
	printf("  --mbuf-size=N: to set the size of mbuf\n");
	printf("  --mbuf-cache-size=N: to set the size of mbuf cache\n");
	printf("  --total-mbuf-count=N: to set the count of total mbuf count\n");


	printf("To set flow items:\n");
	printf("  --ether: add ether layer in flow items\n");
	printf("  --vlan: add vlan layer in flow items\n");
	printf("  --ipv4: add ipv4 layer in flow items\n");
	printf("  --ipv6: add ipv6 layer in flow items\n");
	printf("  --tcp: add tcp layer in flow items\n");
	printf("  --udp: add udp layer in flow items\n");
	printf("  --vxlan: add vxlan layer in flow items\n");
	printf("  --vxlan-gpe: add vxlan-gpe layer in flow items\n");
	printf("  --gre: add gre layer in flow items\n");
	printf("  --geneve: add geneve layer in flow items\n");
	printf("  --gtp: add gtp layer in flow items\n");
	printf("  --meta: add meta layer in flow items\n");
	printf("  --tag: add tag layer in flow items\n");
	printf("  --icmpv4: add icmpv4 layer in flow items\n");
	printf("  --icmpv6: add icmpv6 layer in flow items\n");

	printf("To set flow actions:\n");
	printf("  --port-id: add port-id action in flow actions\n");
	printf("  --rss: add rss action in flow actions\n");
	printf("  --queue: add queue action in flow actions\n");
	printf("  --jump: add jump action in flow actions\n");
	printf("  --mark: add mark action in flow actions\n");
	printf("  --count: add count action in flow actions\n");
	printf("  --set-meta: add set meta action in flow actions\n");
	printf("  --set-tag: add set tag action in flow actions\n");
	printf("  --drop: add drop action in flow actions\n");
	printf("  --hairpin-queue=N: add hairpin-queue action in flow actions\n");
	printf("  --hairpin-rss=N: add hairpin-rss action in flow actions\n");
	printf("  --set-src-mac: add set src mac action to flow actions\n"
		"Src mac to be set is random each flow\n");
	printf("  --set-dst-mac: add set dst mac action to flow actions\n"
		 "Dst mac to be set is random each flow\n");
	printf("  --set-src-ipv4: add set src ipv4 action to flow actions\n"
		"Src ipv4 to be set is random each flow\n");
	printf("  --set-dst-ipv4 add set dst ipv4 action to flow actions\n"
		"Dst ipv4 to be set is random each flow\n");
	printf("  --set-src-ipv6: add set src ipv6 action to flow actions\n"
		"Src ipv6 to be set is random each flow\n");
	printf("  --set-dst-ipv6: add set dst ipv6 action to flow actions\n"
		"Dst ipv6 to be set is random each flow\n");
	printf("  --set-src-tp: add set src tp action to flow actions\n"
		"Src tp to be set is random each flow\n");
	printf("  --set-dst-tp: add set dst tp action to flow actions\n"
		"Dst tp to be set is random each flow\n");
	printf("  --inc-tcp-ack: add inc tcp ack action to flow actions\n"
		"tcp ack will be increments by 1\n");
	printf("  --dec-tcp-ack: add dec tcp ack action to flow actions\n"
		"tcp ack will be decrements by 1\n");
	printf("  --inc-tcp-seq: add inc tcp seq action to flow actions\n"
		"tcp seq will be increments by 1\n");
	printf("  --dec-tcp-seq: add dec tcp seq action to flow actions\n"
		"tcp seq will be decrements by 1\n");
	printf("  --set-ttl: add set ttl action to flow actions\n"
		"L3 ttl to be set is random each flow\n");
	printf("  --dec-ttl: add dec ttl action to flow actions\n"
		"L3 ttl will be decrements by 1\n");
	printf("  --set-ipv4-dscp: add set ipv4 dscp action to flow actions\n"
		"ipv4 dscp value to be set is random each flow\n");
	printf("  --set-ipv6-dscp: add set ipv6 dscp action to flow actions\n"
		"ipv6 dscp value to be set is random each flow\n");
	printf("  --flag: add flag action to flow actions\n");
	printf("  --meter: add meter action to flow actions\n");
	printf("  --policy-mtr=\"g1,g2:y1:r1\": to create meter with specified "
		"colored actions\n");
	printf("  --raw-encap=<data>: add raw encap action to flow actions\n"
		"Data is the data needed to be encaped\n"
		"Example: raw-encap=ether,ipv4,udp,vxlan\n");
	printf("  --raw-decap=<data>: add raw decap action to flow actions\n"
		"Data is the data needed to be decaped\n"
		"Example: raw-decap=ether,ipv4,udp,vxlan\n");
	printf("  --vxlan-encap: add vxlan-encap action to flow actions\n"
		"Encapped data is fixed with pattern: ether,ipv4,udp,vxlan\n"
		"With fixed values\n");
	printf("  --vxlan-decap: add vxlan_decap action to flow actions\n");
}

static void
read_meter_policy(char *prog, char *arg)
{
	char *token;
	size_t i, j, k;

	j = 0;
	k = 0;
	policy_mtr = true;
	token = strsep(&arg, ":\0");
	while (token != NULL && j < RTE_COLORS) {
		actions_str[j++] = token;
		token = strsep(&arg, ":\0");
	}
	j = 0;
	token = strtok(actions_str[0], ",\0");
	while (token == NULL && j < RTE_COLORS - 1)
		token = strtok(actions_str[++j], ",\0");
	while (j < RTE_COLORS && token != NULL) {
		for (i = 0; i < RTE_DIM(flow_options); i++) {
			if (!strcmp(token, flow_options[i].str)) {
				all_actions[j][k++] = flow_options[i].mask;
				break;
			}
		}
		/* Reached last action with no match */
		if (i >= RTE_DIM(flow_options)) {
			fprintf(stderr, "Invalid colored actions: %s\n", token);
			usage(prog);
			rte_exit(EXIT_SUCCESS, "Invalid colored actions\n");
		}
		token = strtok(NULL, ",\0");
		while (!token && j < RTE_COLORS - 1) {
			token = strtok(actions_str[++j], ",\0");
			k = 0;
		}
	}
}

static void
args_parse(int argc, char **argv)
{
	uint64_t pm, seed;
	uint64_t hp_conf;
	char **argvopt;
	uint32_t prio;
	char *token;
	char *end;
	int n, opt;
	int opt_idx;
	size_t i;

	static const struct option lgopts[] = {
		/* Control */
		{ "help",                       0, 0, 0 },
		{ "rules-count",                1, 0, 0 },
		{ "rules-batch",                1, 0, 0 },
		{ "dump-iterations",            0, 0, 0 },
		{ "deletion-rate",              0, 0, 0 },
		{ "dump-socket-mem",            0, 0, 0 },
		{ "enable-fwd",                 0, 0, 0 },
		{ "unique-data",                0, 0, 0 },
		{ "portmask",                   1, 0, 0 },
		{ "hairpin-conf",               1, 0, 0 },
		{ "cores",                      1, 0, 0 },
		{ "random-priority",            1, 0, 0 },
		{ "meter-profile-alg",          1, 0, 0 },
		{ "rxq",                        1, 0, 0 },
		{ "txq",                        1, 0, 0 },
		{ "rxd",                        1, 0, 0 },
		{ "txd",                        1, 0, 0 },
		{ "mbuf-size",                  1, 0, 0 },
		{ "mbuf-cache-size",            1, 0, 0 },
		{ "total-mbuf-count",           1, 0, 0 },
		/* Attributes */
		{ "ingress",                    0, 0, 0 },
		{ "egress",                     0, 0, 0 },
		{ "transfer",                   0, 0, 0 },
		{ "group",                      1, 0, 0 },
		/* Items */
		{ "ether",                      0, 0, 0 },
		{ "vlan",                       0, 0, 0 },
		{ "ipv4",                       0, 0, 0 },
		{ "ipv6",                       0, 0, 0 },
		{ "tcp",                        0, 0, 0 },
		{ "udp",                        0, 0, 0 },
		{ "vxlan",                      0, 0, 0 },
		{ "vxlan-gpe",                  0, 0, 0 },
		{ "gre",                        0, 0, 0 },
		{ "geneve",                     0, 0, 0 },
		{ "gtp",                        0, 0, 0 },
		{ "meta",                       0, 0, 0 },
		{ "tag",                        0, 0, 0 },
		{ "icmpv4",                     0, 0, 0 },
		{ "icmpv6",                     0, 0, 0 },
		/* Actions */
		{ "port-id",                    2, 0, 0 },
		{ "rss",                        0, 0, 0 },
		{ "queue",                      0, 0, 0 },
		{ "jump",                       0, 0, 0 },
		{ "mark",                       0, 0, 0 },
		{ "count",                      0, 0, 0 },
		{ "set-meta",                   0, 0, 0 },
		{ "set-tag",                    0, 0, 0 },
		{ "drop",                       0, 0, 0 },
		{ "hairpin-queue",              1, 0, 0 },
		{ "hairpin-rss",                1, 0, 0 },
		{ "set-src-mac",                0, 0, 0 },
		{ "set-dst-mac",                0, 0, 0 },
		{ "set-src-ipv4",               0, 0, 0 },
		{ "set-dst-ipv4",               0, 0, 0 },
		{ "set-src-ipv6",               0, 0, 0 },
		{ "set-dst-ipv6",               0, 0, 0 },
		{ "set-src-tp",                 0, 0, 0 },
		{ "set-dst-tp",                 0, 0, 0 },
		{ "inc-tcp-ack",                0, 0, 0 },
		{ "dec-tcp-ack",                0, 0, 0 },
		{ "inc-tcp-seq",                0, 0, 0 },
		{ "dec-tcp-seq",                0, 0, 0 },
		{ "set-ttl",                    0, 0, 0 },
		{ "dec-ttl",                    0, 0, 0 },
		{ "set-ipv4-dscp",              0, 0, 0 },
		{ "set-ipv6-dscp",              0, 0, 0 },
		{ "flag",                       0, 0, 0 },
		{ "meter",                      0, 0, 0 },
		{ "raw-encap",                  1, 0, 0 },
		{ "raw-decap",                  1, 0, 0 },
		{ "vxlan-encap",                0, 0, 0 },
		{ "vxlan-decap",                0, 0, 0 },
		{ "policy-mtr",                 1, 0, 0 },
		{ "meter-profile",              1, 0, 0 },
		{ "packet-mode",                0, 0, 0 },
		{ 0, 0, 0, 0 },
	};

	RTE_ETH_FOREACH_DEV(i)
		ports_mask |= 1 << i;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++)
		dst_ports[i] = PORT_ID_DST;

	hairpin_queues_num = 0;
	argvopt = argv;

	printf("\n:: Flow -> ");
	while ((opt = getopt_long(argc, argvopt, "",
				lgopts, &opt_idx)) != EOF) {
		switch (opt) {
		case 0:
			if (strcmp(lgopts[opt_idx].name, "help") == 0) {
				usage(argv[0]);
				exit(EXIT_SUCCESS);
			}

			if (strcmp(lgopts[opt_idx].name, "group") == 0) {
				n = atoi(optarg);
				if (n >= 0)
					flow_group = n;
				else
					rte_exit(EXIT_FAILURE,
						"flow group should be >= 0\n");
				printf("group %d / ", flow_group);
			}

			for (i = 0; i < RTE_DIM(flow_options); i++)
				if (strcmp(lgopts[opt_idx].name,
						flow_options[i].str) == 0) {
					flow_options[i].map[
					(*flow_options[i].map_idx)++] =
						flow_options[i].mask;
					printf("%s / ", flow_options[i].str);
				}

			if (strcmp(lgopts[opt_idx].name,
					"hairpin-rss") == 0) {
				n = atoi(optarg);
				if (n > 0)
					hairpin_queues_num = n;
				else
					rte_exit(EXIT_FAILURE,
						"Hairpin queues should be > 0\n");

				flow_actions[actions_idx++] =
					HAIRPIN_RSS_ACTION;
				printf("hairpin-rss / ");
			}
			if (strcmp(lgopts[opt_idx].name,
					"hairpin-queue") == 0) {
				n = atoi(optarg);
				if (n > 0)
					hairpin_queues_num = n;
				else
					rte_exit(EXIT_FAILURE,
						"Hairpin queues should be > 0\n");

				flow_actions[actions_idx++] =
					HAIRPIN_QUEUE_ACTION;
				printf("hairpin-queue / ");
			}

			if (strcmp(lgopts[opt_idx].name, "raw-encap") == 0) {
				printf("raw-encap ");
				flow_actions[actions_idx++] =
					FLOW_ITEM_MASK(
						RTE_FLOW_ACTION_TYPE_RAW_ENCAP
					);

				token = strtok(optarg, ",");
				while (token != NULL) {
					for (i = 0; i < RTE_DIM(flow_options); i++) {
						if (strcmp(flow_options[i].str, token) == 0) {
							printf("%s,", token);
							encap_data |= flow_options[i].mask;
							break;
						}
						/* Reached last item with no match */
						if (i == (RTE_DIM(flow_options) - 1))
							rte_exit(EXIT_FAILURE,
								"Invalid encap item: %s\n", token);
					}
					token = strtok(NULL, ",");
				}
				printf(" / ");
			}
			if (strcmp(lgopts[opt_idx].name, "raw-decap") == 0) {
				printf("raw-decap ");
				flow_actions[actions_idx++] =
					FLOW_ITEM_MASK(
						RTE_FLOW_ACTION_TYPE_RAW_DECAP
					);

				token = strtok(optarg, ",");
				while (token != NULL) {
					for (i = 0; i < RTE_DIM(flow_options); i++) {
						if (strcmp(flow_options[i].str, token) == 0) {
							printf("%s,", token);
							decap_data |= flow_options[i].mask;
							break;
						}
						/* Reached last item with no match */
						if (i == (RTE_DIM(flow_options) - 1))
							rte_exit(EXIT_FAILURE,
								"Invalid decap item %s\n", token);
					}
					token = strtok(NULL, ",");
				}
				printf(" / ");
			}
			/* Control */
			if (strcmp(lgopts[opt_idx].name,
					"rules-batch") == 0) {
				n = atoi(optarg);
				if (n > 0)
					rules_batch = n;
				else
					rte_exit(EXIT_FAILURE,
							"flow rules-batch should be > 0\n");
			}
			if (strcmp(lgopts[opt_idx].name,
					"rules-count") == 0) {
				rules_count = atoi(optarg);
			}
			if (strcmp(lgopts[opt_idx].name, "random-priority") ==
			    0) {
				end = NULL;
				prio = strtol(optarg, &end, 10);
				if ((optarg[0] == '\0') || (end == NULL))
					rte_exit(EXIT_FAILURE,
						 "Invalid value for random-priority\n");
				max_priority = prio;
				token = end + 1;
				seed = strtoll(token, &end, 10);
				if ((token[0] == '\0') || (*end != '\0'))
					rte_exit(EXIT_FAILURE,
						 "Invalid value for random-priority\n");
				rand_seed = seed;
			}
			if (strcmp(lgopts[opt_idx].name,
					"dump-iterations") == 0)
				dump_iterations = true;
			if (strcmp(lgopts[opt_idx].name,
					"unique-data") == 0)
				unique_data = true;
			if (strcmp(lgopts[opt_idx].name,
					"deletion-rate") == 0)
				delete_flag = true;
			if (strcmp(lgopts[opt_idx].name,
					"dump-socket-mem") == 0)
				dump_socket_mem_flag = true;
			if (strcmp(lgopts[opt_idx].name,
					"enable-fwd") == 0)
				enable_fwd = true;
			if (strcmp(lgopts[opt_idx].name,
					"portmask") == 0) {
				/* parse hexadecimal string */
				end = NULL;
				pm = strtoull(optarg, &end, 16);
				if ((optarg[0] == '\0') || (end == NULL) || (*end != '\0'))
					rte_exit(EXIT_FAILURE, "Invalid fwd port mask\n");
				ports_mask = pm;
			}
			if (strcmp(lgopts[opt_idx].name, "hairpin-conf") == 0) {
				end = NULL;
				hp_conf = strtoull(optarg, &end, 16);
				if ((optarg[0] == '\0') || (end == NULL) || (*end != '\0'))
					rte_exit(EXIT_FAILURE, "Invalid hairpin config mask\n");
				hairpin_conf_mask = hp_conf;
			}
			if (strcmp(lgopts[opt_idx].name,
					"port-id") == 0) {
				uint16_t port_idx = 0;
				char *token;

				token = strtok(optarg, ",");
				while (token != NULL) {
					dst_ports[port_idx++] = atoi(token);
					token = strtok(NULL, ",");
				}
			}
			if (strcmp(lgopts[opt_idx].name, "rxq") == 0) {
				n = atoi(optarg);
				rx_queues_count = (uint8_t) n;
			}
			if (strcmp(lgopts[opt_idx].name, "txq") == 0) {
				n = atoi(optarg);
				tx_queues_count = (uint8_t) n;
			}
			if (strcmp(lgopts[opt_idx].name, "rxd") == 0) {
				n = atoi(optarg);
				rxd_count = (uint8_t) n;
			}
			if (strcmp(lgopts[opt_idx].name, "txd") == 0) {
				n = atoi(optarg);
				txd_count = (uint8_t) n;
			}
			if (strcmp(lgopts[opt_idx].name, "mbuf-size") == 0) {
				n = atoi(optarg);
				mbuf_size = (uint32_t) n;
			}
			if (strcmp(lgopts[opt_idx].name, "mbuf-cache-size") == 0) {
				n = atoi(optarg);
				mbuf_cache_size = (uint32_t) n;
			}
			if (strcmp(lgopts[opt_idx].name, "total-mbuf-count") == 0) {
				n = atoi(optarg);
				total_mbuf_num = (uint32_t) n;
			}
			if (strcmp(lgopts[opt_idx].name, "cores") == 0) {
				n = atoi(optarg);
				if ((int) rte_lcore_count() <= n) {
					rte_exit(EXIT_FAILURE,
						"Error: you need %d cores to run on multi-cores\n"
						"Existing cores are: %d\n", n, rte_lcore_count());
				}
				if (n <= RTE_MAX_LCORE && n > 0)
					mc_pool.cores_count = n;
				else {
					rte_exit(EXIT_FAILURE,
						"Error: cores count must be > 0 and < %d\n",
						RTE_MAX_LCORE);
				}
			}
			if (strcmp(lgopts[opt_idx].name, "policy-mtr") == 0)
				read_meter_policy(argv[0], optarg);
			if (strcmp(lgopts[opt_idx].name,
						"meter-profile") == 0) {
				i = 0;
				token = strsep(&optarg, ",\0");
				while (token != NULL && i < sizeof(
						meter_profile_values) /
						sizeof(uint64_t)) {
					meter_profile_values[i++] = atol(token);
					token = strsep(&optarg, ",\0");
				}
			}
			if (strcmp(lgopts[opt_idx].name, "packet-mode") == 0)
				packet_mode = true;
			break;
		default:
			usage(argv[0]);
			rte_exit(EXIT_FAILURE, "Invalid option: %s\n",
					argv[optind - 1]);
			break;
		}
	}
	if (rules_count % rules_batch != 0) {
		rules_batch = rules_count;
	}
	if (rules_count / rules_batch > MAX_BATCHES_COUNT) {
		rte_exit(EXIT_FAILURE,
			 "rules_count / rules_batch should be <= %d\n",
			 MAX_BATCHES_COUNT);
	}

	printf("end_flow\n");
}

/* Dump the socket memory statistics on console */
static size_t
dump_socket_mem(FILE *f)
{
	struct rte_malloc_socket_stats socket_stats;
	unsigned int i = 0;
	size_t total = 0;
	size_t alloc = 0;
	size_t free = 0;
	unsigned int n_alloc = 0;
	unsigned int n_free = 0;
	bool active_nodes = false;


	for (i = 0; i < RTE_MAX_NUMA_NODES; i++) {
		if (rte_malloc_get_socket_stats(i, &socket_stats) ||
		    !socket_stats.heap_totalsz_bytes)
			continue;
		active_nodes = true;
		total += socket_stats.heap_totalsz_bytes;
		alloc += socket_stats.heap_allocsz_bytes;
		free += socket_stats.heap_freesz_bytes;
		n_alloc += socket_stats.alloc_count;
		n_free += socket_stats.free_count;
		if (dump_socket_mem_flag) {
			fprintf(f, "::::::::::::::::::::::::::::::::::::::::");
			fprintf(f,
				"\nSocket %u:\nsize(M) total: %.6lf\nalloc:"
				" %.6lf(%.3lf%%)\nfree: %.6lf"
				"\nmax: %.6lf"
				"\ncount alloc: %u\nfree: %u\n",
				i,
				socket_stats.heap_totalsz_bytes / 1.0e6,
				socket_stats.heap_allocsz_bytes / 1.0e6,
				(double)socket_stats.heap_allocsz_bytes * 100 /
				(double)socket_stats.heap_totalsz_bytes,
				socket_stats.heap_freesz_bytes / 1.0e6,
				socket_stats.greatest_free_size / 1.0e6,
				socket_stats.alloc_count,
				socket_stats.free_count);
				fprintf(f, "::::::::::::::::::::::::::::::::::::::::");
		}
	}
	if (dump_socket_mem_flag && active_nodes) {
		fprintf(f,
			"\nTotal: size(M)\ntotal: %.6lf"
			"\nalloc: %.6lf(%.3lf%%)\nfree: %.6lf"
			"\ncount alloc: %u\nfree: %u\n",
			total / 1.0e6, alloc / 1.0e6,
			(double)alloc * 100 / (double)total, free / 1.0e6,
			n_alloc, n_free);
		fprintf(f, "::::::::::::::::::::::::::::::::::::::::\n");
	}
	return alloc;
}

static void
print_flow_error(struct rte_flow_error error)
{
	printf("Flow can't be created %d message: %s\n",
		error.type,
		error.message ? error.message : "(no stated reason)");
}

static inline void
print_rules_batches(double *cpu_time_per_batch)
{
	uint8_t idx;
	double delta;
	double rate;

	for (idx = 0; idx < MAX_BATCHES_COUNT; idx++) {
		if (!cpu_time_per_batch[idx])
			break;
		delta = (double)(rules_batch / cpu_time_per_batch[idx]);
		rate = delta / 1000; /* Save rate in K unit. */
		printf(":: Rules batch #%d: %d rules "
			"in %f sec[ Rate = %f K Rule/Sec ]\n",
			idx, rules_batch,
			cpu_time_per_batch[idx], rate);
	}
}

static inline int
has_meter(void)
{
	int i;

	for (i = 0; i < MAX_ACTIONS_NUM; i++) {
		if (flow_actions[i] == 0)
			break;
		if (flow_actions[i]
				& FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_METER))
			return 1;
	}
	return 0;
}

static void
create_meter_policy(void)
{
	struct rte_mtr_error error;
	int ret, port_id;
	struct rte_mtr_meter_policy_params policy;
	uint16_t nr_ports;
	struct rte_flow_action actions[RTE_COLORS][MAX_ACTIONS_NUM];
	int i;

	memset(actions, 0, sizeof(actions));
	memset(&policy, 0, sizeof(policy));
	nr_ports = rte_eth_dev_count_avail();
	for (port_id = 0; port_id < nr_ports; port_id++) {
		for (i = 0; i < RTE_COLORS; i++)
			fill_actions(actions[i], all_actions[i], 0, 0, 0,
				     0, 0, 0, unique_data, rx_queues_count,
				     dst_ports[port_id]);
		policy.actions[RTE_COLOR_GREEN] = actions[RTE_COLOR_GREEN];
		policy.actions[RTE_COLOR_YELLOW] = actions[RTE_COLOR_YELLOW];
		policy.actions[RTE_COLOR_RED] = actions[RTE_COLOR_RED];
		policy_id[port_id] = port_id + 10;
		ret = rte_mtr_meter_policy_add(port_id, policy_id[port_id],
					       &policy, &error);
		if (ret) {
			fprintf(stderr, "port %d: failed to create meter policy\n",
				port_id);
			policy_id[port_id] = UINT32_MAX;
		}
		memset(actions, 0, sizeof(actions));
	}
}

static void
destroy_meter_policy(void)
{
	struct rte_mtr_error error;
	uint16_t nr_ports;
	int port_id;

	nr_ports = rte_eth_dev_count_avail();
	for (port_id = 0; port_id < nr_ports; port_id++) {
		/* If port outside portmask */
		if (!((ports_mask >> port_id) & 0x1))
			continue;

		if (rte_mtr_meter_policy_delete
			(port_id, policy_id[port_id], &error)) {
			fprintf(stderr, "port %u:  failed to  delete meter policy\n",
				port_id);
			rte_exit(EXIT_FAILURE, "Error: Failed to delete meter policy.\n");
		}
	}
}

static void
create_meter_rule(int port_id, uint32_t counter)
{
	int ret;
	struct rte_mtr_params params;
	struct rte_mtr_error error;

	memset(&params, 0, sizeof(struct rte_mtr_params));
	params.meter_enable = 1;
	params.stats_mask = 0xffff;
	params.use_prev_mtr_color = 0;
	params.dscp_table = NULL;

	/*create meter*/
	params.meter_profile_id = DEFAULT_METER_PROF_ID;

	if (!policy_mtr) {
		ret = rte_mtr_create(port_id, counter, &params, 1, &error);
	} else {
		params.meter_policy_id = policy_id[port_id];
		ret = rte_mtr_create(port_id, counter, &params, 0, &error);
	}

	if (ret != 0) {
		printf("Port %u create meter idx(%d) error(%d) message: %s\n",
			port_id, counter, error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "Error in creating meter\n");
	}
}

static void
destroy_meter_rule(int port_id, uint32_t counter)
{
	struct rte_mtr_error error;

	if (policy_mtr && policy_id[port_id] != UINT32_MAX) {
		if (rte_mtr_meter_policy_delete(port_id, policy_id[port_id],
					&error))
			fprintf(stderr, "Error: Failed to delete meter policy\n");
		policy_id[port_id] = UINT32_MAX;
	}
	if (rte_mtr_destroy(port_id, counter, &error)) {
		fprintf(stderr, "Port %d: Failed to delete meter.\n",
				port_id);
		rte_exit(EXIT_FAILURE, "Error in deleting meter rule");
	}
}

static void
meters_handler(int port_id, uint8_t core_id, uint8_t ops)
{
	uint64_t start_batch;
	double cpu_time_used, insertion_rate;
	int rules_count_per_core, rules_batch_idx;
	uint32_t counter, start_counter = 0, end_counter;
	double cpu_time_per_batch[MAX_BATCHES_COUNT] = { 0 };

	rules_count_per_core = rules_count / mc_pool.cores_count;

	if (core_id)
		start_counter = core_id * rules_count_per_core;
	end_counter = (core_id + 1) * rules_count_per_core;

	cpu_time_used = 0;
	start_batch = rte_get_timer_cycles();
	for (counter = start_counter; counter < end_counter; counter++) {
		if (ops == METER_CREATE)
			create_meter_rule(port_id, counter);
		else
			destroy_meter_rule(port_id, counter);
		/*
		 * Save the insertion rate for rules batch.
		 * Check if the insertion reached the rules
		 * patch counter, then save the insertion rate
		 * for this batch.
		 */
		if (!((counter + 1) % rules_batch)) {
			rules_batch_idx = ((counter + 1) / rules_batch) - 1;
			cpu_time_per_batch[rules_batch_idx] =
				((double)(rte_get_timer_cycles() - start_batch))
				/ rte_get_timer_hz();
			cpu_time_used += cpu_time_per_batch[rules_batch_idx];
			start_batch = rte_get_timer_cycles();
		}
	}

	/* Print insertion rates for all batches */
	if (dump_iterations)
		print_rules_batches(cpu_time_per_batch);

	insertion_rate =
		((double) (rules_count_per_core / cpu_time_used) / 1000);

	/* Insertion rate for all rules in one core */
	printf(":: Port %d :: Core %d Meter %s :: start @[%d] - end @[%d],"
		" use:%.02fs, rate:%.02fk Rule/Sec\n",
		port_id, core_id, ops == METER_CREATE ? "create" : "delete",
		start_counter, end_counter - 1,
		cpu_time_used, insertion_rate);

	if (ops == METER_CREATE)
		mc_pool.meters_record.insertion[port_id][core_id]
			= cpu_time_used;
	else
		mc_pool.meters_record.deletion[port_id][core_id]
			= cpu_time_used;
}

static void
destroy_meter_profile(void)
{
	struct rte_mtr_error error;
	uint16_t nr_ports;
	int port_id;

	nr_ports = rte_eth_dev_count_avail();
	for (port_id = 0; port_id < nr_ports; port_id++) {
		/* If port outside portmask */
		if (!((ports_mask >> port_id) & 0x1))
			continue;

		if (rte_mtr_meter_profile_delete
			(port_id, DEFAULT_METER_PROF_ID, &error)) {
			printf("Port %u del profile error(%d) message: %s\n",
				port_id, error.type,
				error.message ? error.message : "(no stated reason)");
			rte_exit(EXIT_FAILURE, "Error: Destroy meter profile Failed!\n");
		}
	}
}

static void
create_meter_profile(void)
{
	uint16_t nr_ports;
	int ret, port_id;
	struct rte_mtr_meter_profile mp;
	struct rte_mtr_error error;

	/*
	 *currently , only create one meter file for one port
	 *1 meter profile -> N meter rules -> N rte flows
	 */
	memset(&mp, 0, sizeof(struct rte_mtr_meter_profile));
	nr_ports = rte_eth_dev_count_avail();
	for (port_id = 0; port_id < nr_ports; port_id++) {
		/* If port outside portmask */
		if (!((ports_mask >> port_id) & 0x1))
			continue;
		mp.alg = RTE_MTR_SRTCM_RFC2697;
		mp.srtcm_rfc2697.cir = meter_profile_values[0] ?
			meter_profile_values[0] : METER_CIR;
		mp.srtcm_rfc2697.cbs = meter_profile_values[1] ?
			meter_profile_values[1] : METER_CIR / 8;
		mp.srtcm_rfc2697.ebs = meter_profile_values[2];
		mp.packet_mode = packet_mode;
		ret = rte_mtr_meter_profile_add
			(port_id, DEFAULT_METER_PROF_ID, &mp, &error);
		if (ret != 0) {
			printf("Port %u create Profile error(%d) message: %s\n",
				port_id, error.type,
				error.message ? error.message : "(no stated reason)");
			rte_exit(EXIT_FAILURE, "Error: Creation meter profile Failed!\n");
		}
	}
}

static inline void
destroy_flows(int port_id, uint8_t core_id, struct rte_flow **flows_list)
{
	struct rte_flow_error error;
	clock_t start_batch, end_batch;
	double cpu_time_used = 0;
	double deletion_rate;
	double cpu_time_per_batch[MAX_BATCHES_COUNT] = { 0 };
	double delta;
	uint32_t i;
	int rules_batch_idx;
	int rules_count_per_core;

	rules_count_per_core = rules_count / mc_pool.cores_count;
	/* If group > 0 , should add 1 flow which created in group 0 */
	if (flow_group > 0 && core_id == 0)
		rules_count_per_core++;

	start_batch = rte_get_timer_cycles();
	for (i = 0; i < (uint32_t) rules_count_per_core; i++) {
		if (flows_list[i] == 0)
			break;

		memset(&error, 0x33, sizeof(error));
		if (rte_flow_destroy(port_id, flows_list[i], &error)) {
			print_flow_error(error);
			rte_exit(EXIT_FAILURE, "Error in deleting flow\n");
		}

		/*
		 * Save the deletion rate for rules batch.
		 * Check if the deletion reached the rules
		 * patch counter, then save the deletion rate
		 * for this batch.
		 */
		if (!((i + 1) % rules_batch)) {
			end_batch = rte_get_timer_cycles();
			delta = (double) (end_batch - start_batch);
			rules_batch_idx = ((i + 1) / rules_batch) - 1;
			cpu_time_per_batch[rules_batch_idx] = delta / rte_get_timer_hz();
			cpu_time_used += cpu_time_per_batch[rules_batch_idx];
			start_batch = rte_get_timer_cycles();
		}
	}

	/* Print deletion rates for all batches */
	if (dump_iterations)
		print_rules_batches(cpu_time_per_batch);

	/* Deletion rate for all rules */
	deletion_rate = ((double) (rules_count_per_core / cpu_time_used) / 1000);
	printf(":: Port %d :: Core %d :: Rules deletion rate -> %f K Rule/Sec\n",
		port_id, core_id, deletion_rate);
	printf(":: Port %d :: Core %d :: The time for deleting %d rules is %f seconds\n",
		port_id, core_id, rules_count_per_core, cpu_time_used);

	mc_pool.flows_record.deletion[port_id][core_id] = cpu_time_used;
}

static struct rte_flow **
insert_flows(int port_id, uint8_t core_id, uint16_t dst_port_id)
{
	struct rte_flow **flows_list;
	struct rte_flow_error error;
	clock_t start_batch, end_batch;
	double first_flow_latency;
	double cpu_time_used;
	double insertion_rate;
	double cpu_time_per_batch[MAX_BATCHES_COUNT] = { 0 };
	double delta;
	uint32_t flow_index;
	uint32_t counter, start_counter = 0, end_counter;
	uint64_t global_items[MAX_ITEMS_NUM] = { 0 };
	uint64_t global_actions[MAX_ACTIONS_NUM] = { 0 };
	int rules_batch_idx;
	int rules_count_per_core;

	rules_count_per_core = rules_count / mc_pool.cores_count;

	/* Set boundaries of rules for each core. */
	if (core_id)
		start_counter = core_id * rules_count_per_core;
	end_counter = (core_id + 1) * rules_count_per_core;

	global_items[0] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH);
	global_actions[0] = FLOW_ITEM_MASK(RTE_FLOW_ACTION_TYPE_JUMP);

	flows_list = rte_zmalloc("flows_list",
		(sizeof(struct rte_flow *) * rules_count_per_core) + 1, 0);
	if (flows_list == NULL)
		rte_exit(EXIT_FAILURE, "No Memory available!\n");

	cpu_time_used = 0;
	flow_index = 0;
	if (flow_group > 0 && core_id == 0) {
		/*
		 * Create global rule to jump into flow_group,
		 * this way the app will avoid the default rules.
		 *
		 * This rule will be created only once.
		 *
		 * Global rule:
		 * group 0 eth / end actions jump group <flow_group>
		 */
		flow = generate_flow(port_id, 0, flow_attrs,
			global_items, global_actions,
			flow_group, 0, 0, 0, 0, dst_port_id, core_id,
			rx_queues_count, unique_data, max_priority, &error);

		if (flow == NULL) {
			print_flow_error(error);
			rte_exit(EXIT_FAILURE, "Error in creating flow\n");
		}
		flows_list[flow_index++] = flow;
	}

	start_batch = rte_get_timer_cycles();
	for (counter = start_counter; counter < end_counter; counter++) {
		flow = generate_flow(port_id, flow_group,
			flow_attrs, flow_items, flow_actions,
			JUMP_ACTION_TABLE, counter,
			hairpin_queues_num, encap_data,
			decap_data, dst_port_id,
			core_id, rx_queues_count,
			unique_data, max_priority, &error);

		if (!counter) {
			first_flow_latency = (double) (rte_get_timer_cycles() - start_batch);
			first_flow_latency /= rte_get_timer_hz();
			/* In millisecond */
			first_flow_latency *= 1000;
			printf(":: First Flow Latency :: Port %d :: First flow "
				"installed in %f milliseconds\n",
				port_id, first_flow_latency);
		}

		if (force_quit)
			counter = end_counter;

		if (!flow) {
			print_flow_error(error);
            if (counter == 0)
                rte_exit(EXIT_FAILURE, "Error in creating n flows\n");

			printf("Error in creating flow maxed out at %d\n", counter);
            rules_count = counter;
            return flows_list;
		}

		flows_list[flow_index++] = flow;

		/*
		 * Save the insertion rate for rules batch.
		 * Check if the insertion reached the rules
		 * patch counter, then save the insertion rate
		 * for this batch.
		 */
		if (!((counter + 1) % rules_batch)) {
			end_batch = rte_get_timer_cycles();
			delta = (double) (end_batch - start_batch);
			rules_batch_idx = ((counter + 1) / rules_batch) - 1;
			cpu_time_per_batch[rules_batch_idx] = delta / rte_get_timer_hz();
			cpu_time_used += cpu_time_per_batch[rules_batch_idx];
			start_batch = rte_get_timer_cycles();
		}
	}

	/* Print insertion rates for all batches */
	if (dump_iterations)
		print_rules_batches(cpu_time_per_batch);

	printf(":: Port %d :: Core %d boundaries :: start @[%d] - end @[%d]\n",
		port_id, core_id, start_counter, end_counter - 1);

	/* Insertion rate for all rules in one core */
	insertion_rate = ((double) (rules_count_per_core / cpu_time_used) / 1000);
	printf(":: Port %d :: Core %d :: Rules insertion rate -> %f K Rule/Sec\n",
		port_id, core_id, insertion_rate);
	printf(":: Port %d :: Core %d :: The time for creating %d in rules %f seconds\n",
		port_id, core_id, rules_count_per_core, cpu_time_used);

	mc_pool.flows_record.insertion[port_id][core_id] = cpu_time_used;
	return flows_list;
}

static void
flows_handler(uint8_t core_id)
{
	struct rte_flow **flows_list;
	uint16_t port_idx = 0;
	uint16_t nr_ports;
	int port_id;

	nr_ports = rte_eth_dev_count_avail();

	if (rules_batch > rules_count)
		rules_batch = rules_count;

	printf(":: Rules Count per port: %d\n\n", rules_count);

	for (port_id = 0; port_id < nr_ports; port_id++) {
		/* If port outside portmask */
		if (!((ports_mask >> port_id) & 0x1))
			continue;

		/* Insertion part. */
		mc_pool.last_alloc[core_id] = (int64_t)dump_socket_mem(stdout);
		if (has_meter())
			meters_handler(port_id, core_id, METER_CREATE);

		flows_list = insert_flows(port_id, core_id,
						dst_ports[port_idx]);
		if (flows_list != NULL && rules_count < mc_pool.rules_count ) {
            uint32_t i;
            struct rte_flow_error error;
            int rules_count_per_core = rules_count / mc_pool.cores_count;

            printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Failed to run test with Rules Count: %d\n\n", mc_pool.rules_count);
            printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>> Rerunning with Rules Count: %d\n\n", rules_count);

            /* Clean up from previous run */
            for (i = 0; i < (uint32_t) rules_count_per_core; i++) {
        		if (flows_list[i] == 0)
        			break;

        		memset(&error, 0x33, sizeof(error));
        		if (rte_flow_destroy(port_id, flows_list[i], &error)) {
        			print_flow_error(error);
        			rte_exit(EXIT_FAILURE, "Error in deleting flow\n");
        		}
            }

            if (has_meter())
				meters_handler(port_id, core_id, METER_DELETE);

            mc_pool.rules_count = rules_count;

            if(rules_batch > rules_count)
               rules_batch = rules_count;

            mc_pool.last_alloc[core_id] = (int64_t)dump_socket_mem(stdout);

            if (has_meter())
			    meters_handler(port_id, core_id, METER_CREATE);

            flows_list = insert_flows(port_id, core_id,
						dst_ports[port_idx]);
            if (flows_list == NULL)
                rte_exit(EXIT_FAILURE, "ERROR RERUNNING THE TEST");
        }
        port_idx++;
		mc_pool.current_alloc[core_id] = (int64_t)dump_socket_mem(stdout);

		/* Deletion part. */
		if (delete_flag) {
			destroy_flows(port_id, core_id, flows_list);
			if (has_meter())
				meters_handler(port_id, core_id, METER_DELETE);
		}
	}
}

static void
dump_used_cpu_time(const char *item,
		uint16_t port, struct used_cpu_time *used_time)
{
	uint32_t i;
	/* Latency: total count of rte rules divided
	 * over max time used by thread between all
	 * threads time.
	 *
	 * Throughput: total count of rte rules divided
	 * over the average of the time consumed by all
	 * threads time.
	 */
	double insertion_latency_time;
	double insertion_throughput_time;
	double deletion_latency_time;
	double deletion_throughput_time;
	double insertion_latency, insertion_throughput;
	double deletion_latency, deletion_throughput;

	/* Save first insertion/deletion rates from first thread.
	 * Start comparing with all threads, if any thread used
	 * time more than current saved, replace it.
	 *
	 * Thus in the end we will have the max time used for
	 * insertion/deletion by one thread.
	 *
	 * As for memory consumption, save the min of all threads
	 * of last alloc, and save the max for all threads for
	 * current alloc.
	 */

	insertion_latency_time = used_time->insertion[port][0];
	deletion_latency_time = used_time->deletion[port][0];
	insertion_throughput_time = used_time->insertion[port][0];
	deletion_throughput_time = used_time->deletion[port][0];

	i = mc_pool.cores_count;
	while (i-- > 1) {
		insertion_throughput_time += used_time->insertion[port][i];
		deletion_throughput_time += used_time->deletion[port][i];
		if (insertion_latency_time < used_time->insertion[port][i])
			insertion_latency_time = used_time->insertion[port][i];
		if (deletion_latency_time < used_time->deletion[port][i])
			deletion_latency_time = used_time->deletion[port][i];
	}

	insertion_latency = ((double) (mc_pool.rules_count
				/ insertion_latency_time) / 1000);
	deletion_latency = ((double) (mc_pool.rules_count
				/ deletion_latency_time) / 1000);

	insertion_throughput_time /= mc_pool.cores_count;
	deletion_throughput_time /= mc_pool.cores_count;
	insertion_throughput = ((double) (mc_pool.rules_count
				/ insertion_throughput_time) / 1000);
	deletion_throughput = ((double) (mc_pool.rules_count
				/ deletion_throughput_time) / 1000);

	/* Latency stats */
	printf("\n%s\n:: [Latency | Insertion] All Cores :: Port %d :: ",
		item, port);
	printf("Total flows insertion rate -> %f K Rules/Sec\n",
		insertion_latency);
	printf(":: [Latency | Insertion] All Cores :: Port %d :: ", port);
	printf("The time for creating %d rules is %f seconds\n",
		mc_pool.rules_count, insertion_latency_time);

	/* Throughput stats */
	printf(":: [Throughput | Insertion] All Cores :: Port %d :: ", port);
	printf("Total flows insertion rate -> %f K Rules/Sec\n",
		insertion_throughput);
	printf(":: [Throughput | Insertion] All Cores :: Port %d :: ", port);
	printf("The average time for creating %d rules is %f seconds\n",
		mc_pool.rules_count, insertion_throughput_time);

	if (delete_flag) {
	/* Latency stats */
		printf(":: [Latency | Deletion] All Cores :: Port %d :: Total "
			"deletion rate -> %f K Rules/Sec\n",
			port, deletion_latency);
		printf(":: [Latency | Deletion] All Cores :: Port %d :: ",
			port);
		printf("The time for deleting %d rules is %f seconds\n",
			mc_pool.rules_count, deletion_latency_time);

		/* Throughput stats */
		printf(":: [Throughput | Deletion] All Cores :: Port %d :: Total "
			"deletion rate -> %f K Rules/Sec\n",
			port, deletion_throughput);
		printf(":: [Throughput | Deletion] All Cores :: Port %d :: ",
			port);
		printf("The average time for deleting %d rules is %f seconds\n",
			mc_pool.rules_count, deletion_throughput_time);
	}
}

static void
dump_used_mem(uint16_t port)
{
	uint32_t i;
	int64_t last_alloc, current_alloc;
	int flow_size_in_bytes;

	last_alloc = mc_pool.last_alloc[0];
	current_alloc = mc_pool.current_alloc[0];

	i = mc_pool.cores_count;
	while (i-- > 1) {
		if (last_alloc > mc_pool.last_alloc[i])
			last_alloc = mc_pool.last_alloc[i];
		if (current_alloc < mc_pool.current_alloc[i])
			current_alloc = mc_pool.current_alloc[i];
	}

	flow_size_in_bytes = (current_alloc - last_alloc) / mc_pool.rules_count;
	printf("\n:: Port %d :: rte_flow size in DPDK layer: %d Bytes\n",
		port, flow_size_in_bytes);
}

static int
run_rte_flow_handler_cores(void *data __rte_unused)
{
	uint16_t port;
	int lcore_counter = 0;
	int lcore_id = rte_lcore_id();
	int i;

	RTE_LCORE_FOREACH(i) {
		/*  If core not needed return. */
		if (lcore_id == i) {
			//printf(":: lcore %d mapped with index %d\n", lcore_id, lcore_counter);
			if (lcore_counter >= (int) mc_pool.cores_count)
				return 0;
			break;
		}
		lcore_counter++;
	}
	lcore_id = lcore_counter;

	if (lcore_id >= (int) mc_pool.cores_count)
		return 0;

	mc_pool.rules_count = rules_count;

	flows_handler(lcore_id);

	/* Only main core to print total results. */
	if (lcore_id != 0)
		return 0;

	/* Make sure all cores finished insertion/deletion process. */
	rte_eal_mp_wait_lcore();

	RTE_ETH_FOREACH_DEV(port) {
		/* If port outside portmask */
		if (!((ports_mask >> port) & 0x1))
			continue;
		if (has_meter())
			dump_used_cpu_time("Meters:",
				port, &mc_pool.meters_record);
		dump_used_cpu_time("Flows:",
			port, &mc_pool.flows_record);
		dump_used_mem(port);
	}

	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		force_quit = true;
	}
}

static inline uint16_t
do_rx(struct lcore_info *li, uint16_t rx_port, uint16_t rx_queue)
{
	uint16_t cnt = 0;
	cnt = rte_eth_rx_burst(rx_port, rx_queue, li->pkts, MAX_PKT_BURST);
	li->rx_pkts += cnt;
	return cnt;
}

static inline void
do_tx(struct lcore_info *li, uint16_t cnt, uint16_t tx_port,
			uint16_t tx_queue)
{
	uint16_t nr_tx = 0;
	uint16_t i;

	nr_tx = rte_eth_tx_burst(tx_port, tx_queue, li->pkts, cnt);
	li->tx_pkts  += nr_tx;
	li->tx_drops += cnt - nr_tx;

	for (i = nr_tx; i < cnt; i++)
		rte_pktmbuf_free(li->pkts[i]);
}

static void
packet_per_second_stats(void)
{
	struct lcore_info *old;
	struct lcore_info *li, *oli;
	int nr_lines = 0;
	int i;

	old = rte_zmalloc("old",
		sizeof(struct lcore_info) * RTE_MAX_LCORE, 0);
	if (old == NULL)
		rte_exit(EXIT_FAILURE, "No Memory available!\n");

	memcpy(old, lcore_infos,
		sizeof(struct lcore_info) * RTE_MAX_LCORE);

	while (!force_quit) {
		uint64_t total_tx_pkts = 0;
		uint64_t total_rx_pkts = 0;
		uint64_t total_tx_drops = 0;
		uint64_t tx_delta, rx_delta, drops_delta;
		int nr_valid_core = 0;

		sleep(1);

		if (nr_lines) {
			char go_up_nr_lines[16];

			sprintf(go_up_nr_lines, "%c[%dA\r", 27, nr_lines);
			printf("%s\r", go_up_nr_lines);
		}

		printf("\n%6s %16s %16s %16s\n", "core", "tx", "tx drops", "rx");
		printf("%6s %16s %16s %16s\n", "------", "----------------",
			"----------------", "----------------");
		nr_lines = 3;
		for (i = 0; i < RTE_MAX_LCORE; i++) {
			li  = &lcore_infos[i];
			oli = &old[i];
			if (li->mode != LCORE_MODE_PKT)
				continue;

			tx_delta    = li->tx_pkts  - oli->tx_pkts;
			rx_delta    = li->rx_pkts  - oli->rx_pkts;
			drops_delta = li->tx_drops - oli->tx_drops;
			printf("%6d %'16"PRId64" %'16"PRId64" %'16"PRId64"\n",
				i, tx_delta, drops_delta, rx_delta);

			total_tx_pkts  += tx_delta;
			total_rx_pkts  += rx_delta;
			total_tx_drops += drops_delta;

			nr_valid_core++;
			nr_lines += 1;
		}

		if (nr_valid_core > 1) {
			printf("%6s %'16"PRId64" %'16"PRId64" %'16"PRId64"\n",
				"total", total_tx_pkts, total_tx_drops,
				total_rx_pkts);
			nr_lines += 1;
		}

		memcpy(old, lcore_infos,
			sizeof(struct lcore_info) * RTE_MAX_LCORE);
	}
}

static int
start_forwarding(void *data __rte_unused)
{
	int lcore = rte_lcore_id();
	int stream_id;
	uint16_t cnt;
	struct lcore_info *li = &lcore_infos[lcore];

	if (!li->mode)
		return 0;

	if (li->mode == LCORE_MODE_STATS) {
		printf(":: started stats on lcore %u\n", lcore);
		packet_per_second_stats();
		return 0;
	}

	while (!force_quit)
		for (stream_id = 0; stream_id < MAX_STREAMS; stream_id++) {
			if (li->streams[stream_id].rx_port == -1)
				continue;

			cnt = do_rx(li,
					li->streams[stream_id].rx_port,
					li->streams[stream_id].rx_queue);
			if (cnt)
				do_tx(li, cnt,
					li->streams[stream_id].tx_port,
					li->streams[stream_id].tx_queue);
		}
	return 0;
}

static void
init_lcore_info(void)
{
	int i, j;
	unsigned int lcore;
	uint16_t nr_port;
	uint16_t queue;
	int port;
	int stream_id = 0;
	int streams_per_core;
	int unassigned_streams;
	int nb_fwd_streams;
	nr_port = rte_eth_dev_count_avail();

	/* First logical core is reserved for stats printing */
	lcore = rte_get_next_lcore(-1, 0, 0);
	lcore_infos[lcore].mode = LCORE_MODE_STATS;

	/*
	 * Initialize all cores
	 * All cores at first must have -1 value in all streams
	 * This means that this stream is not used, or not set
	 * yet.
	 */
	for (i = 0; i < RTE_MAX_LCORE; i++)
		for (j = 0; j < MAX_STREAMS; j++) {
			lcore_infos[i].streams[j].tx_port = -1;
			lcore_infos[i].streams[j].rx_port = -1;
			lcore_infos[i].streams[j].tx_queue = -1;
			lcore_infos[i].streams[j].rx_queue = -1;
			lcore_infos[i].streams_nb = 0;
		}

	/*
	 * Calculate the total streams count.
	 * Also distribute those streams count between the available
	 * logical cores except first core, since it's reserved for
	 * stats prints.
	 */
	nb_fwd_streams = nr_port * rx_queues_count;
	if ((int)(nb_lcores - 1) >= nb_fwd_streams)
		for (i = 0; i < (int)(nb_lcores - 1); i++) {
			lcore = rte_get_next_lcore(lcore, 0, 0);
			lcore_infos[lcore].streams_nb = 1;
		}
	else {
		streams_per_core = nb_fwd_streams / (nb_lcores - 1);
		unassigned_streams = nb_fwd_streams % (nb_lcores - 1);
		for (i = 0; i < (int)(nb_lcores - 1); i++) {
			lcore = rte_get_next_lcore(lcore, 0, 0);
			lcore_infos[lcore].streams_nb = streams_per_core;
			if (unassigned_streams) {
				lcore_infos[lcore].streams_nb++;
				unassigned_streams--;
			}
		}
	}

	/*
	 * Set the streams for the cores according to each logical
	 * core stream count.
	 * The streams is built on the design of what received should
	 * forward as well, this means that if you received packets on
	 * port 0 queue 0 then the same queue should forward the
	 * packets, using the same logical core.
	 */
	lcore = rte_get_next_lcore(-1, 0, 0);
	for (port = 0; port < nr_port; port++) {
		/* Create FWD stream */
		for (queue = 0; queue < rx_queues_count; queue++) {
			if (!lcore_infos[lcore].streams_nb ||
				!(stream_id % lcore_infos[lcore].streams_nb)) {
				lcore = rte_get_next_lcore(lcore, 0, 0);
				lcore_infos[lcore].mode = LCORE_MODE_PKT;
				stream_id = 0;
			}
			lcore_infos[lcore].streams[stream_id].rx_queue = queue;
			lcore_infos[lcore].streams[stream_id].tx_queue = queue;
			lcore_infos[lcore].streams[stream_id].rx_port = port;
			lcore_infos[lcore].streams[stream_id].tx_port = port;
			stream_id++;
		}
	}

	/* Print all streams */
	printf(":: Stream -> core id[N]: (rx_port, rx_queue)->(tx_port, tx_queue)\n");
	for (i = 0; i < RTE_MAX_LCORE; i++)
		for (j = 0; j < MAX_STREAMS; j++) {
			/* No streams for this core */
			if (lcore_infos[i].streams[j].tx_port == -1)
				break;
			printf("Stream -> core id[%d]: (%d,%d)->(%d,%d)\n",
				i,
				lcore_infos[i].streams[j].rx_port,
				lcore_infos[i].streams[j].rx_queue,
				lcore_infos[i].streams[j].tx_port,
				lcore_infos[i].streams[j].tx_queue);
		}
}

const char *
rsstypes_to_str(uint64_t rss_type)
{
	uint16_t i;

	for (i = 0; rss_type_table[i].str != NULL; i++) {
		if (rss_type_table[i].rss_type == rss_type)
			return rss_type_table[i].str;
	}

	return NULL;
}


static void
rss_offload_types_display(uint64_t offload_types, uint16_t char_num_per_line)
{
	uint16_t user_defined_str_len;
	uint16_t total_len = 0;
	uint16_t str_len = 0;
	uint64_t rss_offload;
	uint16_t i;

	for (i = 0; i < sizeof(offload_types) * CHAR_BIT; i++) {
		rss_offload = RTE_BIT64(i);
		if ((offload_types & rss_offload) != 0) {
			const char *p = rsstypes_to_str(rss_offload);

			user_defined_str_len =
				strlen("user-defined-") + (i / 10 + 1);
			str_len = p ? strlen(p) : user_defined_str_len;
			str_len += 2; /* add two spaces */
			if (total_len + str_len >= char_num_per_line) {
				total_len = 0;
				printf("\n");
			}

			if (p)
				printf("  %s", p);
			else
				printf("  user-defined-%u", i);
			total_len += str_len;
		}
	}
	printf("\n");
}

static void
print_dev_capabilities(uint64_t capabilities)
{
	uint64_t single_capa;
	int begin;
	int end;
	int bit;

	if (capabilities == 0)
		return;

	begin = rte_ctz64(capabilities);
	end = sizeof(capabilities) * CHAR_BIT - rte_clz64(capabilities);

	single_capa = 1ULL << begin;
	for (bit = begin; bit < end; bit++) {
		if (capabilities & single_capa)
			printf(" %s",
			       rte_eth_dev_capability_name(single_capa));
		single_capa <<= 1;
	}
}

static void
print_rx_offloads(uint64_t offloads)
{
	uint64_t single_offload;
	int begin;
	int end;
	int bit;

	if (offloads == 0)
		return;

	begin = rte_ctz64(offloads);
	end = sizeof(offloads) * CHAR_BIT - rte_clz64(offloads);

	single_offload = 1ULL << begin;
	for (bit = begin; bit < end; bit++) {
		if (offloads & single_offload)
			printf(" %s",
			       rte_eth_dev_rx_offload_name(single_offload));
		single_offload <<= 1;
	}
}

/*
 * Receive Side Scaling (RSS) configuration.
 */
uint64_t rss_hf = GET_RSS_HF(); /* RSS IP by default. */

static void
init_port(void)
{
	int ret;
	uint16_t std_queue;
	uint16_t hairpin_queue;
	uint16_t port_id;
	uint16_t nr_ports;
	uint16_t nr_queues;
    uint64_t queue_offloads;
	uint64_t port_offloads;
	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
	};
	struct rte_eth_conf port_conf = {
		.rx_adv_conf = {
			.rss_conf.rss_hf = GET_RSS_HF(),
		}
	};

	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;

	nr_queues = rx_queues_count;
	if (hairpin_queues_num != 0)
		nr_queues = rx_queues_count + hairpin_queues_num;


	nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, "Error: no port detected\n");

	mbuf_mp = rte_pktmbuf_pool_create("mbuf_pool",
					total_mbuf_num, mbuf_cache_size,
					0, mbuf_size,
					rte_socket_id());
	if (mbuf_mp == NULL)
		rte_exit(EXIT_FAILURE, "Error: can't init mbuf pool\n");

	for (port_id = 0; port_id < nr_ports; port_id++) {
		uint64_t rx_metadata = 0;

		rx_metadata |= RTE_ETH_RX_METADATA_USER_FLAG;
		rx_metadata |= RTE_ETH_RX_METADATA_USER_MARK;
      	rx_metadata |= RTE_ETH_RX_METADATA_TUNNEL_ID;


		ret = rte_eth_rx_metadata_negotiate(port_id, &rx_metadata);
		if (ret == 0) {
			if (!(rx_metadata & RTE_ETH_RX_METADATA_USER_FLAG)) {
				printf(":: flow action FLAG will not affect Rx mbufs on port=%u\n",
				       port_id);
			}

			if (!(rx_metadata & RTE_ETH_RX_METADATA_USER_MARK)) {
				printf(":: flow action MARK will not affect Rx mbufs on port=%u\n",
				       port_id);
			}

            if (!(rx_metadata & RTE_ETH_RX_METADATA_TUNNEL_ID)) {
			        printf(":: flow tunnel offload support might be limited or unavailable on port %u\n",
				    port_id);
		}
		} else if (ret != -ENOTSUP) {
			rte_exit(EXIT_FAILURE, "Error when negotiating Rx meta features on port=%u: %s\n",
				 port_id, rte_strerror(-ret));
		}

		ret = rte_eth_dev_info_get(port_id, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device"
				" (port %u) info: %s\n",
				port_id, strerror(-ret));

        if (nr_queues > 1) {
    		port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
    		port_conf.rx_adv_conf.rss_conf.rss_hf =
    			rss_hf & dev_info.flow_type_rss_offloads;
    	} else {
    		port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
    		port_conf.rx_adv_conf.rss_conf.rss_hf = 0;
    	}

        printf("\n\nDevice capabilities: 0x%"PRIx64"(", dev_info.dev_capa);
    	print_dev_capabilities(dev_info.dev_capa);
    	printf(" )\n");

    	if (dev_info.hash_key_size > 0)
    		printf("Hash key size in bytes: %u\n", dev_info.hash_key_size);
    	if (dev_info.reta_size > 0)
    		printf("Redirection table size: %u\n", dev_info.reta_size);
    	if (!dev_info.flow_type_rss_offloads)
    		printf("No RSS offload flow type is supported.\n");
    	else {
    		printf("Supported RSS offload flow types:\n");
    		rss_offload_types_display(dev_info.flow_type_rss_offloads,
    				RSS_TYPES_CHAR_NUM_PER_LINE);
    	}

    	/* Show switch info only if valid switch domain and port id is set */
    	if (dev_info.switch_info.domain_id !=
    	 	RTE_ETH_DEV_SWITCH_DOMAIN_ID_INVALID) {
    		if (dev_info.switch_info.name)
    			printf("Switch name: %s\n", dev_info.switch_info.name);

    		printf("Switch domain Id: %u\n",
    			dev_info.switch_info.domain_id);
    		printf("Switch Port Id: %u\n",
    			dev_info.switch_info.port_id);
    		if ((dev_info.dev_capa & RTE_ETH_DEV_CAPA_RXQ_SHARE) != 0)
    			printf("Switch Rx domain: %u\n",
    			       dev_info.switch_info.rx_domain);
    	}

        queue_offloads = dev_info.rx_queue_offload_capa;
        port_offloads = dev_info.rx_offload_capa ^ queue_offloads;

        printf("Rx Offloading Capabilities of port %d :\n", port_id);
        printf("  Per Queue :");
        print_rx_offloads(queue_offloads);

        printf("\n");
        printf("  Per Port  :");
        print_rx_offloads(port_offloads);
        printf("\n\n");


		port_conf.txmode.offloads &= dev_info.tx_offload_capa;
		port_conf.rxmode.offloads &= dev_info.rx_offload_capa;

		printf(":: initializing port: %d\n", port_id);

		ret = rte_eth_dev_configure(port_id, nr_queues,
				nr_queues, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				":: cannot configure device: err=%d, port=%u\n",
				ret, port_id);

		rxq_conf = dev_info.default_rxconf;
		for (std_queue = 0; std_queue < rx_queues_count; std_queue++) {
			ret = rte_eth_rx_queue_setup(port_id, std_queue, rxd_count,
					rte_eth_dev_socket_id(port_id),
					&rxq_conf,
					mbuf_mp);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					":: Rx queue setup failed: err=%d, port=%u\n",
					ret, port_id);
		}

		txq_conf = dev_info.default_txconf;
		for (std_queue = 0; std_queue < tx_queues_count; std_queue++) {
			ret = rte_eth_tx_queue_setup(port_id, std_queue, txd_count,
					rte_eth_dev_socket_id(port_id),
					&txq_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					":: Tx queue setup failed: err=%d, port=%u\n",
					ret, port_id);
		}

		/* Catch all packets from traffic generator. */
		ret = rte_eth_promiscuous_enable(port_id);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				":: promiscuous mode enable failed: err=%s, port=%u\n",
				rte_strerror(-ret), port_id);

		if (hairpin_queues_num != 0) {
			/*
			 * Configure peer which represents hairpin Tx.
			 * Hairpin queue numbers start after standard queues
			 * (rx_queues_count and tx_queues_count).
			 */
			for (hairpin_queue = rx_queues_count, std_queue = 0;
					hairpin_queue < nr_queues;
					hairpin_queue++, std_queue++) {
				hairpin_conf.peers[0].port = port_id;
				hairpin_conf.peers[0].queue =
					std_queue + tx_queues_count;
				hairpin_conf.use_locked_device_memory =
					!!(hairpin_conf_mask & HAIRPIN_RX_CONF_LOCKED_MEMORY);
				hairpin_conf.use_rte_memory =
					!!(hairpin_conf_mask & HAIRPIN_RX_CONF_RTE_MEMORY);
				hairpin_conf.force_memory =
					!!(hairpin_conf_mask & HAIRPIN_RX_CONF_FORCE_MEMORY);
				ret = rte_eth_rx_hairpin_queue_setup(
						port_id, hairpin_queue,
						rxd_count, &hairpin_conf);
				if (ret != 0)
					rte_exit(EXIT_FAILURE,
						":: Hairpin rx queue setup failed: err=%d, port=%u\n",
						ret, port_id);
			}

			for (hairpin_queue = tx_queues_count, std_queue = 0;
					hairpin_queue < nr_queues;
					hairpin_queue++, std_queue++) {
				hairpin_conf.peers[0].port = port_id;
				hairpin_conf.peers[0].queue =
					std_queue + rx_queues_count;
				hairpin_conf.use_locked_device_memory =
					!!(hairpin_conf_mask & HAIRPIN_TX_CONF_LOCKED_MEMORY);
				hairpin_conf.use_rte_memory =
					!!(hairpin_conf_mask & HAIRPIN_TX_CONF_RTE_MEMORY);
				hairpin_conf.force_memory =
					!!(hairpin_conf_mask & HAIRPIN_TX_CONF_FORCE_MEMORY);
				ret = rte_eth_tx_hairpin_queue_setup(
						port_id, hairpin_queue,
						txd_count, &hairpin_conf);
				if (ret != 0)
					rte_exit(EXIT_FAILURE,
						":: Hairpin tx queue setup failed: err=%d, port=%u\n",
						ret, port_id);
			}
		}

		ret = rte_eth_dev_start(port_id);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start:err=%d, port=%u\n",
				ret, port_id);

		printf(":: initializing port: %d done\n", port_id);
	}
}

int
main(int argc, char **argv)
{
	int ret;
	uint16_t port;
	struct rte_flow_error error;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "EAL init failed\n");

	force_quit = false;
	dump_iterations = false;
	rules_count = DEFAULT_RULES_COUNT;
	rules_batch = DEFAULT_RULES_BATCH;
	delete_flag = false;
	dump_socket_mem_flag = false;
	flow_group = DEFAULT_GROUP;
	unique_data = false;

	rx_queues_count = (uint8_t) RXQ_NUM;
	tx_queues_count = (uint8_t) TXQ_NUM;
	rxd_count = (uint8_t) NR_RXD;
	txd_count = (uint8_t) NR_TXD;
	mbuf_size = (uint32_t) MBUF_SIZE;
	mbuf_cache_size = (uint32_t) MBUF_CACHE_SIZE;
	total_mbuf_num = (uint32_t) TOTAL_MBUF_NUM;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	argc -= ret;
	argv += ret;
	if (argc > 1)
		args_parse(argc, argv);

	/* For more fancy, localised integer formatting. */
	setlocale(LC_NUMERIC, "");

	init_port();

	nb_lcores = rte_lcore_count();
	if (nb_lcores <= 1)
		rte_exit(EXIT_FAILURE, "This app needs at least two cores\n");

	printf(":: Flows Count per port: %d\n", rules_count);

	rte_srand(rand_seed);

	if (has_meter()) {
		create_meter_profile();
		if (policy_mtr)
			create_meter_policy();
	}
	rte_eal_mp_remote_launch(run_rte_flow_handler_cores, NULL, CALL_MAIN);

	if (enable_fwd) {
		init_lcore_info();
		rte_eal_mp_remote_launch(start_forwarding, NULL, CALL_MAIN);
	}
	if (has_meter() && delete_flag) {
		destroy_meter_profile();
		if (policy_mtr)
			destroy_meter_policy();
	}

	RTE_ETH_FOREACH_DEV(port) {
		rte_flow_flush(port, &error);
		if (rte_eth_dev_stop(port) != 0)
			printf("Failed to stop device on port %u\n", port);
		rte_eth_dev_close(port);
	}
	printf("\nBye ...\n");
	return 0;
}
