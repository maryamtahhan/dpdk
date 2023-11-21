#include <rte_flow.h>
#include <rte_ethdev.h>

#include "main.h"

#define NUM_QUEUES 1

static int
template_alloc(uint32_t id, struct port_template **template,
           struct port_template **list)
{
    struct port_template *lst = *list;
    struct port_template **ppt;
    struct port_template *pt = NULL;

    *template = NULL;
    if (id == UINT32_MAX) {
        /* taking first available ID */
        if (lst) {
            if (lst->id == UINT32_MAX - 1) {
                printf("Highest template ID is already"
                " assigned, delete it first\n");
                return -ENOMEM;
            }
            id = lst->id + 1;
        } else {
            id = 0;
        }
    }
    pt = calloc(1, sizeof(*pt));
    if (!pt) {
        printf("Allocation of port template failed\n");
        return -ENOMEM;
    }
    ppt = list;
    while (*ppt && (*ppt)->id > id)
        ppt = &(*ppt)->next;
    if (*ppt && (*ppt)->id == id) {
        printf("Template #%u is already assigned,"
            " delete it first\n", id);
        free(pt);
        return -EINVAL;
    }
    pt->next = *ppt;
    pt->id = id;
    *ppt = pt;
    *template = pt;
    return 0;
}


/** Get info about flow management resources. */
int
port_flow_get_info(uint16_t port_id)
{
    int err;
    struct rte_flow_port_info port_info;
    struct rte_flow_queue_info queue_info;
    struct rte_flow_error error;
    struct rte_eth_conf pconf;
    struct rte_eth_dev_info dev_info;

    memset(&dev_info, 0, sizeof(dev_info));
    memset(&pconf, 0, sizeof(pconf));

    err = rte_eth_dev_info_get(port_id, &dev_info);
    if (err != 0)
        return -err;

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

    /* Poisoning to make sure PMDs update it in case of error. */
    memset(&error, 0x99, sizeof(error));
    memset(&port_info, 0, sizeof(port_info));
    memset(&queue_info, 0, sizeof(queue_info));
    err = rte_flow_info_get(port_id, &port_info, &queue_info, &error) ;
    if (err < 0)
        return port_flow_complain(&error);
    printf(":: Flow engine resources on port %u:\n"
           "Number of queues: %d\n"
           "Size of queues: %d\n"
           "Number of counters: %d\n"
           "Number of aging objects: %d\n"
           "Number of meter actions: %d\n",
           port_id, port_info.max_nb_queues,
           queue_info.max_size,
           port_info.max_nb_counters,
           port_info.max_nb_aging_objects,
           port_info.max_nb_meters);

    return 0;
}

#define NUM_QUEUES 1
/** Get info about flow management resources. */
int
port_flow_get_info_all(void)
{
    uint16_t port_id, nr_ports;
    int err;
    struct rte_eth_conf pconf;

    nr_ports = rte_eth_dev_count_avail();
    if (nr_ports == 0)
        rte_exit(EXIT_FAILURE, "Error: no port detected\n");

    for (port_id = 0; port_id < nr_ports; port_id++) {
        memset(&pconf, 0, sizeof(pconf));

        if (port_id_is_invalid(port_id, ENABLED_WARN))
            return -1;

        err = rte_eth_dev_configure(port_id, NUM_QUEUES,
                NUM_QUEUES, &pconf);
        if (err < 0)
            rte_exit(EXIT_FAILURE,
                ":: cannot configure device: err=%d, port=%u\n",
                err, port_id);
        err = port_flow_get_info(port_id);
        if (err < 0)
            rte_exit(EXIT_FAILURE,
                ":: cannot retrieve flow info "
                "for (port %u): %s\n",
                port_id, strerror(-err));
    }

    return 0;
}
#if 0
static int
table_alloc(uint32_t id, struct port_table **table,
        struct port_table **list)
{
    struct port_table *lst = *list;
    struct port_table **ppt;
    struct port_table *pt = NULL;

    *table = NULL;
    if (id == UINT32_MAX) {
        /* taking first available ID */
        if (lst) {
            if (lst->id == UINT32_MAX - 1) {
                printf("Highest table ID is already"
                " assigned, delete it first\n");
                return -ENOMEM;
            }
            id = lst->id + 1;
        } else {
            id = 0;
        }
    }
    pt = calloc(1, sizeof(*pt));
    if (!pt) {
        printf("Allocation of table failed\n");
        return -ENOMEM;
    }
    ppt = list;
    while (*ppt && (*ppt)->id > id)
        ppt = &(*ppt)->next;
    if (*ppt && (*ppt)->id == id) {
        printf("Table #%u is already assigned,"
            " delete it first\n", id);
        free(pt);
        return -EINVAL;
    }
    pt->next = *ppt;
    pt->id = id;
    *ppt = pt;
    *table = pt;
    return 0;
}
#endif
/** Create pattern template */
int
port_flow_pattern_template_create(uint16_t port_id, uint32_t id,
                  const struct rte_flow_pattern_template_attr *attr,
                  const struct rte_flow_item *pattern,
                  struct port_template *pattern_templ_list)
{
   // struct rte_port *port;
    struct port_template *pit;
    int ret;
    struct rte_flow_error error;

    ret = template_alloc(id, &pit, &pattern_templ_list);
    if (ret)
        return ret;
    /* Poisoning to make sure PMDs update it in case of error. */
    memset(&error, 0x22, sizeof(error));
    pit->template.pattern_template = rte_flow_pattern_template_create(port_id,
                        attr, pattern, &error);
    if (!pit->template.pattern_template) {
        uint32_t destroy_id = pit->id;
        port_flow_pattern_template_destroy(port_id, 1,
                            &destroy_id, pattern_templ_list);
        return port_flow_complain(&error);
    }
    printf(" :::::::: Pattern template #%u created::::::::::\n", pit->id);
    return 0;
}

/** Destroy pattern template */
int
port_flow_pattern_template_destroy(uint16_t port_id, uint32_t n,
                   const uint32_t *template,
                   struct port_template *pattern_templ_list)
{
   // struct rte_port *port;
    struct port_template **tmp;
    int ret = 0;

    tmp = &pattern_templ_list;
    while (*tmp) {
        uint32_t i;

        for (i = 0; i != n; ++i) {
            struct rte_flow_error error;
            struct port_template *pit = *tmp;

            if (template[i] != pit->id)
                continue;
            /*
             * Poisoning to make sure PMDs update it in case
             * of error.
             */
            memset(&error, 0x33, sizeof(error));

            if (pit->template.pattern_template &&
                rte_flow_pattern_template_destroy(port_id,
                               pit->template.pattern_template,
                               &error)) {
                ret = port_flow_complain(&error);
                continue;
            }
            *tmp = pit->next;
            printf("Pattern template #%u destroyed\n", pit->id);
            free(pit);
            break;
        }
        if (i == n)
            tmp = &(*tmp)->next;
    }
    return ret;
}

/** Flush pattern template */
int
port_flow_pattern_template_flush(uint16_t port_id,
                                 struct port_template *pattern_templ_list)
{
    //struct rte_port *port;
    struct port_template **tmp;
    int ret = 0;

    tmp = &pattern_templ_list;
    while (*tmp) {
        struct rte_flow_error error;
        struct port_template *pit = *tmp;

        /*
         * Poisoning to make sure PMDs update it in case
         * of error.
         */
        memset(&error, 0x33, sizeof(error));
        if (pit->template.pattern_template &&
            rte_flow_pattern_template_destroy(port_id,
            pit->template.pattern_template, &error)) {
            printf("Pattern template #%u not destroyed\n", pit->id);
            ret = port_flow_complain(&error);
            tmp = &pit->next;
        } else {
            *tmp = pit->next;
            free(pit);
        }
    }
    return ret;
}

#if 0
/** Create actions template */
int
port_flow_actions_template_create(uint16_t port_id, uint32_t id,
                  const struct rte_flow_actions_template_attr *attr,
                  const struct rte_flow_action *actions,
                  const struct rte_flow_action *masks,
                  struct port_template *actions_templ_list)
{
    struct rte_port *port;
    struct port_template *pat;
    int ret;
    struct rte_flow_error error;

    if (port_id_is_invalid(port_id, ENABLED_WARN) ||
        port_id == (uint16_t)RTE_PORT_ALL)
        return -EINVAL;
    ret = template_alloc(id, &pat, &actions_templ_list);
    if (ret)
        return ret;
    /* Poisoning to make sure PMDs update it in case of error. */
    memset(&error, 0x22, sizeof(error));
    pat->template.actions_template = rte_flow_actions_template_create(port_id,
                        attr, actions, masks, &error);
    if (!pat->template.actions_template) {
        uint32_t destroy_id = pat->id;
        port_flow_actions_template_destroy(port_id, 1, &destroy_id);
        return port_flow_complain(&error);
    }
    printf("Actions template #%u created\n", pat->id);
    return 0;
}

/** Destroy actions template */
int
port_flow_actions_template_destroy(uint16_t port_id, uint32_t n,
                   const uint32_t *template)
{
    struct rte_port *port;
    struct port_template **tmp;
    int ret = 0;

    if (port_id_is_invalid(port_id, ENABLED_WARN) ||
        port_id == (uint16_t)RTE_PORT_ALL)
        return -EINVAL;
    port = &ports[port_id];
    tmp = &port->actions_templ_list;
    while (*tmp) {
        uint32_t i;

        for (i = 0; i != n; ++i) {
            struct rte_flow_error error;
            struct port_template *pat = *tmp;

            if (template[i] != pat->id)
                continue;
            /*
             * Poisoning to make sure PMDs update it in case
             * of error.
             */
            memset(&error, 0x33, sizeof(error));

            if (pat->template.actions_template &&
                rte_flow_actions_template_destroy(port_id,
                    pat->template.actions_template, &error)) {
                ret = port_flow_complain(&error);
                continue;
            }
            *tmp = pat->next;
            printf("Actions template #%u destroyed\n", pat->id);
            free(pat);
            break;
        }
        if (i == n)
            tmp = &(*tmp)->next;
    }
    return ret;
}

/** Flush actions template */
int
port_flow_actions_template_flush(uint16_t port_id)
{
    struct rte_port *port;
    struct port_template **tmp;
    int ret = 0;

    if (port_id_is_invalid(port_id, ENABLED_WARN) ||
        port_id == (uint16_t)RTE_PORT_ALL)
        return -EINVAL;
    port = &ports[port_id];
    tmp = &port->actions_templ_list;
    while (*tmp) {
        struct rte_flow_error error;
        struct port_template *pat = *tmp;

        /*
         * Poisoning to make sure PMDs update it in case
         * of error.
         */
        memset(&error, 0x33, sizeof(error));

        if (pat->template.actions_template &&
            rte_flow_actions_template_destroy(port_id,
            pat->template.actions_template, &error)) {
            ret = port_flow_complain(&error);
            printf("Actions template #%u not destroyed\n", pat->id);
            tmp = &pat->next;
        } else {
            *tmp = pat->next;
            free(pat);
        }
    }
    return ret;
}

/** Create table */
int
port_flow_template_table_create(uint16_t port_id, uint32_t id,
        const struct rte_flow_template_table_attr *table_attr,
        uint32_t nb_pattern_templates, uint32_t *pattern_templates,
        uint32_t nb_actions_templates, uint32_t *actions_templates)
{
    struct rte_port *port;
    struct port_table *pt;
    struct port_template *temp = NULL;
    int ret;
    uint32_t i;
    struct rte_flow_error error;
    struct rte_flow_pattern_template
            *flow_pattern_templates[nb_pattern_templates];
    struct rte_flow_actions_template
            *flow_actions_templates[nb_actions_templates];

    if (port_id_is_invalid(port_id, ENABLED_WARN) ||
        port_id == (uint16_t)RTE_PORT_ALL)
        return -EINVAL;
    port = &ports[port_id];
    for (i = 0; i < nb_pattern_templates; ++i) {
        bool found = false;
        temp = port->pattern_templ_list;
        while (temp) {
            if (pattern_templates[i] == temp->id) {
                flow_pattern_templates[i] =
                    temp->template.pattern_template;
                found = true;
                break;
            }
            temp = temp->next;
        }
        if (!found) {
            printf("Pattern template #%u is invalid\n",
                   pattern_templates[i]);
            return -EINVAL;
        }
    }
    for (i = 0; i < nb_actions_templates; ++i) {
        bool found = false;
        temp = port->actions_templ_list;
        while (temp) {
            if (actions_templates[i] == temp->id) {
                flow_actions_templates[i] =
                    temp->template.actions_template;
                found = true;
                break;
            }
            temp = temp->next;
        }
        if (!found) {
            printf("Actions template #%u is invalid\n",
                   actions_templates[i]);
            return -EINVAL;
        }
    }
    ret = table_alloc(id, &pt, &port->table_list);
    if (ret)
        return ret;
    /* Poisoning to make sure PMDs update it in case of error. */
    memset(&error, 0x22, sizeof(error));
    pt->table = rte_flow_template_table_create(port_id, table_attr,
              flow_pattern_templates, nb_pattern_templates,
              flow_actions_templates, nb_actions_templates,
              &error);

    if (!pt->table) {
        uint32_t destroy_id = pt->id;
        port_flow_template_table_destroy(port_id, 1, &destroy_id);
        return port_flow_complain(&error);
    }
    pt->nb_pattern_templates = nb_pattern_templates;
    pt->nb_actions_templates = nb_actions_templates;
    rte_memcpy(&pt->flow_attr, &table_attr->flow_attr,
           sizeof(struct rte_flow_attr));
    printf("Template table #%u created\n", pt->id);
    return 0;
}

/** Destroy table */
int
port_flow_template_table_destroy(uint16_t port_id,
                 uint32_t n, const uint32_t *table)
{
    struct rte_port *port;
    struct port_table **tmp;
    int ret = 0;

    if (port_id_is_invalid(port_id, ENABLED_WARN) ||
        port_id == (uint16_t)RTE_PORT_ALL)
        return -EINVAL;
    port = &ports[port_id];
    tmp = &port->table_list;
    while (*tmp) {
        uint32_t i;

        for (i = 0; i != n; ++i) {
            struct rte_flow_error error;
            struct port_table *pt = *tmp;

            if (table[i] != pt->id)
                continue;
            /*
             * Poisoning to make sure PMDs update it in case
             * of error.
             */
            memset(&error, 0x33, sizeof(error));

            if (pt->table &&
                rte_flow_template_table_destroy(port_id,
                                pt->table,
                                &error)) {
                ret = port_flow_complain(&error);
                continue;
            }
            *tmp = pt->next;
            printf("Template table #%u destroyed\n", pt->id);
            free(pt);
            break;
        }
        if (i == n)
            tmp = &(*tmp)->next;
    }
    return ret;
}

/** Flush table */
int
port_flow_template_table_flush(uint16_t port_id)
{
    struct rte_port *port;
    struct port_table **tmp;
    int ret = 0;

    if (port_id_is_invalid(port_id, ENABLED_WARN) ||
        port_id == (uint16_t)RTE_PORT_ALL)
        return -EINVAL;
    port = &ports[port_id];
    tmp = &port->table_list;
    while (*tmp) {
        struct rte_flow_error error;
        struct port_table *pt = *tmp;

        /*
         * Poisoning to make sure PMDs update it in case
         * of error.
         */
        memset(&error, 0x33, sizeof(error));

        if (pt->table &&
            rte_flow_template_table_destroy(port_id,
                           pt->table,
                           &error)) {
            ret = port_flow_complain(&error);
            printf("Template table #%u not destroyed\n", pt->id);
            tmp = &pt->next;
        } else {
            *tmp = pt->next;
            free(pt);
        }
    }
    return ret;
}
#endif
