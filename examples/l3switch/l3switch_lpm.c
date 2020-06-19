#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "l3switch.h"

/* Shared data structure containing host port info. */
extern struct port_info *ports;

struct ipv4_l3fwd_lpm_route {
        uint32_t ip;
        uint8_t  depth;
        uint8_t  if_out;
};

struct ipv6_l3fwd_lpm_route {
        uint8_t ip[16];
        uint8_t  depth;
        uint8_t  if_out;
};

static struct ipv4_l3fwd_lpm_route ipv4_l3fwd_lpm_route_array[] = {
        {IPv4(1, 1, 1, 0), 24, 0},
        {IPv4(2, 1, 1, 0), 24, 1},
        {IPv4(3, 1, 1, 0), 24, 2},
        {IPv4(4, 1, 1, 0), 24, 3},
        {IPv4(5, 1, 1, 0), 24, 4},
        {IPv4(6, 1, 1, 0), 24, 5},
        {IPv4(7, 1, 1, 0), 24, 6},
        {IPv4(8, 1, 1, 0), 24, 7},
};

static struct ipv6_l3fwd_lpm_route ipv6_l3fwd_lpm_route_array[] = {
        {{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 0},
        {{2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 1},
        {{3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 2},
        {{4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 3},
        {{5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 4},
        {{6, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 5},
        {{7, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 6},
        {{8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 7},
};

#define IPV4_L3FWD_LPM_NUM_ROUTES \
        (sizeof(ipv4_l3fwd_lpm_route_array) / sizeof(ipv4_l3fwd_lpm_route_array[0]))
#define IPV6_L3FWD_LPM_NUM_ROUTES \
        (sizeof(ipv6_l3fwd_lpm_route_array) / sizeof(ipv6_l3fwd_lpm_route_array[0]))

#define IPV4_L3FWD_LPM_MAX_RULES         1024
#define IPV4_L3FWD_LPM_NUMBER_TBL8S (1 << 8)
#define IPV6_L3FWD_LPM_MAX_RULES         1024
#define IPV6_L3FWD_LPM_NUMBER_TBL8S (1 << 16)

struct rte_lpm *ipv4_l3fwd_lpm_lookup_struct[NB_SOCKETS];
struct rte_lpm6 *ipv6_l3fwd_lpm_lookup_struct[NB_SOCKETS];

int
get_initialized_ports(uint8_t if_out) {
        for (int i = 0; i < ports->num_ports; i++) {
                if (ports->id[i] == if_out)
                        return 1;
        }
        return 0;
}
void
setup_lpm(const int socketid)
{
        struct rte_lpm6_config config;
        struct rte_lpm_config config_ipv4;
        unsigned i;
        int ret;
        char s[64];

        /* create the LPM table */
        config_ipv4.max_rules = IPV4_L3FWD_LPM_MAX_RULES;
        config_ipv4.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
        config_ipv4.flags = 0;
        snprintf(s, sizeof(s), "IPV4_L3FWD_LPM_%d", socketid);
        ipv4_l3fwd_lpm_lookup_struct[socketid] =
                        rte_lpm_create(s, socketid, &config_ipv4);
        if (ipv4_l3fwd_lpm_lookup_struct[socketid] == NULL)
                rte_exit(EXIT_FAILURE,
                        "Unable to create the l3fwd LPM table on socket %d\n",
                        socketid);
        /* populate the LPM table */
        for (i = 0; i < IPV4_L3FWD_LPM_NUM_ROUTES; i++) {

                /* skip unused ports */
                if (get_initialized_ports(ipv4_l3fwd_lpm_route_array[i].if_out) == 0)
                        continue;

                ret = rte_lpm_add(ipv4_l3fwd_lpm_lookup_struct[socketid],
                        ipv4_l3fwd_lpm_route_array[i].ip,
                        ipv4_l3fwd_lpm_route_array[i].depth,
                        ipv4_l3fwd_lpm_route_array[i].if_out);

                if (ret < 0) {
                        rte_exit(EXIT_FAILURE,
                                "Unable to add entry %u to the l3fwd LPM table on socket %d\n",
                                i, socketid);
                }

                printf("LPM: Adding route 0x%08x / %d (%d)\n",
                        (unsigned)ipv4_l3fwd_lpm_route_array[i].ip,
                        ipv4_l3fwd_lpm_route_array[i].depth,
                        ipv4_l3fwd_lpm_route_array[i].if_out);
        }

        /* create the LPM6 table */
        snprintf(s, sizeof(s), "IPV6_L3FWD_LPM_%d", socketid);

        config.max_rules = IPV6_L3FWD_LPM_MAX_RULES;
        config.number_tbl8s = IPV6_L3FWD_LPM_NUMBER_TBL8S;
        config.flags = 0;
        ipv6_l3fwd_lpm_lookup_struct[socketid] = rte_lpm6_create(s, socketid,
                                &config);
        if (ipv6_l3fwd_lpm_lookup_struct[socketid] == NULL)
                rte_exit(EXIT_FAILURE,
                        "Unable to create the l3fwd LPM table on socket %d\n",
                        socketid);

        /* populate the LPM table */
        for (i = 0; i < IPV6_L3FWD_LPM_NUM_ROUTES; i++) {
                /* skip unused ports */
                if (get_initialized_ports(ipv4_l3fwd_lpm_route_array[i].if_out) == 0)
                        continue;

                ret = rte_lpm6_add(ipv6_l3fwd_lpm_lookup_struct[socketid],
                        ipv6_l3fwd_lpm_route_array[i].ip,
                        ipv6_l3fwd_lpm_route_array[i].depth,
                        ipv6_l3fwd_lpm_route_array[i].if_out);

                if (ret < 0) {
                        rte_exit(EXIT_FAILURE,
                                "Unable to add entry %u to the l3fwd LPM table on socket %d\n",
                                i, socketid);
                }

                printf("LPM: Adding route %s / %d (%d)\n",
                        "IPV6",
                        ipv6_l3fwd_lpm_route_array[i].depth,
                        ipv6_l3fwd_lpm_route_array[i].if_out);
        }
}

int
lpm_check_ptype(int portid)
{
        int i, ret;
        int ptype_l3_ipv4 = 0, ptype_l3_ipv6 = 0;
        uint32_t ptype_mask = RTE_PTYPE_L3_MASK;

        ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
        if (ret <= 0)
                return 0;

        uint32_t ptypes[ret];

        ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
        for (i = 0; i < ret; ++i) {
                if (ptypes[i] & RTE_PTYPE_L3_IPV4)
                        ptype_l3_ipv4 = 1;
                if (ptypes[i] & RTE_PTYPE_L3_IPV6)
                        ptype_l3_ipv6 = 1;
        }

        if (ptype_l3_ipv4 == 0)
                printf("port %d cannot parse RTE_PTYPE_L3_IPV4\n", portid);

        if (ptype_l3_ipv6 == 0)
                printf("port %d cannot parse RTE_PTYPE_L3_IPV6\n", portid);

        if (ptype_l3_ipv4 && ptype_l3_ipv6)
                return 1;

        return 0;

}
