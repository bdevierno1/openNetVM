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
#include <rte_malloc.h>

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

int
setup_lpm()
{
        struct rte_lpm6_config config;
        int i, status, ret;
        char name[64];

        /* create the LPM table */
        l3switch_req = (struct lpm_request *) rte_malloc(NULL, sizeof(struct lpm_request), 0);

        if (!l3switch_req) return 1;

        snprintf(name, sizeof(name), "fw%d-%"PRIu64, rte_lcore_id(), rte_get_tsc_cycles());
        l3switch_req->max_num_rules = IPV4_L3FWD_LPM_MAX_RULES;
        l3switch_req->num_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
        l3switch_req->socket_id = rte_socket_id();
        snprintf(l3switch_req->name, sizeof(name), "%s", name);
        status = onvm_nflib_request_lpm(l3switch_req);

        if (status < 0) {
                printf("Cannot get lpm region for firewall\n");
                return -1;
        }

        lpm_tbl = rte_lpm_find_existing(name);

        if (lpm_tbl == NULL) {
                printf("No existing LPM_TBL\n");
                return -1;
        }
        /* populate the LPM table */
        for (i = 0; i < IPV4_L3FWD_LPM_NUM_ROUTES; i++) {

                /* skip unused ports */
                if (get_initialized_ports(ipv4_l3fwd_lpm_route_array[i].if_out) == 0)
                        continue;

                ret = rte_lpm_add(lpm_tbl,
                        ipv4_l3fwd_lpm_route_array[i].ip,
                        ipv4_l3fwd_lpm_route_array[i].depth,
                        ipv4_l3fwd_lpm_route_array[i].if_out);

                if (ret < 0) {
                        printf("Unable to add entry %u to the l3fwd LPM table. \n", i);
                        return -1;
                }

                printf("LPM: Adding route 0x%08x / %d (%d)\n",
                        (unsigned)ipv4_l3fwd_lpm_route_array[i].ip,
                        ipv4_l3fwd_lpm_route_array[i].depth,
                        ipv4_l3fwd_lpm_route_array[i].if_out);
        }
        return 0;
}

int
lpm_check_ptype()
{
        for (int portid = 0; portid < ports -> num_ports; portid++) {
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
}

static inline void
lpm_parse_ptype(struct rte_mbuf *m)
{
        struct ether_hdr *eth_hdr;
        uint32_t packet_type = RTE_PTYPE_UNKNOWN;
        uint16_t ether_type;

        eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
        ether_type = eth_hdr->ether_type;
        if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4))
                packet_type |= RTE_PTYPE_L3_IPV4_EXT_UNKNOWN;
        else if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6))
                packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;

        m->packet_type = packet_type;
}

uint16_t
lpm_get_ipv4_dst_port(void *ipv4_hdr, uint16_t portid, void *lookup_struct)
{
        uint32_t next_hop;
        struct rte_lpm *ipv4_l3fwd_lookup_struct =
                (struct rte_lpm *)lookup_struct;

        return (uint16_t) ((rte_lpm_lookup(ipv4_l3fwd_lookup_struct,
                rte_be_to_cpu_32(((struct ipv4_hdr *)ipv4_hdr)->dst_addr),
                &next_hop) == 0) ? next_hop : portid);
}

int
get_initialized_ports(uint8_t if_out) {
        for (int i = 0; i < ports->num_ports; i++) {
                if (ports->id[i] == if_out)
                        return 1;
        }
        return 0;
}

