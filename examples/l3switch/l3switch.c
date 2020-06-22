/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2020 George Washington University
 *            2015-2020 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * l3switch.c - send all packets from one port out the adjacent port.
 ********************************************************************/


#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "l3switch.h"

#define NF_TAG "l3switch"

uint32_t hash_entry_number = HASH_ENTRY_NUMBER_DEFAULT;

uint64_t packets_dropped;

/* Number of package between each print. */
static uint32_t print_delay = 1000000;

/* Select Longest-Prefix or Exact match. */
static int l3fwd_lpm_on = 1;
static int l3fwd_em_on = 0;

/* ethernet addresses of ports */
uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];
struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

xmm_t val_eth[RTE_MAX_ETHPORTS];

struct l3fwd_lkp_mode {
    int  (*setup)(void);
    int  (*check_ptype)(int);
};

static struct l3fwd_lkp_mode l3fwd_lkp;

static struct l3fwd_lkp_mode l3fwd_em_lkp = {
    .setup                  = setup_lpm,
    .check_ptype            = lpm_check_ptype,
};

static struct l3fwd_lkp_mode l3fwd_lpm_lkp = {
    .setup                  = setup_lpm,
    .check_ptype            = lpm_check_ptype,
};


uint64_t port_statistics[RTE_MAX_ETHPORTS];

static void
setup_l3fwd_lookup_tables(void)
{
    /* Setup HASH lookup functions. */
    if (l3fwd_em_on)
        l3fwd_lkp = l3fwd_em_lkp;
    /* Setup LPM lookup functions. */
    else
        l3fwd_lkp = l3fwd_lpm_lkp;
}

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf("%s [EAL args] -- [NF_LIB args] -- -p <print_delay>\n", progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
        printf(" -  -e : Enable exact match. \n");
        printf(" - `-l : Enable longest prefix match. \n");
        printf(" - `-h : Specifies the hash entry number in decimal to be setup. Default is 4. \n");
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c;

        while ((c = getopt(argc, argv, "h:e")) != -1) {
                switch (c) {
                        case 'h':
                                hash_entry_number = strtoul(optarg, NULL, 10);
                                break;
                        case 'p':
                                print_delay = strtoul(optarg, NULL, 10);
                                break;
                        case 'e':
                                l3fwd_lpm_on = 0;
                                l3fwd_em_on = 1;
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'p')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (isprint(optopt))
                                        RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                                else
                                        RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                                return -1;
                        default:
                                usage(progname);
                                return -1;
                }
        }
        return optind;
}

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
print_stats(void) {
        const char clr[] = {27, '[', '2', 'J', '\0'};
        const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
        uint64_t total_packets;

        /* Clear screen and move to top left */
        printf("\nPort statistics ====================================");
        int i;
	for (i = 0; i < ports->num_ports; i++) {
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %20"PRIu64,
			   ports->id[i],
			   port_statistics[ports->id[i]]);

		total_packets += port_statistics[ports->id[i]];
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
                   "\nPackets dropped: %18"PRIu64,
		   total_packets,
                   packets_dropped);
	printf("\n====================================================\n");

        printf("\n\n");
}

static int
lpm_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        static uint32_t counter = 0;
        if (counter++ == print_delay) {
               print_stats();
               counter = 0;
        }
        struct ether_hdr *eth_hdr;
        struct ipv4_hdr *ipv4_hdr;
        uint16_t dst_port;

        eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

        if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
                /* Handle IPv4 headers.*/
                ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *,
                                                   sizeof(struct ether_hdr));

#ifdef DO_RFC_1812_CHECKS
                /* Check to make sure the packet is valid (RFC1812) */
                if (is_valid_ipv4_pkt(ipv4_hdr, m->pkt_len) < 0) {
                        rte_pktmbuf_free(m);
                        return;
                }
#endif
                dst_port = lpm_get_ipv4_dst_port(ipv4_hdr, pkt->port,
                                                 lpm_tbl);

                if (dst_port >= RTE_MAX_ETHPORTS ||
                        get_initialized_ports(dst_port) == 0)
                        dst_port = pkt->port;

#ifdef DO_RFC_1812_CHECKS
                /* Update time to live and header checksum */
                --(ipv4_hdr->time_to_live);
                ++(ipv4_hdr->hdr_checksum);
#endif
                /* dst addr */
                *(uint64_t *)&eth_hdr->d_addr = dest_eth_addr[dst_port];

                /* src addr */
                ether_addr_copy(&ports_eth_addr[dst_port], &eth_hdr->s_addr);

                meta->destination = dst_port;
                port_statistics[dst_port]++;
        } else {
                meta->action = ONVM_NF_ACTION_DROP;
                packets_dropped++;
        }
        return 0;
}

/*
 * This function displays the ethernet addressof each initialized port.
 * It saves the ethernet addresses in the struct ether_addr array.
 */
static void
l3fwd_initialize_ports(void) {
        uint16_t i;
        for (i = 0; i < ports->num_ports; i++) {
                rte_eth_macaddr_get(ports->id[i], &ports_eth_addr[ports->id[i]]);
                printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                        ports->id[i],
                        ports_eth_addr[ports->id[i]].addr_bytes[0],
                        ports_eth_addr[ports->id[i]].addr_bytes[1],
                        ports_eth_addr[ports->id[i]].addr_bytes[2],
                        ports_eth_addr[ports->id[i]].addr_bytes[3],
                        ports_eth_addr[ports->id[i]].addr_bytes[4],
                        ports_eth_addr[ports->id[i]].addr_bytes[5]);
        }
}

static void
l3fwd_initialize_dst(void) {
        uint16_t i;
        /* pre-init dst MACs for all ports to 02:00:00:00:00:xx */
        for (i = 0; i < ports->num_ports; i++) {
                dest_eth_addr[ports->id[i]] =
                        ETHER_LOCAL_ADMIN_ADDR + ((uint64_t)ports->id[i] << 40);
                *(uint64_t *)(val_eth + ports->id[i]) = dest_eth_addr[ports->id[i]];
        }
}

int
main(int argc, char *argv[]) {
        int arg_offset;
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        const char *progname = argv[0];

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();
        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &lpm_handler;

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                if (arg_offset == ONVM_SIGNAL_TERMINATION) {
                        printf("Exiting due to user termination\n");
                        return 0;
                } else {
                        rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
                }
        }

        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }
        /*
         * Hash flags are valid only for
         * exact macth, reset them to default for
         * longest-prefix match.
         */
        if (l3fwd_lpm_on) {
                hash_entry_number = HASH_ENTRY_NUMBER_DEFAULT;
                printf("Longest prefix match enabled. \n");
        } else {
                printf("Hash table exact match enabled. \n");
                printf("Hash entry number set to: %d\n", hash_entry_number);
        }

        setup_l3fwd_lookup_tables();
        l3fwd_initialize_ports();
        l3fwd_initialize_dst();

        if (l3fwd_lkp.setup() < 0){
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Unable to setup LPM\n");
        }
        if (lpm_check_ptype() < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Port unable to parse RTE_PTYPE\n");
        }
        lpm_check_ptype();
        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
