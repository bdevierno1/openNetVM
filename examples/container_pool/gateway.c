/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
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
 * speed_tester.c - create pkts and loop through NFs.
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "container_pool"

#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
#define PKT_READ_SIZE ((uint16_t)32)
#define SPEED_TESTER_BIT 7
#define LATENCY_BIT 6
#define LOCAL_EXPERIMENTAL_ETHER 0x88B5
#define DEFAULT_PKT_NUM 128
#define DEFAULT_LAT_PKT_NUM 16
#define MAX_PKT_NUM NF_QUEUE_RINGSIZE

/* number of package between each print */
static uint32_t print_delay = 10000000;
static uint16_t destination;

/*user defined packet size and destination mac address
 *size defaults to ethernet header length
 */
static uint16_t packet_size = RTE_ETHER_HDR_LEN;
static uint8_t d_addr_bytes[RTE_ETHER_ADDR_LEN];

/*  track the -c option to see if it has been filled */
static uint8_t use_custom_pkt_count = 0;
/* Default number of packets: 128; user can modify it by -c <packet_number> in command line */
static uint32_t packet_number = 0;

/* Variables for measuring packet latency */
static uint8_t measure_latency = 0;
static uint32_t latency_packets = 0;
static uint64_t total_latency = 0;

static struct onvm_flow_entry *flow_entry = NULL;

void
nf_setup(struct onvm_nf_local_ctx *nf_local_ctx);

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf(
            "%s [EAL args] -- [NF_LIB args] -- -d <destination> [-p <print_delay>] "
            "[-s <packet_length>] [-m <dest_mac_address>] [-o <pcap_filename>] "
            "[-c <packet_number>] [-l]\n",
            progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
        printf(" - `-d DST`: Destination Service ID to foward to\n");
        printf(" - `-p PRINT_DELAY`: Number of packets between each print, e.g. `-p 1` prints every packets.\n");
        printf(
            " - `-s PACKET_SIZE`: Size of packet, e.g. `-s 32` allocates 32 bytes for the data segment of "
            "`rte_mbuf`.\n");
        printf(
            " - `-m DEST_MAC`: User specified destination MAC address, e.g. `-m aa:bb:cc:dd:ee:ff` sets the "
            "destination address within the ethernet header that is located at the start of the packet data.\n");
        printf(" - `-o PCAP_FILENAME` : The filename of the pcap file to replay\n");
        printf(
            " - `-l LATENCY` : Enable latency measurement. This should only be enabled on one Speed Tester NF. Packets "
            "must be routed back to the same speed tester NF.\n");
        printf(
            " - `-c PACKET_NUMBER` : Use user specified number of packets in the batch. If not specified then this "
            "defaults to 128.\n");
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c, i, count, dst_flag = 0;
        int values[RTE_ETHER_ADDR_LEN];

        while ((c = getopt(argc, argv, "d:p:s:m:c:l")) != -1) {
                switch (c) {
                        case 'd':
                                destination = strtoul(optarg, NULL, 10);
                                dst_flag = 1;
                                break;
                        case 'p':
                                print_delay = strtoul(optarg, NULL, 10);
                                break;
                        case 's':
                                packet_size = strtoul(optarg, NULL, 10);
                                break;
                        case 'm':
                                count = sscanf(optarg, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2],
                                               &values[3], &values[4], &values[5]);
                                if (count == RTE_ETHER_ADDR_LEN) {
                                        for (i = 0; i < RTE_ETHER_ADDR_LEN; ++i) {
                                                d_addr_bytes[i] = (uint8_t)values[i];
                                        }
                                } else {
                                        usage(progname);
                                        return -1;
                                }
                                break;
                        case 'c':
                                use_custom_pkt_count = 1;
                                packet_number = strtoul(optarg, NULL, 10);
                                if (packet_number > MAX_PKT_NUM) {
                                        RTE_LOG(INFO, APP, "Illegal packet number(1 ~ %u) %u!\n", MAX_PKT_NUM,
                                                packet_number);
                                        return -1;
                                }
                                break;
                        case 'l':
                                measure_latency = 1;
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'd')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (optopt == 'p')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (optopt == 's')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (optopt == 'm')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (optopt == 'c')
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

        if (!dst_flag) {
                RTE_LOG(INFO, APP, "Speed tester NF requires a destination NF with the -d flag.\n");
                return -1;
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
do_stats_display(struct rte_mbuf *pkt) {
        static uint64_t last_cycles;
        static uint64_t cur_pkts = 0;
        static uint64_t last_pkts = 0;
        const char clr[] = {27, '[', '2', 'J', '\0'};
        const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
        (void)pkt;

        uint64_t cur_cycles = rte_get_tsc_cycles();
        cur_pkts += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("Total packets: %9" PRIu64 " \n", cur_pkts);
        printf("TX pkts per second: %9" PRIu64 " \n",
               (cur_pkts - last_pkts) * rte_get_timer_hz() / (cur_cycles - last_cycles));
        if (measure_latency && latency_packets > 0)
                printf("Avg latency nanoseconds: %6" PRIu64 " \n",
                       total_latency / (latency_packets)*1000000000 / rte_get_timer_hz());
        printf("Initial packets created: %u\n", packet_number);

        total_latency = 0;
        latency_packets = 0;

        last_pkts = cur_pkts;
        last_cycles = cur_cycles;

        printf("\n\n");
}

static void
nf_setup(__attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        flow_entry = (struct onvm_flow_entry *)rte_calloc(NULL, 1, sizeof(struct onvm_flow_entry), 0);
        if (flow_entry == NULL) {
                rte_exit(EXIT_FAILURE, "Unable to allocate flow entry\n");
        }
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        static uint32_t counter = 0;
        int ret;
        /* TODO:
        Is packet is in a new flow?
                a. yes
                        - Send packet through to Auto-Scaler/Instantiator
                        - check NF pool for "warm" NFs
                        - if pool empty, use auto-scale API to instantiate
                        - dequeue containerized NF and assign a new flow table rule
                b. no
                        - do flow table lookup of packet
                        - assign to that containerized NF
        */

        if (!onvm_pkt_is_ipv4(pkt)) {
                meta->action = ONVM_NF_ACTION_DROP;
                return 0;
        }

        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }

        struct onvm_ft_ipv4_5tuple key;
        onvm_ft_fill_key(&key, pkt);
        ret = onvm_ft_lookup_key(sdn_ft, &key, (char **)&flow_entry);
        if (ret >= 0) {
                // assign to
                meta->action = ONVM_NF_ACTION_NEXT;
        } else {
                ret = onvm_ft_add_key(sdn_ft, &key, (char **)&flow_entry);
                if (ret < 0) {
                        meta->action = ONVM_NF_ACTION_DROP;
                        meta->destination = 0;
                        return 0;
                }
                flow_entry->sc = onvm_sc_create();
                onvm_sc_append_entry(flow_entry->sc, ONVM_NF_ACTION_TONF, destination);
                meta->action = ONVM_NF_ACTION_TONF;
                meta->destination = destination;
        }
        return 0;
}

int
main(int argc, char *argv[]) {
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        int arg_offset;

        const char *progname = argv[0];

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();

        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;
        nf_function_table->setup = &nf_setup;

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                if (arg_offset == ONVM_SIGNAL_TERMINATION) {
                        printf("Exiting due to user termination\n");
                        return 0;
                } else {
                        rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
                }
        }

        onvm_nflib_pool_enqueue("s", "sef", 1, -1);
        onvm_nflib_pool_dequeue("s", 1, 1);
        // onvm_nflib_pool_dequeue("s", 2, -1);

        // argc -= arg_offset;
        // argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                // rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        // onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}