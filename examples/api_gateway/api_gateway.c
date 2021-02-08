/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2021 George Washington University
 *            2015-2021 University of California Riverside
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
 * api_gateway.c - A gateway NF to support containerized network functions.
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
#include <rte_lpm.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "api_gateway.h"
#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "api_gateway"

/* Print a usage message. */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf("%s [EAL args] -- [NF_LIB args] -- -p <print_delay>\n", progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
}

/* Parse the application arguments. */
static int
parse_app_args(int argc, char *argv[], const char *progname, struct state_info *stats) {
        int c;

        while ((c = getopt(argc, argv, "p:")) != -1) {
                switch (c) {
                        case 'p':
                                stats->print_delay = strtoul(optarg, NULL, 10);
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
 * screen when called.
 */
static void
print_stats(__attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        const char clr[] = {27, '[', '2', 'J', '\0'};
        const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
        uint64_t total_packets = 0;

        struct onvm_nf *nf = nf_local_ctx->nf;
        struct state_info *stats = (struct state_info *)nf->data;

        /* Clear screen and move to top left */
        printf("\nStatistics ====================================");
        int i;
        for (i = 0; i < NUM_CONTAINERS; i++) {
                printf(
                    "\nStatistics for NF Container %d ------------------------------"
                    "\nPackets forwarded to: %20" PRIu64,
                    i, stats->statistics[i]);

                total_packets += stats->statistics[i];
        }
        printf(
            "\nAggregate statistics ==============================="
            "\nTotal packets forwarded: %17" PRIu64 "\nPackets dropped: %18" PRIu64,
            total_packets, stats->packets_dropped);
        printf("\n====================================================\n");

        printf("\n\n");
}

/*
 * This function performs an IPV4 lookup int the hash table. Packets are then forwared to the corresponding NF.
 */
static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        static uint32_t counter = 0;

        struct onvm_nf *nf = nf_local_ctx->nf;
        struct state_info *stats = (struct state_info *)nf->data;

        if (counter++ == stats->print_delay) {
                print_stats(nf_local_ctx);
                counter = 0;
        }
        uint16_t dst;

        dst = get_ipv4_dst(pkt, stats);

        if (dst == -1) {
                meta->action = ONVM_NF_ACTION_DROP;
                stats->packets_dropped++;
                return 0;
        }
        meta->destination = dst;
        stats->statistics[dst]++;
        meta->action = ONVM_NF_ACTION_TONF;
        return 0;
}

void
nf_setup(struct onvm_nf_local_ctx *nf_local_ctx) {
        struct onvm_nf *nf = nf_local_ctx->nf;
        struct state_info *stats = (struct state_info *)nf->data;
        if (setup_hash(stats) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_free(stats);
                rte_exit(EXIT_FAILURE, "Unable to setup Hash\n");
        }
        printf("Hash table successfully created. \n");
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

        argc -= arg_offset;
        argv += arg_offset;

        /* Allocate NF data structure to keep track of state information. */
        struct onvm_nf *nf = nf_local_ctx->nf;
        struct state_info *stats = rte_calloc("state", 1, sizeof(struct state_info), 0);
        if (stats == NULL) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Unable to initialize NF stats.");
        }
        nf->data = (void *)stats;

        /* Set defualt print delay */
        stats->print_delay = 1000000;

        /* Parse application arguments. */
        if (parse_app_args(argc, argv, progname, stats) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }
        struct flow_classifier *cls_app;
        
        add_rules(parm_config.rule_ipv4_name, cls_app);

        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        /* Stats will be freed by manager. Do not put table data structures in the stats struct as doing so will result
           in seg fault. Update stats to be deallocated by NF? */
        onvm_ft_free(em_tbl);
        printf("If we reach here, program is ending\n");
        return 0;
}