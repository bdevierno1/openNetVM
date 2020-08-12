/*********************************************************************
 * openNetVM
 * https://sdnfv.github.io
 *
 * BSD LICENSE
 *
 * Copyright(c)
 * 2015-2019 George Washington University
 * 2015-2019 University of California Riverside
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the
 * distribution.
 * * The name of the author may not be used to endorse or promote
 * products derived from this software without specific prior
 * written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * flow_load_balancer.c - an example using onvm. Stores incoming flows and prints info about them.
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "flow_load_balancer"
#define TBL_SIZE 10000
#define EXPIRE_TIME 5
#define NUM_REPLICAS 4
#define SERVICE_ID \
        2  // Service ID of the first NF. If the number of replicas to be distributed is four, corresponding service ID
           // will be 2,3,4,5
#define INTERVAL 1000000

/*Struct that holds all NF state information */
struct state_info {
        struct onvm_ft *ft;
        uint16_t print_delay;
        uint16_t num_stored;
        uint64_t elapsed_cycles;
        uint64_t last_cycles;
        uint64_t total_packets;
};

/*Struct that holds info about each flow, and is stored at each flow table entry */
struct flow_stats {
        int pkt_count;
        uint64_t last_pkt_cycles;
        int is_active;
        uint16_t target_nf;
};

struct state_info *state_info;
static double weights[NUM_REPLICAS] = {64, 64, 64, 64};
static double packets_per_nf[4] = {0, 0, 0, 0};
static uint16_t num_keys[4] = {0, 0, 0, 0};

static int
update_weights(struct state_info *state_info);
/*
 * Prints application arguments
 */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf("%s [EAL args] -- [NF_LIB args] --d <destination>\n", progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
}

/*
 * Loops through inputted arguments and assigns values as necessary
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c;

        while ((c = getopt(argc, argv, "d:p:")) != -1) {
                switch (c) {
                        case 'p':
                                state_info->print_delay = strtoul(optarg, NULL, 10);
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'd')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument\n", optopt);
                                else if (optopt == 'p')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument\n", optopt);
                                else
                                        RTE_LOG(INFO, APP, "Unknown option character\n");
                                return -1;
                        default:
                                usage(progname);
                                return -1;
                }
        }

        return optind;
}

/*
 * Clears expired entries from the flow table
 */
static int
clear_entries(struct state_info *state_info) {
        if (unlikely(state_info == NULL)) {
                return -1;
        }
        struct flow_stats *data = NULL;
        struct onvm_ft_ipv4_5tuple *key = NULL;
        uint32_t next = 0;
        int ret = 0;

        while (onvm_ft_iterate(state_info->ft, (const void **)&key, (void **)&data, &next) > -1) {
                ret = onvm_ft_remove_key(state_info->ft, key);
                state_info->num_stored--;
                if (ret < 0) {
                        printf("Key should have been removed, but was not\n");
                        state_info->num_stored++;
                }
        }
        return 0;
}

/*
 * Prints out information about flows stored in table
 */
static void
do_stats_display(void) {
        int32_t i;

        const char clr[] = {27, '[', '2', 'J', '\0'};
        const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("\nLoad Balancer statistics ====================================");

        for (i = 0; i < NUM_REPLICAS; i++) {
                printf("\nStatistics for Service ID %u ------------------------------",i + SERVICE_ID);
                // printf("\nPackets sent %u", packets_per_nf[i]);
                // printf("Number of keys: %u"num_keys[i]);
        }
        printf(
            "\nAggregate statistics ==============================="
            "\nTotal packets received: %14" PRIu64,
            state_info->total_packets);
        printf("\nWeight 0: %f", weights[0]);
        printf("\nWeight 1: %f", weights[1]);
        printf("\nWeight 2: %f", weights[2]);
        printf("\n====================================================\n");
}

/*
 * Adds an entry to the flow table. It first checks if the table is full, and
 * if so, it calls clear_entries() to free up space.
 */
static struct flow_stats *
table_add_entry(struct onvm_ft_ipv4_5tuple *key, struct state_info *state_info) {
        struct flow_stats *data = NULL;

        if (unlikely(key == NULL || state_info == NULL)) {
                return NULL;
        }

        if (TBL_SIZE - state_info->num_stored == 0) {
                int ret = clear_entries(state_info);
                if (ret < 0) {
                        return NULL;
                }
        }

        int random_number = (rand() % 256);
        int tbl_index = onvm_ft_add_key(state_info->ft, key, (char **)&data);
        if (tbl_index < 0) {
                return NULL;
        }
        if (random_number < weights[0]) {
                data->target_nf = 2;
                num_keys[0]++;
                return data;
        }
        if (random_number >= weights[0] &&
            random_number < (weights[1] + weights[0])) {
                data->target_nf = 3;
                num_keys[1]++;
                return data;
        }
        if (random_number >= weights[1] + weights[0] && random_number < weights[2] + weights[0] + weights[1]) {
                data->target_nf = 4;
                num_keys[2]++;
                return data;
        }
        if (random_number >= weights[0] + weights[1] + weights[2]) {
                data->target_nf = 5;
                num_keys[3]++;
                return data;
        }
        return NULL;
}

/*
 * Looks up a packet hash to see if there is a matching key in the table.
 * If it finds one, it updates the metadata associated with the key entry,
 * and if it doesn't, it calls table_add_entry() to add it to the table.
 */
static struct flow_stats *
table_lookup_entry(struct rte_mbuf *pkt, struct state_info *state_info) {
        struct flow_stats *data = NULL;
        struct onvm_ft_ipv4_5tuple key;

        if (unlikely(pkt == NULL || state_info == NULL)) {
                return NULL;
        }

        int ret = onvm_ft_fill_key_symmetric(&key, pkt);
        if (ret < 0)
                return NULL;
        int tbl_index = onvm_ft_lookup_key(state_info->ft, &key, (char **)&data);
        if (tbl_index == -ENOENT) {
                return table_add_entry(&key, state_info);
        } else if (tbl_index < 0) {
                printf("Some other error occurred with the packet hashing\n");
                return NULL;
        } else {
                data->pkt_count += 1;
                data->last_pkt_cycles = state_info->elapsed_cycles;
                return data;
        }
}

/*
 * This function updates the weights so that all NFs will get a more even distribution of flows.
 * If an service ID is receiving an inbalanced number of packets, its weight is increased or
 * decreased accordingly.
 */
static int
update_weights(struct state_info *state_info) {
        if (state_info->total_packets == 0) {
                return 0;
        }
        weights[0] = (256 - ((packets_per_nf[0] * 256) / INTERVAL)) / 3;
        weights[1] = (256 - ((packets_per_nf[1] * 256) / INTERVAL)) / 3;
        weights[2] = (256 - ((packets_per_nf[2] * 256) / INTERVAL)) / 3;
        return 0;
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        static uint64_t counter = 0;
        static uint64_t print_delay = 0;
        if (!onvm_pkt_is_ipv4(pkt)) {
                meta->action = ONVM_NF_ACTION_DROP;
                return 0;
        }

        struct flow_stats *flow_entry = table_lookup_entry(pkt, state_info);
        if (flow_entry == NULL) {
                printf("Packet could not be identified or processed\n");
                meta->action = ONVM_NF_ACTION_DROP;
                return 0;
        }

        meta->destination = flow_entry->target_nf;
        meta->action = ONVM_NF_ACTION_TONF;

        packets_per_nf[flow_entry->target_nf - SERVICE_ID]++;  // adjust by 2 because targetNF is a service ID (2...5)
        state_info->total_packets++;
        if (++counter == INTERVAL) {
                if (++print_delay == state_info->print_delay) {
                    do_stats_display();
                    print_delay = 0;
                }
                update_weights(state_info);
                clear_entries(state_info);
                state_info->total_packets = 0;
                packets_per_nf[0] = 0;
                packets_per_nf[1] = 0;
                packets_per_nf[2] = 0;
                packets_per_nf[3] = 0;
                counter = 0;
        }
        return 0;
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

        state_info = rte_calloc("state", 1, sizeof(struct state_info), 0);
        if (state_info == NULL) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Unable to initialize NF state");
        }

        /* Default print delay set to five seconds. */
        state_info->print_delay = EXPIRE_TIME;
        state_info->num_stored = 0;
        state_info->total_packets = 0;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments");
        }

        state_info->ft = onvm_ft_create(TBL_SIZE, sizeof(struct flow_stats));
        if (state_info->ft == NULL) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Unable to create flow table");
        }

        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending!\n");
        return 0;
}