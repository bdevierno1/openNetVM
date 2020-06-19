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

/* Select Longest-Prefix or Exact match. */
static int l3fwd_lpm_on;
static int l3fwd_em_on;

struct l3fwd_lkp_mode {
    void  (*setup)(int);
    int   (*check_ptype)(int);
    rte_rx_callback_fn cb_parse_ptype;
    int   (*main_loop)(void *);
    void* (*get_ipv4_lookup_struct)(int);
    void* (*get_ipv6_lookup_struct)(int);
};

static struct l3fwd_lkp_mode l3fwd_lkp;

static struct l3fwd_lkp_mode l3fwd_em_lkp = {
    .setup                  = setup_hash,
    .check_ptype        = em_check_ptype,
    .cb_parse_ptype     = em_cb_parse_ptype,
    .main_loop              = em_main_loop,
    .get_ipv4_lookup_struct = em_get_ipv4_l3fwd_lookup_struct,
    .get_ipv6_lookup_struct = em_get_ipv6_l3fwd_lookup_struct,
};

static struct l3fwd_lkp_mode l3fwd_lpm_lkp = {
    .setup                  = setup_lpm,
    .check_ptype        = lpm_check_ptype,
    .cb_parse_ptype     = lpm_cb_parse_ptype,
    .main_loop              = lpm_main_loop,
    .get_ipv4_lookup_struct = lpm_get_ipv4_l3fwd_lookup_struct,
    .get_ipv6_lookup_struct = lpm_get_ipv6_l3fwd_lookup_struct,
};


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
        while ((c = getopt(argc, argv, "e:l:h")) != -1) {
                switch (c) {
                        case 'e':
                                l3fwd_em_on = 1;
                                break;
                        case 'l':
                                l3fwd_lpm_on = 1;
                                break;
                        case 'h':
                                hash_entry_number = strtoul(optarg, NULL, 10);
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

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {

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

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        /* If both LPM and EM are selected, return error. */
        if (l3fwd_lpm_on && l3fwd_em_on) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "LPM and EM are mutually exclusive, select only one\n.\n");
        }

        /*
         * Hash flags are valid only for
         * exact macth, reset them to default for
         * longest-prefix match.
         */
        if (l3fwd_lpm_on) {
                hash_entry_number = HASH_ENTRY_NUMBER_DEFAULT;
        } else {
                printf("Hash entry number set to: %d\n", hash_entry_number);
        }
        lpm_check_ptype(0);
        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}