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
 * l3switch.h - This application performs L3 forwarding.
 ********************************************************************/

#ifndef __L3_SWITCH_H_
#define __L3_SWICTH_H_

#define HASH_ENTRY_NUMBER_DEFAULT       4
#define NB_SOCKETS        8

/* Function pointers for LPM or EM functionality. */

void
setup_lpm(const int socketid); //done

void
setup_hash(const int socketid);

int
em_check_ptype(int portid);

int
lpm_check_ptype(int portid);

uint16_t
em_cb_parse_ptype(uint16_t port, uint16_t queue, struct rte_mbuf *pkts[],
                  uint16_t nb_pkts, uint16_t max_pkts, void *user_param);

uint16_t
lpm_cb_parse_ptype(uint16_t port, uint16_t queue, struct rte_mbuf *pkts[],
                   uint16_t nb_pkts, uint16_t max_pkts, void *user_param);
int
em_main_loop(__attribute__((unused)) void *dummy);

int
lpm_main_loop(__attribute__((unused)) void *dummy);

/* Return ipv4/ipv6 fwd lookup struct for LPM or EM. */
void *
em_get_ipv4_l3fwd_lookup_struct(const int socketid);

void *
em_get_ipv6_l3fwd_lookup_struct(const int socketid);

void *
lpm_get_ipv4_l3fwd_lookup_struct(const int socketid);

void *
lpm_get_ipv6_l3fwd_lookup_struct(const int socketid);

#endif // __L3_SWICTH_H_
