/*
 *  UFTP - UDP based FTP with multicast
 *
 *  Copyright (C) 2001-2010   Dennis A. Bush, Jr.   bush@tcnj.edu
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  Additional permission under GNU GPL version 3 section 7
 *
 *  If you modify this program, or any covered work, by linking or
 *  combining it with the OpenSSL project's OpenSSL library (or a
 *  modified version of that library), containing parts covered by the
 *  terms of the OpenSSL or SSLeay licenses, the copyright holder
 *  grants you additional permission to convey the resulting work.
 *  Corresponding Source for a non-source form of such a combination
 *  shall include the source code for the parts of OpenSSL used as well
 *  as that of the covered work.
 */

#ifndef _PROXY_COMMON_H
#define _PROXY_COMMON_H

int find_group(uint32_t group_id);
int find_client(int listidx, uint32_t addr);
int addr_in_list(uint32_t *addrlist, int size);
void group_cleanup(int listidx);
void set_uftp_header(struct uftp_h *header, int func, int listidx);
void set_timeout(int listidx, int pending_reset);

int max_msg_dest(int listidx, int func);
void send_all_pending(int listidx);
void check_pending(int listidx, int hostdix, const unsigned char *message);
int load_pending(int listidx, int pendidx, int func,
                 uint32_t *addrlist, int listlen);
int check_unfinished_clients(int listidx, int abort);

void forward_message(int listidx, const struct sockaddr_in *src,
                     const unsigned char *packet);
void handle_hb_request(const struct sockaddr_in *src,
                       const unsigned char *packet);
void handle_hb_response(const struct sockaddr_in *src,
                        const unsigned char *packet);
void handle_key_req(const struct sockaddr_in *src,
                    const unsigned char *packet);
void handle_abort(int listidx, const struct sockaddr_in *src,
                  const unsigned char *packet);
void send_upstream_abort(int listidx, uint32_t addr, const char *message);
void send_downstream_abort(int listidx, uint32_t addr, const char *message);
void send_auth_hb_request(int hostidx, uint32_t nonce);
void send_hb_request();
void send_hb_response(const struct sockaddr_in *src, int response);
void send_proxy_key();

int verify_fingerprint(const struct fp_list_t *fplist, int listlen,
                       const unsigned char *keymod, uint32_t keyexp,
                       int keylen, uint32_t addr);
uint8_t *build_verify_data(int listidx, int hostidx, int *verifylen, int full);
void add_naks_to_pending(int listidx, int pendidx,
                         const unsigned char *message);

#endif  // _PROXY_COMMON_H

