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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef WINDOWS

#include "win_func.h"

#else // WINDOWS

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif

#include "proxy.h"
#include "proxy_common.h"
#include "proxy_loop.h"
#include "proxy_upstream.h"
#include "proxy_downstream.h"

/**
 * Gets the current timeout value to use for the main loop
 *
 * First check to see if any active groups have an expired timeout, and
 * handle that timeout.  Once all expired timeouts have been handled, find
 * the active group with the earliest timeout and return the time until that
 * timeout.  If there are no active groups, return NULL.
 */
struct timeval *getrecenttimeout()
{
    static struct timeval tv = {0,0};
    struct timeval current_timestamp, min_timestamp;
    int i, j, found_timeout, recheck, pending;
    int32_t usecs;

    gettimeofday(&current_timestamp, NULL);

    recheck = 1;
    while (recheck) {
        found_timeout = 0;
        recheck = 0;
        // First check group timeouts
        for (i = 0; i < MAXLIST; i++) {
            if (group_list[i].group_id != 0) {
                if ((group_list[i].phase == PR_PHASE_REGISTERED) ||
                        (group_list[i].phase == PR_PHASE_READY)) {
                    if ((group_list[i].phase == PR_PHASE_READY) &&
                            (cmptimestamp(current_timestamp,
                                    group_list[i].phase_timeout_time) >= 0)) {
                        send_keyinfo(i, NULL, 0);
                        recheck = 1;
                    }
                    if (cmptimestamp(current_timestamp,
                            group_list[i].phase_expire_time) >= 0) {
                        group_list[i].phase = PR_PHASE_RECEIVING;
                        check_unfinished_clients(i, 1);
                    }
                }
                if (cmptimestamp(current_timestamp,
                        group_list[i].timeout_time) >= 0) {
                    // If at least one message is pending, timeout_time is
                    // time to next send of the specified message.
                    // Otherwise it's the overall timeout.
                    for (pending = 0, j = 0; (j < MAX_PEND) && !pending; j++) {
                        if (group_list[i].pending[j].msg != 0) {
                            pending = 1;
                        }
                    }
                    if (pending) {
                        send_all_pending(i);
                    } else {
                        log(group_list[i].group_id, 0, "Group timed out");
                        group_cleanup(i);
                    }
                    recheck = 1;
                }
                if (!recheck && ((!found_timeout) ||
                                 (cmptimestamp(group_list[i].timeout_time,
                                               min_timestamp) < 0))) {
                    min_timestamp = group_list[i].timeout_time;
                    found_timeout = 1;
                }
            }
        }
        // Then check timeout for sending heartbeat
        if (hbhost_count) {
            if (cmptimestamp(current_timestamp, next_hb_time) >= 0) {
                send_hb_request();
                recheck = 1;
            } else if ((!found_timeout) ||
                       (cmptimestamp(next_hb_time, min_timestamp) < 0)) {
                min_timestamp = next_hb_time;
                found_timeout = 1;
            }
        }
    }
    if (found_timeout) {
        usecs = (int32_t)diff_usec(min_timestamp, current_timestamp);
        tv.tv_sec = usecs / 1000000;
        tv.tv_usec = usecs % 1000000;
        return &tv;
    } else {
        return NULL;
    }
}

/**
 * This is the main message reading loop.  Messages are read, validated,
 * decrypted if necessary, then passed to the appropriate routine for handling.
 */
void mainloop()
{
    struct uftp_h *header;
    unsigned char *buf, *decrypted, *message;
    int packetlen, listidx, hostidx, i;
    unsigned int decryptlen, meslen;
    uint8_t *func;
    struct sockaddr_in src;
    struct timeval *tv;
    const int bsize = 9000;  // Roughly size of ethernet jumbo frame

    log(0, 0, "%s", VERSIONSTR);
    for (i = 0; i < key_count; i++) {
        log(0, 0, "Loaded key with fingerprint %s",
                  print_key_fingerprint(privkey[i]));
    }

    buf = calloc(bsize, 1);
    decrypted = calloc(bsize, 1);
    if ((buf == NULL) || (decrypted == NULL)) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)buf;

    while (1) {
        tv = getrecenttimeout();
        if (read_packet(listener, &src, buf, &packetlen,
                        bsize, tv) <= 0) {
            continue;
        }

        if (header->uftp_id != UFTP_VER_NUM) {
            log(0, 0, "Invalid message from %s: not uftp packet "
                      "or invalid version", inet_ntoa(src.sin_addr));
            continue;
        }
        if (packetlen != sizeof(struct uftp_h) + ntohs(header->blsize)) {
            log(0, 0, "Invalid packet size from %s: got %d, expected %d",
                      inet_ntoa(src.sin_addr), packetlen,
                      sizeof(struct uftp_h) + ntohs(header->blsize));
            continue;
        }

        if ((src.sin_addr.s_addr == out_addr.s_addr) &&
                (src.sin_port == htons(port))) {
            // Packet from self -- drop
            continue;
        }
        if (header->func == HB_REQ) {
            handle_hb_request(&src, buf);
            continue;
        }
        if (header->func == HB_RESP) {
            handle_hb_response(&src, buf);
            continue;
        }
        if (header->func == KEY_REQ) {
            handle_key_req(&src, buf);
            continue;
        }
        if ((proxy_type == SERVER_PROXY) &&
                (down_addr.sin_addr.s_addr == INADDR_ANY)) {
            log(0, 0, "Rejecting message from %s: downstream address "
                      "not established", inet_ntoa(src.sin_addr));
            continue;
        }

        listidx = find_group(ntohl(header->group_id));
        if (header->func == ANNOUNCE) {
            handle_announce(listidx, &src, buf);
        } else {
            if (listidx == -1) {
                continue;
            }
            if (proxy_type == SERVER_PROXY) {
                // Server proxies don't do anything outside of an ANNOUNCE.
                // Just send it on through.
                forward_message(listidx, &src, buf);
                continue;
            }
            if (header->func == ABORT) {
                handle_abort(listidx, &src, buf);
                continue;
            }
            if (!memcmp(&src, &group_list[listidx].up_addr, sizeof(src))) {
                // Downstream message
                if (header->func == KEYINFO) {
                    handle_keyinfo(listidx, buf);
                } else if ((header->func == REG_CONF) &&
                           (group_list[listidx].keytype != KEY_NONE)) {
                    handle_regconf(listidx, buf);
                } else {
                    // If we don't need to process the message, don't bother
                    // decrypting anything.  Just forward it on.
                    forward_message(listidx, &src, buf);
                }
            } else {
                // Upstream message
                // Decrypt first if necessary
                hostidx = find_client(listidx, header->srcaddr);
                if ((hostidx != -1) && (header->func == ENCRYPTED) &&
                        (group_list[listidx].keytype != KEY_NONE)) {
                    if (!validate_and_decrypt(buf, &decrypted, &decryptlen,
                            group_list[listidx].mtu,group_list[listidx].keytype,
                            group_list[listidx].groupkey,
                            group_list[listidx].groupsalt,
                            group_list[listidx].ivlen,
                            group_list[listidx].hashtype,
                            group_list[listidx].grouphmackey,
                            group_list[listidx].hmaclen,
                            group_list[listidx].sigtype,
                            group_list[listidx].destinfo[hostidx].pubkey,
                            group_list[listidx].destinfo[hostidx].pubkeylen)) {
                        log(ntohl(header->group_id), 0, "Rejecting message "
                                "from %s: decrypt/validate failed",
                                inet_ntoa(src.sin_addr));
                        continue;
                    }
                    func = (uint8_t *)decrypted;
                    message = decrypted;
                    meslen = decryptlen;
                } else {
                    if ((hostidx != -1) &&
                            (group_list[listidx].keytype != KEY_NONE) &&
                            ((header->func == INFO_ACK) ||
                             (header->func == STATUS) ||
                             (header->func == COMPLETE))) {
                        log(ntohl(header->group_id), 0, "Rejecting %s message "
                                "from %s: not encrypted", 
                                func_name(header->func),
                                inet_ntoa(src.sin_addr));
                        continue;
                    }
                    func = (uint8_t *)&header->func;
                    message = buf + sizeof(struct uftp_h);
                    meslen = ntohs(header->blsize);
                }

                switch (*func) {
                case REGISTER:
                    handle_register(listidx, hostidx, message, meslen,
                                    header->srcaddr);
                    break;
                case CLIENT_KEY:
                    handle_clientkey(listidx, hostidx, message, meslen,
                                     header->srcaddr);
                    break;
                case INFO_ACK:
                    handle_info_ack(listidx, hostidx, message, meslen);
                    break;
                case STATUS:
                    handle_status(listidx, hostidx, message, meslen);
                    break;
                case COMPLETE:
                    handle_complete(listidx, hostidx, message, meslen);
                    break;
                default:
                    forward_message(listidx, &src, buf);
                    break;
                }
            }
        }
    }
}

