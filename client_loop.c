/*
 *  UFTP - UDP based FTP with multicast
 *
 *  Copyright (C) 2001-2011   Dennis A. Bush, Jr.   bush@tcnj.edu
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

#include "client.h"
#include "client_common.h"
#include "client_loop.h"
#include "client_announce.h"
#include "client_transfer.h"

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
    int i, found,done;
    int32_t usecs;

    gettimeofday(&current_timestamp, NULL);
    done = 0;
    while (!done) {
        found = 0;
        done = 1;
        for (i = 0; i < MAXLIST; i++) {
            if (group_list[i].group_id != 0) {
                if (cmptimestamp(current_timestamp,
                                 group_list[i].timeout_time) >= 0) {
                    switch (group_list[i].phase) {
                    case PHASE_REGISTERED:
                        send_register(i);
                        break;
                    case PHASE_RECEIVING:
                    case PHASE_MIDGROUP:
                        log(group_list[i].group_id, group_list[i].file_id,
                            "Transfer timed out");
                        send_abort(i, "Transfer timed out");
                        break;
                    case PHASE_COMPLETE:
                        send_complete(i);
                        break;
                    }
                    done = 0;
                } else if (!found) {
                    min_timestamp = group_list[i].timeout_time;
                    found = 1;
                } else if (cmptimestamp(group_list[i].timeout_time,
                                        min_timestamp) < 0) {
                    min_timestamp = group_list[i].timeout_time;
                }
            }
        }
        // Check timeout for proxy key request
        if (has_proxy && (proxy_key == (RSA_key_t)NULL)) {
            if (cmptimestamp(current_timestamp, next_keyreq_time) >= 0) {
                send_key_req();
                done = 0;
            } else if ((!found) ||
                       (cmptimestamp(next_keyreq_time, min_timestamp) < 0)) {
                min_timestamp = next_keyreq_time;
                found = 1;
            }
        }
    }
    if (found) {
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
    struct uftp2_h *v2_header;
    unsigned char *buf, *decrypted, *message;
    unsigned int decryptlen, meslen, expectedlen;
    int packetlen, listidx, i;
    uint8_t version, *func;
    uint32_t v2func;
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
    if ((buf == NULL) || (decrypted == NULL)){
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)buf;
    v2_header = (struct uftp2_h *)buf;

    while (1) {
        tv = getrecenttimeout();
        if (read_packet(listener, &src, buf, &packetlen,
                        bsize, tv) <= 0) {
            continue;
        }

        if (header->uftp_id == UFTP_VER_NUM) {
            version = UFTP_VER_NUM;
            expectedlen = sizeof(struct uftp_h) + ntohs(header->blsize);
            listidx = find_file(ntohl(header->group_id));
        } else if (ntohl(v2_header->uftp_id) == V2_UFTP_ID) {
            version = UFTP_V2_VER;
            expectedlen = V2_PACKETSIZE;
            listidx = find_file(ntohl(v2_header->tx_id));
            v2func = ntohl(v2_header->func);
        } else {
            log(0, 0, "Invalid message from %s: not uftp packet "
                      "or invalid version", inet_ntoa(src.sin_addr));
            continue;
        }
        if (packetlen != expectedlen) {
            log(0, 0, "Invalid packet size from %s: got %d, expected %d",
                      inet_ntoa(src.sin_addr), packetlen, expectedlen);
            continue;
        }

        if ((version == UFTP_VER_NUM) && (header->func == ENCRYPTED) &&
                (listidx != -1) && (group_list[listidx].keytype != KEY_NONE)) {
            if (group_list[listidx].phase == PHASE_REGISTERED) {
                log(ntohl(header->group_id), 0, "Got encrypted packet from %s "
                        "but keys not established", inet_ntoa(src.sin_addr));
            }

            if (!validate_and_decrypt(buf, &decrypted, &decryptlen,
                    group_list[listidx].mtu, group_list[listidx].keytype,
                    group_list[listidx].groupkey, group_list[listidx].groupsalt,
                    group_list[listidx].ivlen, group_list[listidx].hashtype,
                    group_list[listidx].grouphmackey,
                    group_list[listidx].hmaclen, group_list[listidx].sigtype,
                    group_list[listidx].serverkey,
                    group_list[listidx].server_keylen)) {
                log(ntohl(header->group_id), 0, "Rejecting message from %s: "
                        "decrypt/validate failed", inet_ntoa(src.sin_addr));
                continue;
            }
            func = (uint8_t *)decrypted;
            message = decrypted;
            meslen = decryptlen;
        } else if (version == UFTP_VER_NUM) {
            if ((listidx != -1) && (group_list[listidx].keytype != KEY_NONE) &&
                    ((header->func == FILEINFO) || (header->func == FILESEG) ||
                     (header->func == DONE) || (header->func == DONE_CONF) ||
                     ((header->func == ABORT) &&
                         (group_list[listidx].phase != PHASE_REGISTERED)))) {
                log(0, 0, "Rejecting %s message from %s: not encrypted",
                        func_name(header->func), inet_ntoa(src.sin_addr));
                continue;
            }
            func = (uint8_t *)&header->func;
            message = buf + sizeof(struct uftp_h);
            meslen = ntohs(header->blsize);
        } else {
            // Version 2
            message = buf;
            meslen = V2_PACKETSIZE;
        }

        if ((version == UFTP_VER_NUM) && (header->func == PROXY_KEY)) {
            handle_proxy_key(&src, buf);
            continue;
        }
        if (((version == UFTP_VER_NUM) && (header->func == ANNOUNCE)) ||
                ((version == UFTP_V2_VER) && (v2func == V2_ANNOUNCE))) {
            // Ignore any ANNOUNCE for a group we're already handling
            if (listidx == -1) {
                handle_announce(src, version, buf);
            } else if (group_list[listidx].phase == PHASE_MIDGROUP) {
                // Make sure we don't time out while waiting for other
                // clients to register with the server.
                set_timeout(listidx);
            }
        } else {
            if (listidx == -1) {
                // group / file ID not in list
                continue;
            }
            if (group_list[listidx].version != version) {
                log(group_list[listidx].group_id, group_list[listidx].file_id,
                        "Version mismatch");
                continue;
            }
            if (((version == UFTP_VER_NUM) && (*func == ABORT)) ||
                    ((version == UFTP_V2_VER) && (v2func == V2_ABORT))) {
                handle_abort(listidx, message, meslen);
                continue;
            }
            switch (group_list[listidx].phase) {
            case PHASE_REGISTERED:
                if (version == UFTP_V2_VER) {
                    // This is repeated in one of the cases below, but it's
                    // separated out anyway to keep the V2 stuff separate.
                    handle_regconf(listidx, message, meslen);
                } else if (group_list[listidx].keytype != KEY_NONE) {
                    if (*func == KEYINFO) {
                        handle_keyinfo(listidx, buf);
                    } else {
                        log(group_list[listidx].group_id,
                                group_list[listidx].file_id,
                                "Expected KEYINFO, got %s", func_name(*func));
                    }
                } else if (group_list[listidx].keytype == KEY_NONE) {
                    if (*func == REG_CONF) {
                        handle_regconf(listidx, message, meslen);
                    } else if (*func == FILEINFO) {
                        handle_fileinfo(listidx, message, meslen);
                    } else {
                        log(group_list[listidx].group_id,
                                group_list[listidx].file_id,
                                "Expected REG_CONF, got %s", func_name(*func));
                    }
                }
                break;
            case PHASE_MIDGROUP:
                if ((version == UFTP_VER_NUM) && (*func == FILEINFO)) {
                    handle_fileinfo(listidx, message, meslen);
                } else if ((version == UFTP_VER_NUM) && (*func == KEYINFO)) {
                    handle_keyinfo(listidx, buf);
                } else if (((version == UFTP_V2_VER) && (v2func == V2_DONE)) ||
                        ((version == UFTP_VER_NUM) && (*func == DONE))) {
                    handle_done(listidx, message, meslen);
                } else {
                    // Other clients may be still getting earlier files or
                    // setting up, so silently ignore anything unexpected
                    // and reset the timeout.
                    set_timeout(listidx);
                }
                break;
            case PHASE_RECEIVING:
                if ((version == UFTP_VER_NUM) && (*func == FILEINFO)) {
                    handle_fileinfo(listidx, message, meslen);
                } else if (((version == UFTP_V2_VER) &&
                            (v2func == V2_FILESEG)) ||
                        ((version == UFTP_VER_NUM) && (*func == FILESEG))) {
                    handle_fileseg(listidx, message, meslen);
                } else if (((version == UFTP_V2_VER) && (v2func == V2_DONE)) ||
                        ((version == UFTP_VER_NUM) && (*func == DONE))) {
                    handle_done(listidx, message, meslen);
                }
                break;
            case PHASE_COMPLETE:
                if (((version == UFTP_V2_VER) && (v2func == V2_DONE_CONF)) ||
                        ((version == UFTP_VER_NUM) && (*func == DONE_CONF))) {
                    handle_done_conf(listidx, message, meslen);
                }
                break;
            }
        }
    }
}

