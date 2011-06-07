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

#include <ws2tcpip.h>
#include <io.h>

#include "win_func.h"

#else  // if WINDOWS

#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#endif

#include "proxy.h"
#include "proxy_common.h"
#include "proxy_upstream.h"

/**
 * Look for a given group in the global group list
 * Returns the file's index in the list, or -1 if not found
 */
int find_group(uint32_t group_id)
{
    int i;

    for (i = 0; i < MAXLIST; i++) {
        if (group_list[i].group_id == group_id) {
            return i;
        }
    }

    return -1;
}

/**
 * Look for a given client in the group's client list
 * Returns the client's index in the list, or -1 if not found
 */
int find_client(int listidx, uint32_t addr)
{
    int i;

    for (i = 0; i < group_list[listidx].destcount; i++) {
        if (group_list[listidx].destinfo[i].addr.s_addr == addr) {
            return i;
        }
    }
    return -1;
}

/**
 * Looks for one of the local listening addresses in a list of addresses.
 * Returns the index in m_interface of the match, or -1 if no match
 */
int addr_in_list(uint32_t *addrlist, int size)
{
    int i, j;

    for (i = 0; i < size; i++) {
        if (addrlist[i] == 0) {
            return -1;
        }
        for (j = 0; j < interface_count; j++) {
            if (addrlist[i] == m_interface[j].addr.s_addr) {
                return j;
            }
        }
    }
    return -1;
}

/**
 * Checks to see if the multicast address used for the given group list member
 * is also being used by either another member or the public address list
 */
int other_mcast_users(int listidx)
{
    int i;

    for (i = 0; i < pub_multi_count; i++) {
        if (group_list[listidx].multi.s_addr == pub_multi[i].s_addr) {
            return 1;
        }
    }
    for (i = 0; i < MAXLIST; i++) {
        if ((i != listidx) && (group_list[i].group_id != 0) &&
                (group_list[listidx].multi.s_addr ==
                    group_list[i].multi.s_addr)) {
            return 1;
        }
    }
    return 0;
}

/**
 * Clean up a group list entry.  Free malloc'ed structures, drop the
 * multicast group (if no one else is using it) and free the slot.
 */
void group_cleanup(int listidx)
{
    int i;

    for (i = 0; i < MAX_PEND; i++) {
        free(group_list[listidx].pending[i].naklist);
    }

    if ((group_list[listidx].multi.s_addr != 0) &&
            (proxy_type != CLIENT_PROXY) && !other_mcast_users(listidx) &&
            group_list[listidx].multi_join) {
        multicast_leave(listener, group_list[listidx].group_id,
                &group_list[listidx].multi, m_interface, interface_count,
                server_fp, server_fp_count);
    }
    if (group_list[listidx].serverkey) {
        free_RSA_key(group_list[listidx].serverkey);
    }
    for (i = 0; i < group_list[listidx].destcount; i++) {
        if (group_list[listidx].destinfo[i].pubkey) {
            free_RSA_key(group_list[listidx].destinfo[i].pubkey);
        }
    }
    memset(&group_list[listidx], 0, sizeof(group_list[listidx]));
}

/**
 * Initializes the uftp header of an outgoing packet
 * blsize is initialized to 0, but must be set later before sending
 */
void set_uftp_header(struct uftp_h *header, int func, int listidx)
{
    header->uftp_id = UFTP_VER_NUM;
    header->func = func;
    header->blsize = 0;
    header->group_id = htonl(group_list[listidx].group_id);
    header->srcaddr = group_list[listidx].destaddr.s_addr;
    switch (func) {
    case REGISTER:
    case INFO_ACK:
    case STATUS:
    case COMPLETE:
        header->destaddr = group_list[listidx].srcaddr.s_addr;
        break;
    case KEYINFO:
        header->destaddr = group_list[listidx].multi.s_addr;
        break;
    }
    // Let ABORTs set destaddr themselves, since it depends on the direction
}

/**
 * Sets the timeout time for a given group list member
 */
void set_timeout(int listidx, int pending_reset)
{
    int pending, i;

    if (group_list[listidx].phase == PR_PHASE_READY) {
        gettimeofday(&group_list[listidx].phase_timeout_time, NULL);
        group_list[listidx].phase_timeout_time.tv_usec += 
                group_list[listidx].announce_int * 1000;
        while (group_list[listidx].phase_timeout_time.tv_usec >= 1000000) {
            group_list[listidx].phase_timeout_time.tv_usec -= 1000000;
            group_list[listidx].phase_timeout_time.tv_sec++;
        }
    }

    for (pending = 0, i = 0; (i < MAX_PEND) && !pending; i++) {
        if (group_list[listidx].pending[i].msg != 0) {
            pending = group_list[listidx].pending[i].msg;
        }
    }
    if (pending) {
        if (pending_reset) {
            gettimeofday(&group_list[listidx].timeout_time, NULL);
            switch (pending) {
            case REGISTER:
            case INFO_ACK:
                group_list[listidx].timeout_time.tv_usec +=
                        // It's really: announce_int * 1000 * (proxy_int / 100)
                        group_list[listidx].announce_int * 10 * proxy_int;
                break;
            case STATUS:
            case COMPLETE:
                // TODO: a COMPLETE could be send in response to a FILEINFO.
                // In this case using announce_int would be better.
                // Need to figure out how we would know this.
                group_list[listidx].timeout_time.tv_usec +=
                        // It's really: status_int * 1000 * (proxy_int / 100)
                        group_list[listidx].status_int * 10 * proxy_int;
                break;
            }
        }
    } else {
        gettimeofday(&group_list[listidx].timeout_time, NULL);
        group_list[listidx].timeout_time.tv_sec +=
                group_list[listidx].status_time;
    }
    while (group_list[listidx].timeout_time.tv_usec >= 1000000) {
        group_list[listidx].timeout_time.tv_usec -= 1000000;
        group_list[listidx].timeout_time.tv_sec++;
    }
}

/**
 * Returns the maximum number of clients that can be listed in a given message
 */
int max_msg_dest(int listidx, int func)
{
    switch (func) {
    case REGISTER:
        return (group_list[listidx].payloadsize -
                sizeof(struct register_h)) / sizeof(uint32_t);
    case KEYINFO:
        return (group_list[listidx].payloadsize -
                sizeof(struct keyinfo_h)) / sizeof(struct destkey);
    case INFO_ACK:
        return (group_list[listidx].encpayloadsize -
                sizeof(struct infoack_h)) / sizeof(uint32_t);
    case STATUS:
        return (group_list[listidx].encpayloadsize -
                sizeof(struct prstatus_h)) / sizeof(uint32_t);
    case COMPLETE:
        return (group_list[listidx].encpayloadsize -
                sizeof(struct complete_h)) / sizeof(uint32_t);
    default:
        return 0;
    }
}

/**
 * Sends a pending aggregate message for a given group and message
 */
void send_pending(int listidx, int pendidx)
{
    switch (group_list[listidx].pending[pendidx].msg) {
    case REGISTER:
        send_register(listidx, pendidx);
        break;
    case INFO_ACK:
        send_info_ack(listidx, pendidx, FILEINFO);
        break;
    case STATUS:
        send_status(listidx, pendidx);
        break;
    case COMPLETE:
        send_complete(listidx, pendidx);
        break;
    default:
        log(group_list[listidx].group_id, 0, "Tried to send pending on "
                "invalid type %s",
                func_name(group_list[listidx].pending[pendidx].msg));
        return;
    }
    if (group_list[listidx].pending[pendidx].count <= 0) {
        // Finish the cleanup we started in load_pending
        free(group_list[listidx].pending[pendidx].naklist);
        memset(&group_list[listidx].pending[pendidx], 0,
                sizeof(struct pr_pending_info_t));
    }
}

/**
 * Sends all pending aggregate message for a given group
 */
void send_all_pending(int listidx)
{
    int i;

    for (i = 0; i < MAX_PEND; i++) {
        if (group_list[listidx].pending[i].msg != 0) {
            send_pending(listidx, i);
        }
    }
}

/**
 * Add the NAKs in the given STATUS message to the list of pending NAKs
 */
void add_naks_to_pending(int listidx, int pendidx,
                         const unsigned char *message)
{
    const unsigned char *naks;
    unsigned i;

    naks = message + sizeof(struct status_h);
    for (i = 0; i < group_list[listidx].blocksize; i++) {
        group_list[listidx].pending[pendidx].naklist[i] |= naks[i];
    }
}

/**
 * Puts the given message on the pending message list.  If it doesn't match
 * any pending message and there are no open slots, first send what's pending.
 * If the pending list is full after adding the given message, then send.
 */
void check_pending(int listidx, int hostidx, const unsigned char *message)
{
    struct infoack_h *infoack;
    struct status_h *status;
    struct complete_h *complete;
    const uint8_t *func;
    struct pr_pending_info_t *pending;
    int match, pendidx;

    func = message;
    infoack = (struct infoack_h *)message;
    status = (struct status_h *)message;
    complete = (struct complete_h *)message;

    for (pendidx = 0; pendidx < MAX_PEND; pendidx++) {
        pending = &group_list[listidx].pending[pendidx];
        if (group_list[listidx].pending[pendidx].msg == 0) {
            match = 1;
            break;
        }

        match = (*func == pending->msg);
        switch (*func) {
        case REGISTER:
            // REGISTER always matches itself
            break;
        case INFO_ACK:
            // Only in response to FILEINFO.
            // Responses to KEYINFO are not forwarded.
            match = match && (ntohs(infoack->file_id) == pending->file_id);
            break;
        case STATUS:
            match = match && ((ntohs(status->file_id) == pending->file_id) &&
                              (status->pass == pending->pass) &&
                              (ntohs(status->section) == pending->section));
            break;
        case COMPLETE:
            match = match && (ntohs(complete->file_id) == pending->file_id);
            break;
        default:
            log(group_list[listidx].group_id, 0, "Tried to check pending "
                    "on invalid type %s", func_name(*func));
            return;
        }
        if (match) {
            break;
        }
    }

    if (!match) {
        send_all_pending(listidx);
        pendidx = 0;
        pending = &group_list[listidx].pending[pendidx];
    }

    pending->msg = *func;
    if (group_list[listidx].destinfo[hostidx].pending != pendidx) {
        group_list[listidx].destinfo[hostidx].pending = pendidx;
        pending->count++;
    }

    switch (*func) {
    case INFO_ACK:
        if (pending->count == 1) {
            pending->partial = 1;
        }
        pending->file_id = ntohs(infoack->file_id);
        pending->partial = pending->partial &&
                            ((infoack->flags & FLAG_PARTIAL) != 0);
        break;
    case STATUS:
        pending->file_id = ntohs(status->file_id);
        pending->pass = status->pass;
        pending->section = ntohs(status->section);
        pending->seq = group_list[listidx].last_seq;
        if (!pending->naklist) {
            pending->naklist = calloc(group_list[listidx].blocksize, 1);
            if (pending->naklist == NULL) {
                syserror(0, 0, "calloc failed!");
                exit(1);
            }
        }
        if (ntohl(status->nak_count) != 0) {
            add_naks_to_pending(listidx, pendidx, message);
        }
        break;
    case COMPLETE:
        pending->file_id = ntohs(complete->file_id);
        break;
    }

    if (pending->count == max_msg_dest(listidx, *func)) {
        send_pending(listidx, pendidx);
    } else {
        int total_pending, i;

        for (total_pending = 0, i = 0; i < MAX_PEND; i++) {
            total_pending += group_list[listidx].pending[i].count;
        }
        if (total_pending == 1) {
            set_timeout(listidx, 1);
        }
    }
}

/**
 * Check for any client that hasn't fully registered.
 * If the abort parameter is set, send an ABORT to the server and client.
 * Returns 1 if any aren't fully registered, 0 if all are registered.
 */
int check_unfinished_clients(int listidx, int abort)
{
    int hostidx, found;
    struct pr_destinfo_t *dest;

    if (group_list[listidx].keytype == KEY_NONE) {
        return 0;
    }

    found = 0;
    for (hostidx = 0; hostidx < group_list[listidx].destcount; hostidx++) {
        dest = &group_list[listidx].destinfo[hostidx];
        if ((group_list[listidx].group_id != 0) &&
                (dest->state != PR_CLIENT_READY)) {
            if (abort) {
                send_downstream_abort(listidx, dest->addr.s_addr,
                        "Client not fully registered at proxy");
                send_upstream_abort(listidx, dest->addr.s_addr,
                        "Client not fully registered at proxy");
            }
            found = 1;
        }
    }
    return found;
}

/**
 * Load a message body with the list of pending clients
 */
int load_pending(int listidx, int pendidx, int func,
                 uint32_t *addrlist, int listlen)
{
    int hostidx, cnt;
    struct pr_destinfo_t *dest;

    for (cnt = 0, hostidx = 0;
            (hostidx < group_list[listidx].destcount) && (cnt < listlen);
            hostidx++) {
        dest = &group_list[listidx].destinfo[hostidx];
        if (dest->pending == pendidx) {
            addrlist[cnt++] = dest->addr.s_addr;
            dest->pending = -1;
            group_list[listidx].pending[pendidx].count--;
        }
    }
    if (group_list[listidx].pending[pendidx].count <= 0) {
        // Don't zero out the whole pending struct.
        // We need to clear the message now to set timeouts properly but
        // we still use the other fields just before sending the message.
        // The full cleanup is done in send_pending
        group_list[listidx].pending[pendidx].count = 0;
        group_list[listidx].pending[pendidx].msg = 0;
    }

    return cnt;
}

/**
 * Forward a message unmodified to the next hop, resigning if necessary.
 */
void forward_message(int listidx, const struct sockaddr_in *src,
                     const unsigned char *packet)
{
    struct uftp_h *header;
    struct encrypted_h *encrypted;
    struct sockaddr_in dest;
    unsigned int meslen, siglen;
    int hostidx;
    uint8_t *sig, *sigcopy;
    RSA_key_t key;

    header = (struct uftp_h *)packet;
    meslen = sizeof(struct uftp_h) + ntohs(header->blsize);

    memset(&dest, 0, sizeof(dest));
    if (!memcmp(src, &group_list[listidx].up_addr, sizeof(*src))) {
        if (proxy_type == RESPONSE_PROXY) {
            // Response proxy, no downstream fowarding
            set_timeout(listidx, 0);
            return;
        } else if (proxy_type == SERVER_PROXY) {
            dest = down_addr;
        } else {
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = header->destaddr;
            dest.sin_port = htons(out_port);
            key = group_list[listidx].serverkey;
        }
    } else {
        dest = group_list[listidx].up_addr;
        if (proxy_type != SERVER_PROXY) {
            hostidx = find_client(listidx, header->srcaddr);
            if (hostidx == -1) {
                log(group_list[listidx].group_id, 0,
                        "Couldn't find receiver in list");
                return;
            }
            key = group_list[listidx].destinfo[hostidx].pubkey;
        }
    }

    // If we're using RSA signatures, verify the signature and resign
    if ((proxy_type != SERVER_PROXY) && (header->func == ENCRYPTED) &&
            (group_list[listidx].sigtype == SIG_RSA)) {
        encrypted = (struct encrypted_h *)(packet + sizeof(struct uftp_h));
        sig = (uint8_t *)encrypted + sizeof(struct encrypted_h);
        siglen = ntohs(encrypted->sig_len);

        sigcopy = calloc(siglen, 1);
        if (sigcopy == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        memcpy(sigcopy, sig, siglen);
        memset(sig, 0, siglen);
        if (!verify_RSA_sig(key, group_list[listidx].hashtype, packet,
                            meslen, sigcopy, siglen)) {
            log(group_list[listidx].group_id, 0,
                    "Signature verification failed");
            free(sigcopy);
            return;
        }
        if (!create_RSA_sig(group_list[listidx].proxykey,
                            group_list[listidx].hashtype, packet, meslen,
                            sigcopy, &siglen)) {
            log(group_list[listidx].group_id, 0,
                    "Signature creation failed");
            free(sigcopy);
            return;
        }
        memcpy(sig, sigcopy, siglen);
        free(sigcopy);
    }

    if (nb_sendto(listener, packet, meslen, 0, (struct sockaddr *)&dest,
               sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id, 0, "Error forwarding message");
        log(group_list[listidx].group_id, 0, "Dest: %s:%d",
                inet_ntoa(dest.sin_addr), ntohs(dest.sin_port));
    }
    set_timeout(listidx, 0);
}

/**
 * Process an HB_REQ message
 */
void handle_hb_request(const struct sockaddr_in *src,
                       const unsigned char *packet)
{
    struct uftp_h *header;
    struct hb_req_h *hbreq;
    unsigned char *keymod, *sig;
    struct hostent *hp;
    RSA_key_t key;
    unsigned char *verifydata, fingerprint[HMAC_LEN];
    unsigned int verifylen, fplen, keylen, siglen;
    int resp;

    header = (struct uftp_h *)packet;
    hbreq = (struct hb_req_h *)(packet + sizeof(struct uftp_h));

    if (!noname && (hp = gethostbyaddr((char *)&src->sin_addr,
                                       sizeof(struct in_addr), AF_INET))) {
        log(0, 0, "Received HB_REQ from %s (%s)",
                  hp->h_name, inet_ntoa(src->sin_addr));
    } else {
        log(0, 0, "Received HB_REQ from %s", inet_ntoa(src->sin_addr));
    }
    if ((proxy_type == SERVER_PROXY) && have_down_fingerprint) {
        if ((down_addr.sin_addr.s_addr == src->sin_addr.s_addr) &&
                down_addr.sin_port == src->sin_port) {
            resp = HB_AUTH_OK;
        } else if (down_nonce != ntohl(hbreq->nonce)) {
            resp = HB_AUTH_CHALLENGE;
        } else {
            keymod = (unsigned char *)hbreq + sizeof(struct hb_req_h);
            keylen = ntohs(hbreq->keylen);
            sig = keymod + keylen;
            siglen = ntohs(hbreq->siglen);

            // First check key fingerprint
            verifylen = 0;
            verifydata = calloc(sizeof(hbreq->keyexp) + keylen, 1);
            if (verifydata == NULL) {
                syserror(0, 0, "calloc failed!");
                exit(1);
            }
            memcpy(verifydata, &hbreq->keyexp, sizeof(hbreq->keyexp));
            verifylen += sizeof(hbreq->keyexp);
            memcpy(verifydata + verifylen, keymod, keylen);
            verifylen += keylen;
            hash(HASH_SHA1, verifydata, verifylen, fingerprint, &fplen);
            if (memcmp(down_fingerprint, fingerprint, fplen)) {
                log(0, 0, "Failed to verify HB_REQ fingerprint");
                free(verifydata);
                resp = HB_AUTH_FAILED;
                goto end;
            }
            free(verifydata);

            // Then check signature
            if (!import_RSA_key(&key, ntohl(hbreq->keyexp), keymod, keylen)) {
                log(0, 0, "Failed to import public key from HB_REQ");
                resp = HB_AUTH_FAILED;
                goto end;
            } 

            if (!verify_RSA_sig(key, HASH_SHA1, (unsigned char *)&hbreq->nonce,
                    sizeof(hbreq->nonce), sig, siglen)) {
                log(0, 0, "Failed to verify HB_REQ signature");
                resp = HB_AUTH_FAILED;
                goto end;
            }

            down_addr = *src;
            log(0, 0, "Using %s:%d as downstream address:port",
                      inet_ntoa(src->sin_addr), ntohs(src->sin_port));
            down_nonce = rand();
            resp = HB_AUTH_OK;
        }
    } else {
        resp = HB_AUTH_OK;
    }

end:
    send_hb_response(src, resp);
}

/**
 * Process an HB_RESP message
 */
void handle_hb_response(const struct sockaddr_in *src,
                        const unsigned char *packet)
{
    struct uftp_h *header;
    struct hb_resp_h *hbresp;
    struct hostent *hp;
    int hostidx;

    header = (struct uftp_h *)packet;
    hbresp = (struct hb_resp_h *)(packet + sizeof(struct uftp_h));

    if (!noname && (hp = gethostbyaddr((char *)&src->sin_addr,
                                       sizeof(struct in_addr), AF_INET))) {
        log(0, 0, "Received HB_RESP from %s (%s)",
                  hp->h_name, inet_ntoa(src->sin_addr));
    } else {
        log(0, 0, "Received HB_RESP from %s", inet_ntoa(src->sin_addr));
    }
    if (hbresp->authenticated == HB_AUTH_CHALLENGE) {
        log(0, 0, "Heartbeat authentication required");
        for (hostidx = 0; hostidx < hbhost_count; hostidx++) {
            if ((src->sin_addr.s_addr == hb_hosts[hostidx].sin_addr.s_addr) &&
                    (src->sin_port == hb_hosts[hostidx].sin_port)) {
                send_auth_hb_request(hostidx, ntohl(hbresp->nonce));
                break;
            }
        }
    } else if (hbresp->authenticated == HB_AUTH_FAILED) {
        log(0, 0, "Heartbeat authentication failed");
    } else if (hbresp->authenticated == HB_AUTH_OK) {
        log(0, 0, "Heartbeat authentication successful");
    }
}

/**
 * Process an KEY_REQ message
 */
void handle_key_req(const struct sockaddr_in *src,
                    const unsigned char *packet)
{
    struct hostent *hp;
    struct timeval current_timestamp;

    if (!noname && (hp = gethostbyaddr((char *)&src->sin_addr,
                                       sizeof(struct in_addr), AF_INET))) {
        log(0, 0, "Received KEY_REQ from %s (%s)",
                  hp->h_name, inet_ntoa(src->sin_addr));
    } else {
        log(0, 0, "Received KEY_REQ from %s", inet_ntoa(src->sin_addr));
    }

    gettimeofday(&current_timestamp, NULL);
    if (diff_sec(current_timestamp, last_key_req) > KEY_REQ_LIMIT) {
        send_proxy_key();
    }
}


/**
 * Sends an authenticated HB_REQ message to the given host.
 */
void send_auth_hb_request(int hostidx, uint32_t nonce)
{
    unsigned char *packet, *keymod, *sig;
    struct uftp_h *header;
    struct hb_req_h *hbreq;
    uint8_t modulus[PUBKEY_LEN];
    uint32_t exponent, n_nonce;
    uint16_t modlen;
    unsigned int meslen, siglen;

    packet = calloc(sizeof(struct uftp_h) + sizeof(struct hb_req_h) +
                    (PUBKEY_LEN * 2) , 1);
    if (packet == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)packet;
    hbreq = (struct hb_req_h *)(packet + sizeof(struct uftp_h));
    keymod = (unsigned char *)hbreq + sizeof(struct hb_req_h);
    header->uftp_id = UFTP_VER_NUM;
    header->func = HB_REQ;
    hbreq->func = HB_REQ;

    if (!export_RSA_key(privkey[0], &exponent,
                        modulus, &modlen)) {
        log(0, 0, "Error exporting public key");
        free(packet);
        return;
    }

    n_nonce = htonl(nonce);
    hbreq->nonce = n_nonce;
    hbreq->keyexp = htonl(exponent);
    memcpy(keymod, modulus, modlen);
    hbreq->keylen = htons(modlen);
    sig = keymod + modlen;
    if (!create_RSA_sig(privkey[0], HASH_SHA1, (unsigned char *)&n_nonce,
                        sizeof(n_nonce), sig, &siglen) ||
                siglen > modlen) {
        log(0, 0, "Error signing nonce");
        free(packet);
        return;
    }
    hbreq->siglen = htons(siglen);
    meslen = sizeof(struct hb_req_h) + modlen + siglen;

    header->blsize = htons(meslen);
    meslen += sizeof(struct uftp_h);
    if (nb_sendto(listener, packet, meslen, 0, 
                  (struct sockaddr *)&hb_hosts[hostidx],
                  sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error sending HB_REQ");
    } else {
        log(0, 0, "Sent authenticated HB_REQ to %s:%d",
                  inet_ntoa(hb_hosts[hostidx].sin_addr),
                  ntohs(hb_hosts[hostidx].sin_port));
    }
    free(packet);
}

/**
 * Sends an HB_REQ message to each host listed in the hb_host list
 */
void send_hb_request()
{
    unsigned char *packet;
    struct uftp_h *header;
    struct hb_req_h *hbreq;
    int meslen, i;

    packet = calloc(sizeof(struct uftp_h) + sizeof(struct hb_req_h), 1);
    if (packet == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)packet;
    hbreq = (struct hb_req_h *)(packet + sizeof(struct uftp_h));
    header->uftp_id = UFTP_VER_NUM;
    header->func = HB_REQ;
    hbreq->func = HB_REQ;

    for (i = 0; i < hbhost_count; i++) {
        hbreq->nonce = 0;
        hbreq->keylen = 0;
        hbreq->siglen = 0;
        meslen = sizeof(struct hb_req_h);
        header->blsize = htons(meslen);
        meslen += sizeof(struct uftp_h);
        if (nb_sendto(listener, packet, meslen, 0, 
                      (struct sockaddr *)&hb_hosts[i],
                      sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error sending HB_REQ");
        } else {
            log(0, 0, "Sent HB_REQ to %s:%d",
                      inet_ntoa(hb_hosts[i].sin_addr),
                      ntohs(hb_hosts[i].sin_port));
        }
    }
    free(packet);
    gettimeofday(&next_hb_time, NULL);
    next_hb_time.tv_sec += hb_interval;
}

/**
 * Sends an HB_RESP in response to an HB_REQ
 */
void send_hb_response(const struct sockaddr_in *src, int response)
{
    unsigned char *packet;
    struct uftp_h *header;
    struct hb_resp_h *hbresp;
    int meslen;

    packet = calloc(sizeof(struct uftp_h) + sizeof(struct hb_resp_h), 1);
    if (packet == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)packet;
    hbresp = (struct hb_resp_h *)(packet + sizeof(struct uftp_h));
    header->uftp_id = UFTP_VER_NUM;
    header->func = HB_RESP;
    header->blsize = ntohs(sizeof(struct hb_resp_h));
    hbresp->func = HB_RESP;
    hbresp->authenticated = response;
    if (response == HB_AUTH_CHALLENGE) {
        hbresp->nonce = htonl(down_nonce);
    }

    meslen = sizeof(struct uftp_h) + sizeof(struct hb_resp_h);
    if (nb_sendto(listener, packet, meslen, 0, (struct sockaddr *)src,
                  sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error sending HB_RESP");
    } else {
        log(0, 0, "Sent HB_RESP to %s:%d", inet_ntoa(src->sin_addr),
                                           ntohs(src->sin_port));
    }
    free(packet);
}

/**
 * Sends a PROXY_KEY message to the first listed public multicast address.
 */
void send_proxy_key()
{
    unsigned char *packet, *keymod, *sig;
    struct uftp_h *header;
    struct proxy_key_h *proxykey;
    uint8_t modulus[PUBKEY_LEN];
    uint32_t exponent, nonce;
    uint16_t modlen;
    unsigned int meslen, siglen;
    struct sockaddr_in pubaddr;

    packet = calloc(sizeof(struct uftp_h) + sizeof(struct hb_req_h) +
                    (PUBKEY_LEN * 2) , 1);
    if (packet == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)packet;
    proxykey = (struct proxy_key_h *)(packet + sizeof(struct uftp_h));
    keymod = (unsigned char *)proxykey + sizeof(struct proxy_key_h);
    header->uftp_id = UFTP_VER_NUM;
    header->func = PROXY_KEY;
    proxykey->func = PROXY_KEY;

    if (!export_RSA_key(privkey[0], &exponent,
                        modulus, &modlen)) {
        log(0, 0, "Error exporting public key");
        free(packet);
        return;
    }

    nonce = htonl(rand());
    proxykey->nonce = nonce;
    proxykey->keyexp = htonl(exponent);
    memcpy(keymod, modulus, modlen);
    proxykey->keylen = htons(modlen);
    sig = keymod + modlen;
    if (!create_RSA_sig(privkey[0], HASH_SHA1, (unsigned char *)&nonce,
                        sizeof(nonce), sig, &siglen) ||
                siglen > modlen) {
        log(0, 0, "Error signing nonce");
        free(packet);
        return;
    }
    proxykey->siglen = htons(siglen);
    meslen = sizeof(struct proxy_key_h) + modlen + siglen;

    header->blsize = htons(meslen);
    meslen += sizeof(struct uftp_h);
    memset(&pubaddr, 0, sizeof(pubaddr));
    pubaddr.sin_family = AF_INET;
    pubaddr.sin_addr = pub_multi[0];
    pubaddr.sin_port = htons(port);
    if (nb_sendto(listener, packet, meslen, 0, 
                  (struct sockaddr *)&pubaddr,
                  sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error sending PROXY_KEY");
    } else {
        log(0, 0, "Sent PROXY_KEY to %s",
                  inet_ntoa(pubaddr.sin_addr));
    }
    free(packet);
}

/**
 * Sends an ABORT message upstream to a server
 */
void send_upstream_abort(int listidx, uint32_t addr, const char *message)
{
    unsigned char *buf;
    struct uftp_h *header;
    struct abort_h *abort;
    int payloadlen;

    buf = calloc(group_list[listidx].mtu, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)buf;
    abort = (struct abort_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, ABORT, listidx);
    if (!group_list[listidx].foundaddr) {
        header->srcaddr = m_interface[0].addr.s_addr;
    }
    header->destaddr = group_list[listidx].srcaddr.s_addr;
    abort->func = ABORT;
    abort->host = addr;
    strncpy(abort->message, message, sizeof(abort->message) - 1);
    header->blsize = htons(sizeof(struct abort_h));
    payloadlen = sizeof(struct uftp_h) + sizeof(struct abort_h);

    // Proxies should never need to send an encrypted ABORT

    if (nb_sendto(listener, buf, payloadlen, 0,
               (struct sockaddr *)&group_list[listidx].up_addr,
               sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id, 0, "Error sending ABORT");
    }

    if (addr == 0) {
        group_cleanup(listidx);
    }
    free(buf);
}

/**
 * Sends an ABORT message downstream to clients
 */
void send_downstream_abort(int listidx, uint32_t addr, const char *message)
{
    unsigned char *buf;
    struct uftp_h *header;
    struct abort_h *abort;
    struct sockaddr_in sin;
    int payloadlen;

    buf = calloc(group_list[listidx].mtu, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)buf;
    abort = (struct abort_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, ABORT, listidx);
    header->destaddr = group_list[listidx].multi.s_addr;
    abort->func = ABORT;
    abort->host = addr;
    strncpy(abort->message, message, sizeof(abort->message) - 1);
    header->blsize = htons(sizeof(struct abort_h));
    payloadlen = sizeof(struct uftp_h) + sizeof(struct abort_h);

    // Proxies should never need to send an encrypted ABORT

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr = group_list[listidx].multi;
    sin.sin_port = htons(out_port);
    if (nb_sendto(listener, buf, payloadlen, 0, (struct sockaddr *)&sin,
               sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id, 0, "Error sending ABORT");
    }

    free(buf);
}

/**
 * Handles an ABORT message from a client or server
 * and forwards if necessary.
 */
void handle_abort(int listidx, const struct sockaddr_in *src,
                  const unsigned char *packet)
{
    struct uftp_h *header;
    struct abort_h *abort;
    int upstream, hostidx, found, i;

    header = (struct uftp_h *)packet;
    abort = (struct abort_h *)(packet + sizeof(struct uftp_h));

    upstream = (!memcmp(src, &group_list[listidx].up_addr, sizeof(*src)));
    if (ntohs(header->blsize) != sizeof(struct abort_h)) {
        log(group_list[listidx].group_id, 0,
                "Rejecting ABORT from %s: invalid message size",
                upstream ? "server" : "client");
    }

    if (upstream) {
        for (i = 0, found = 0; (i < interface_count) && !found; i++) {
            if (abort->host == m_interface[i].addr.s_addr) {
                found = 1;
            }
        }

        if ((abort->host == 0) || found) {
            log(group_list[listidx].group_id, 0,
                    "Transfer aborted by server: %s", abort->message);
            if (proxy_type != RESPONSE_PROXY) {
                send_downstream_abort(listidx, 0, abort->message);
            }
            group_cleanup(listidx);
        } else {
            if (proxy_type != RESPONSE_PROXY) {
                send_downstream_abort(listidx, header->srcaddr, abort->message);
            }
        }
    } else {
        if ((hostidx = find_client(listidx, header->srcaddr)) != -1) {
            log(group_list[listidx].group_id, 0, "Transfer aborted by %s: %s",
                    group_list[listidx].destinfo[hostidx].name, abort->message);
        } else {
            log(group_list[listidx].group_id, 0, "Transfer aborted by %s: %s",
                    inet_ntoa(to_addr(header->srcaddr)), abort->message);
        }
        send_upstream_abort(listidx, header->srcaddr, abort->message);
    }
}

/**
 * Verifies a server's or client's public key fingerprint
 */
int verify_fingerprint(const struct fp_list_t *fplist, int listlen,
                       const unsigned char *keymod, uint32_t keyexp,
                       int keylen, uint32_t addr)
{
    unsigned char *verifydata, fingerprint[HMAC_LEN];
    unsigned int verifylen, fplen;
    int found, keyidx;

    if (listlen == 0) {
        return 1;
    }

    for (keyidx = 0, found = 0; (keyidx < listlen) && !found; keyidx++) {
        if (fplist[keyidx].addr.s_addr == addr) {
            keyidx--;
            found = 1;
        }
    }
    if (!found) {
        return 0;
    }
    if (!fplist[keyidx].has_fingerprint) {
        return 1;
    }

    verifylen = 0;
    verifydata = calloc(sizeof(keyexp) + keylen, 1);
    if (verifydata == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    memcpy(verifydata, &keyexp, sizeof(keyexp));
    verifylen += sizeof(keyexp);
    memcpy(verifydata + verifylen, keymod, keylen);
    verifylen += keylen;
    hash(HASH_SHA1, verifydata, verifylen, fingerprint, &fplen);
    if (memcmp(fplist[keyidx].fingerprint, fingerprint, fplen)) {
        free(verifydata);
        return 0;
    } else {
        free(verifydata);
        return 1;
    }
}

/**
 * Returns the verify_data string used in certain messages.  This value
 * is then run through the PRF with the result going into the message.
 */
uint8_t *build_verify_data(int listidx, int hostidx, int *verifylen, int full)
{
    uint8_t *verifydata;
    uint32_t exponent;
    uint16_t modlen;
    uint8_t modulus[PUBKEY_LEN];
    uint32_t group_id;
    struct pr_group_list_t *group;
    struct pr_destinfo_t *dest;
    RSA_key_t key;

    group = &group_list[listidx];
    if (hostidx != -1) {
        dest = &group->destinfo[hostidx];
    }
    *verifylen = 0;
    if (!full) {
        verifydata = calloc(sizeof(group->group_id) +
                sizeof(group->multi.s_addr) + sizeof(group->rand1) +
                sizeof(group->rand2) + sizeof(group->premaster), 1);
    } else {
        verifydata = calloc(sizeof(group->group_id) +
                sizeof(group->multi.s_addr) + sizeof(group->rand1) +
                sizeof(group->rand2) + sizeof(group->premaster) +
                PUBKEY_LEN + 4 + sizeof(group->groupmaster), 1);
    }
    if (verifydata == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    group_id = htonl(group->group_id);
    memcpy(verifydata, &group_id, sizeof(group_id));
    *verifylen += sizeof(group_id);
    memcpy(verifydata + *verifylen, &group->multi.s_addr,
            sizeof(group->multi.s_addr));
    *verifylen += sizeof(group->multi.s_addr);
    memcpy(verifydata + *verifylen, group->rand1, sizeof(group->rand1));
    *verifylen += sizeof(group->rand1);
    if (hostidx == -1) {
        memcpy(verifydata + *verifylen, group->rand2, sizeof(group->rand2));
        *verifylen += sizeof(group->rand2);
        memcpy(verifydata + *verifylen, group->premaster,
                sizeof(group->premaster));
        *verifylen += sizeof(group->premaster);
    } else {
        memcpy(verifydata + *verifylen, dest->rand2, sizeof(dest->rand2));
        *verifylen += sizeof(dest->rand2);
        memcpy(verifydata + *verifylen, dest->premaster,
                sizeof(dest->premaster));
        *verifylen += sizeof(dest->premaster);
    }

    if (full) {
        if (group->client_auth) {
            if (hostidx == -1) {
                key = group->proxykey;
            } else {
                key = dest->pubkey;
            }
            if (!export_RSA_key(key, &exponent, modulus, &modlen)) {
                free(verifydata);
                return NULL;
            }
            exponent = htonl(exponent);
            memcpy(verifydata + *verifylen, &exponent, sizeof(exponent));
            *verifylen += sizeof(exponent);
            memcpy(verifydata + *verifylen, modulus, modlen);
            *verifylen += modlen;
        }
        memcpy(verifydata + *verifylen, group->groupmaster,
                sizeof(group->groupmaster));
        *verifylen += sizeof(group->groupmaster);
    }

    return verifydata;
}


