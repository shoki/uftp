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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef WINDOWS

#include "win_func.h"

#else

#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#endif

#include "proxy.h"
#include "proxy_common.h"
#include "proxy_downstream.h"

/**
 * Adds a client to the given group
 */
int add_client(uint32_t addr, int listidx)
{
    struct hostent *hp;
    struct in_addr inaddr;
    struct pr_destinfo_t *dest;

    dest = &group_list[listidx].destinfo[group_list[listidx].destcount];
    inaddr.s_addr = addr;
    if (ntohl(addr) <= 0xffffff) {
        sprintf(dest->name, "0x%06X", ntohl(addr));
    } else {
        if (!noname && (hp = gethostbyaddr((char *)&inaddr,
                                           sizeof(struct in_addr), AF_INET))) {
            strncpy(dest->name, hp->h_name, sizeof(dest->name)-1);
        } else {
            strncpy(dest->name, inet_ntoa(inaddr), sizeof(dest->name)-1);
        }
        dest->name[sizeof(dest->name)-1] = '\x0';
    }
    dest->addr = inaddr;
    dest->pending = -1;
    return group_list[listidx].destcount++;
}

/**
 * For a given client, calculate the master key and do key expansion
 * to determine the symmetric cypher key and IV salt, and hash key
 */
void calculate_client_keys(int listidx, int hostidx)
{
    unsigned char *seed, *prf_buf;
    int explen, len, seedlen;
    struct pr_group_list_t *group;
    struct pr_destinfo_t *dest;

    group = &group_list[listidx];
    dest = &group->destinfo[hostidx];

    explen = group->keylen + group->ivlen +
             group->hmaclen;
    seedlen = sizeof(group->rand1) * 2;
    seed = calloc(seedlen, 1);
    prf_buf = calloc(MASTER_LEN + explen + group->hmaclen, 1);
    if ((seed == NULL) || (prf_buf == NULL)) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    memcpy(seed, group->rand1, sizeof(group->rand1));
    memcpy(seed + sizeof(group_list[listidx].rand1), dest->rand2,
            sizeof(dest->rand2));
    PRF(group->hashtype, MASTER_LEN, dest->premaster, sizeof(dest->premaster),
            "master secret", seed, seedlen, prf_buf, &len);
    memcpy(dest->master,prf_buf, sizeof(dest->master));

    PRF(group->hashtype, explen, dest->master, sizeof(dest->master),
            "key expansion", seed, seedlen, prf_buf, &len);
    memcpy(dest->hmackey, prf_buf, group->hmaclen);
    memcpy(dest->key, prf_buf + group->hmaclen, group->keylen);
    memcpy(dest->salt, prf_buf + group->hmaclen + group->keylen, group->ivlen);

    free(seed);
    free(prf_buf);
}

/**
 * Verifies the data in a CLIENT_KEY message signed by the client's public key
 */
int verify_client_key(int listidx, int hostidx)
{
    uint8_t *verifydata;
    int verifylen;
    struct pr_destinfo_t *dest;

    dest = &group_list[listidx].destinfo[hostidx];

    // build_verify_data should never fail in this case
    verifydata = build_verify_data(listidx, hostidx, &verifylen, 0);

    if (!verify_RSA_sig(dest->pubkey, group_list[listidx].hashtype, verifydata,
            verifylen, dest->verifydata, dest->verifylen)) {
        log(group_list[listidx].group_id, 0, "Rejecting CLIENT_KEY from %s: "
                "verify data mismatch", dest->name);
        free(verifydata);
        return 0;
    }

    free(verifydata);
    return 1;
}

/**
 * Processes encryption key information received in a REGISTER message
 */
int handle_register_keys(const struct register_h *reg,
                         const unsigned char *enckey, int listidx, int hostidx,
                         uint32_t src)
{
    unsigned char *decrypted;
    int len;
    struct pr_destinfo_t *dest;

    dest = &group_list[listidx].destinfo[hostidx];
    decrypted = calloc(PUBKEY_LEN, 1);
    if (decrypted == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    memcpy(dest->rand2, reg->rand2, sizeof(dest->rand2));
    if (!RSA_decrypt(group_list[listidx].proxykey, enckey,
                     ntohs(reg->premaster_len), decrypted, &len)) {
        log(group_list[listidx].group_id, 0, "Rejecting REGISTER from %s: "
                "failed to decrypt premaster secret", dest->name);
        free(decrypted);
        return 0;
    }
    if (len > ntohs(reg->premaster_len)) {
        log(group_list[listidx].group_id, 0, "Rejecting REGISTER from %s: "
                "decrypted premaster secret too long", dest->name);
        free(decrypted);
        return 0;
    }
    memcpy(dest->premaster, decrypted, len);
    calculate_client_keys(listidx, hostidx);
    free(decrypted);

    if (dest->pubkey) {
        if (!verify_client_key(listidx, hostidx)) {
            return 0;
        }
    }

    return 1;
}

/**
 * Handles an incoming REGSITER message from a client.
 */
void handle_register(int listidx, int hostidx, const unsigned char *message,
                     int meslen, uint32_t src)
{
    struct register_h *reg;
    unsigned char *enckey;
    struct pr_destinfo_t *dest;
    int dupmsg;

    reg = (struct register_h *)message;
    enckey = (unsigned char *)reg + sizeof(struct register_h);

    if (group_list[listidx].destcount == MAXDEST) {
        log(group_list[listidx].group_id, 0, "Rejecting REGISTER from %s: "
                "max destinations exceeded", inet_ntoa(to_addr(src)));
        send_downstream_abort(listidx, src, "Max destinations exceeded");
        return;
    }
    if (meslen != sizeof(struct register_h) + ntohs(reg->premaster_len) +
                  (ntohs(reg->destcount) * sizeof(uint32_t))) {
        log(group_list[listidx].group_id, 0, "Rejecting REGISTER from %s: "
                "invalid message size", inet_ntoa(to_addr(src)));
        send_downstream_abort(listidx, src, "Invalid message size");
        return;
    }

    if (hostidx == -1) {
        hostidx = add_client(src, listidx);
    }
    dest = &group_list[listidx].destinfo[hostidx];
    dupmsg = (dest->registered == 1);
    dest->registered = 1;

    if (dest->state != PR_CLIENT_REGISTERED) {
        if (group_list[listidx].keytype != KEY_NONE) {
            if (!handle_register_keys(reg, enckey, listidx, hostidx, src)) {
                return;
            }
        }
        if (!group_list[listidx].client_auth || dest->pubkey) {
            dest->state = PR_CLIENT_REGISTERED;
        }
    }

    log(group_list[listidx].group_id, 0, "Received REGISTER%s from %s",
            dupmsg ? "+" : "", dest->name);

    if (dest->state == PR_CLIENT_REGISTERED) {
        check_pending(listidx, hostidx, message);
    }
}

/**
 * Handles an incoming CLIENT_KEY message from a client.
 */
void handle_clientkey(int listidx, int hostidx, const unsigned char *message,
                      int meslen, uint32_t src)
{
    struct client_key_h *clientkey;
    unsigned char *keymod, *verify;
    struct pr_destinfo_t *dest;
    int dupmsg;

    clientkey = (struct client_key_h *)message;
    keymod = (unsigned char *)clientkey + sizeof(struct client_key_h);
    verify = keymod + ntohs(clientkey->keylen);

    if (group_list[listidx].destcount == MAXDEST) {
        log(group_list[listidx].group_id, 0, "Rejecting CLIENT_KEY from %s: "
                "max destinations exceeded", inet_ntoa(to_addr(src)));
        send_downstream_abort(listidx, src, "Max destinations exceeded");
        return;
    }
    if (meslen != sizeof(struct client_key_h) + ntohs(clientkey->keylen) +
                  ntohs(clientkey->verifylen)) {
        log(group_list[listidx].group_id, 0, "Rejecting REGISTER from %s: "
                "invalid message size", inet_ntoa(to_addr(src)));
        send_downstream_abort(listidx, src, "Invalid message size");
        return;
    }

    if (hostidx == -1) {
        hostidx = add_client(src, listidx);
    }
    dest = &group_list[listidx].destinfo[hostidx];
    dupmsg = (dest->pubkey != (RSA_key_t)NULL);

    if (!dest->verified) {
        if (!import_RSA_key(&dest->pubkey, ntohl(clientkey->keyexp),
                            keymod, ntohs(clientkey->keylen))) {
            log(group_list[listidx].group_id, 0,
                    "Failed to load client public key");
            send_downstream_abort(listidx, src,
                                  "Failed to load client public key");
            return;
        }
        dest->pubkeylen = RSA_keylen(dest->pubkey);
        if (!verify_fingerprint(client_fp, client_fp_count,
                                keymod, clientkey->keyexp,
                                ntohs(clientkey->keylen), src)) {
            log(group_list[listidx].group_id, 0,
                    "Failed to verify client key fingerprint");
            send_downstream_abort(listidx, src, 
                                  "Failed to verify client key fingerprint");
            return;
        }
        dest->verified = 1;
    }

    memcpy(dest->verifydata, verify, ntohs(clientkey->verifylen));
    dest->verifylen = ntohs(clientkey->verifylen);
    if (dest->registered) {
        if (!verify_client_key(listidx, hostidx)) {
            return;
        }
        dest->state = PR_CLIENT_REGISTERED;
    }

    log(group_list[listidx].group_id, 0, "Received CLIENT_KEY%s from %s",
            dupmsg ? "+" : "", dest->name);

    if (dest->state == PR_CLIENT_REGISTERED) {
        // Pass in a dummy REGISTER message to check_pending, since
        // CLIENT_KEY is basically an extention of REGISTER.
        // Since only the leading byte is looked at for a REGISTER,
        // the dummy message is just a single byte.
        unsigned char reg = REGISTER;
        check_pending(listidx, hostidx, &reg);
    }
}

/**
 * Handles an incoming INFO_ACK from a client for either KEYINFO or FILEINFO
 */
void handle_info_ack(int listidx, int hostidx,
                     const unsigned char *message, int meslen)
{
    struct infoack_h *infoack;
    uint32_t *addr;
    unsigned char *verifydata, *verify_hash, *verify_test;
    int verifylen, len, clientcnt, dupmsg;
    unsigned int hashlen;
    struct pr_group_list_t *group;
    struct pr_destinfo_t *dest;

    infoack = (struct infoack_h *)message;
    addr = (uint32_t *)((char *)infoack + sizeof(struct infoack_h));
    clientcnt = ntohs(infoack->destcount);
    group = &group_list[listidx];
    dest = &group->destinfo[hostidx];

    if (meslen != sizeof(struct infoack_h) +
                  (clientcnt * sizeof(uint32_t))) {
        log(group->group_id, ntohs(infoack->file_id),
                "Rejecting INFO_ACK from %s: invalid message size", dest->name);
        send_downstream_abort(listidx, dest->addr.s_addr,
                              "Invalid message size");
        return;
    }

    // If in response to a KEYINFO, check the verify data
    if ((group->keytype != KEY_NONE) && ntohs(infoack->file_id) == 0) {
        if (!(verifydata = build_verify_data(listidx, hostidx, &verifylen,1))) {
            log(group->group_id, ntohs(infoack->file_id),
                    "Rejecting INFO_ACK from %s: error exporting "
                    "client public key", dest->name);
            return;
        }
        verify_hash = calloc(group->hmaclen, 1);
        verify_test = calloc(VERIFY_LEN + group->hmaclen, 1);
        if ((verify_hash == NULL) || (verify_test == NULL)){
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        hash(group->hashtype, verifydata, verifylen, verify_hash, &hashlen);
        PRF(group->hashtype, VERIFY_LEN, group->groupmaster,
                sizeof(group->groupmaster), "client finished",
                verify_hash, hashlen, verify_test, &len);
        if (memcmp(infoack->verify_data, verify_test, VERIFY_LEN)) {
            log(group->group_id, ntohs(infoack->file_id),
                    "Rejecting INFO_ACK from %s: verify data mismatch",
                    dest->name);
            free(verifydata);
            free(verify_hash);
            free(verify_test);
            return;
        }

        free(verifydata);
        free(verify_hash);
        free(verify_test);

        dupmsg = (dest->state == PR_CLIENT_READY);
        log(group->group_id, ntohs(infoack->file_id),
                "Received INFO_ACK%s from %s", dupmsg ? "+" : "", dest->name);
        dest->state = PR_CLIENT_READY;
        if (!check_unfinished_clients(listidx, 0)) {
            group->phase = PR_PHASE_RECEIVING;
        }
    } else {
        log(group->group_id, ntohs(infoack->file_id),
                "Received INFO_ACK from %s", dest->name);
        check_pending(listidx, hostidx, message);
    }
}

/**
 * Sends a KEYINFO to each client that the server sent a REG_CONF for.
 */
void send_keyinfo(int listidx, uint32_t *addrlist, int addrlen)
{
    unsigned char *buf, *iv;
    struct uftp_h *header;
    struct keyinfo_h *keyinfo;
    struct destkey *keylist;
    struct timeval tv;
    unsigned int payloadlen, len;
    int maxdest, packetcnt, dests, foundaddr, i, j;
    struct pr_destinfo_t *dest;
    struct sockaddr_in sin;

    buf = calloc(group_list[listidx].mtu, 1);
    iv = calloc(group_list[listidx].ivlen, 1);
    if ((buf == NULL) || (iv == NULL)) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)buf;
    keyinfo = (struct keyinfo_h *)(buf + sizeof(struct uftp_h));
    keylist = (struct destkey *)((char *)keyinfo + sizeof(struct keyinfo_h));

    set_uftp_header(header, KEYINFO, listidx);
    keyinfo->func = KEYINFO;

    maxdest = max_msg_dest(listidx, KEYINFO);
    packetcnt = 1;
    gettimeofday(&tv, NULL);
    keyinfo->tstamp_sec = htonl(tv.tv_sec);
    keyinfo->tstamp_usec = htonl(tv.tv_usec);
    for (i = 0, dests = 0; i < group_list[listidx].destcount; i++) {
        dest = &group_list[listidx].destinfo[i];
        if (dest->state == PR_CLIENT_CONF) {
            if (addrlist) {
                // We just got a REG_CONF, so only send to listed hosts
                for (j = 0, foundaddr = 0; (j < addrlen) && (!foundaddr); j++) {
                    if (dest->addr.s_addr == addrlist[j]) {
                        foundaddr = 1;
                    }
                }
            } else {
                foundaddr = 1;
            }
            if (foundaddr) {
                keylist[dests].destaddr = dest->addr.s_addr;
                build_iv(iv, dest->salt, group_list[listidx].ivlen,
                         htonl(group_list[listidx].group_id),
                         group_list[listidx].destaddr.s_addr,
                         htonl(tv.tv_sec), htonl(tv.tv_usec));
                if (!encrypt_block(group_list[listidx].keytype, iv, dest->key,
                                   &group_list[listidx].groupmaster[1],
                                   sizeof(group_list[listidx].groupmaster) - 1,
                                   keylist[dests].groupmaster, &len)) {
                    log(group_list[listidx].group_id, 0,
                            "Error encrypting KEYINFO for %s", dest->name);
                    free(buf);
                    free(iv);
                    return;
                }
                if (!keyinfo->groupmaster_len) keyinfo->groupmaster_len = len;
                dests++;
            }
        }
        if ((dests >= maxdest) ||
                ((i == group_list[listidx].destcount - 1) && (dests > 0))) {
            payloadlen = sizeof(struct keyinfo_h) +
                         (dests * sizeof(struct destkey));
            header->blsize = htons(payloadlen);
            keyinfo->destcount = dests;
            log(group_list[listidx].group_id, 0, "Sending KEYINFO %d.%d",
                    group_list[listidx].keyinfo_cnt, packetcnt);
            memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            sin.sin_addr = group_list[listidx].multi;
            sin.sin_port = htons(out_port);
            if (nb_sendto(listener, buf, payloadlen + sizeof(struct uftp_h), 0,
                       (struct sockaddr *)&sin, sizeof(sin)) == SOCKET_ERROR) {
                sockerror(group_list[listidx].group_id, 0,
                          "Error sending KEYINFO");
                free(buf);
                free(iv);
                return;
            }
            // TODO: This value is good for around 100Mbps.  This is under the
            // assumtion that the client proxy is local to the clients
            // it serves.  This should probably be a parameter.
            usleep(120);
            memset(keylist, 0, maxdest * sizeof(struct destkey));
            dests = 0;
            packetcnt++;
        }
    }
    group_list[listidx].keyinfo_cnt++;
    set_timeout(listidx, 0);
    free(buf);
    free(iv);
}

/**
 * Handles an incoming STATUS message from a client
 */
void handle_status(int listidx, int hostidx,
                   const unsigned char *message, int meslen)
{
    struct status_h *status;
    int mes_pass, mes_section, nak_count;
    struct pr_destinfo_t *dest;

    status = (struct status_h *)message;
    mes_pass = status->pass;
    mes_section = ntohs(status->section);
    nak_count = ntohl(status->nak_count);
    dest = &group_list[listidx].destinfo[hostidx];

    if (meslen != sizeof(struct status_h) +
                  (nak_count ? group_list[listidx].blocksize : 0)) {
        log(group_list[listidx].group_id, 0,
                "Rejecting STATUS from %s: invalid message size", dest->name);
        return;
    }

    log(group_list[listidx].group_id, ntohs(status->file_id),
            "Got %d NAKs for pass %d section %d from %s",
            nak_count, mes_pass, mes_section, dest->name);

    check_pending(listidx, hostidx, message);
}

/**
 * Handles an incoming COMPLETE message from a client
 */
void handle_complete(int listidx, int hostidx,
                     const unsigned char *message, int meslen)
{
    struct complete_h *complete;
    struct pr_destinfo_t *dest;
    int alldone, i;

    complete = (struct complete_h *)message;
    dest = &group_list[listidx].destinfo[hostidx];

    if (meslen != sizeof(struct complete_h) +
                  (ntohs(complete->destcount) * sizeof(uint32_t))) {
        log(group_list[listidx].group_id, 0,
                "Rejecting COMPLETE from %s: invalid message size", dest->name);
        return;
    }

    log(group_list[listidx].group_id, ntohs(complete->file_id),
            "Received COMPLETE from %s", dest->name);

    if (ntohs(complete->file_id) == 0) {
        dest->state = PR_CLIENT_DONE;
        for (alldone = 1, i = 0;
                (i < group_list[listidx].destcount) && alldone; i++) {
            alldone = alldone &&
                    (group_list[listidx].destinfo[i].state == PR_CLIENT_DONE);
        }
        if (alldone) {
            group_list[listidx].phase = PR_PHASE_DONE;
        }
    }

    check_pending(listidx, hostidx, message);
}

