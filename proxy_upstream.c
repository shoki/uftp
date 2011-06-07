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
#include <time.h>
#include <errno.h>

#ifdef WINDOWS

#include <ws2tcpip.h>

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
#include "proxy_upstream.h"
#include "proxy_downstream.h"

/**
 * Finds next open slot in the global group list.
 * Returns the index of the open slot, or -1 if none found.
 */
int find_open_slot()
{
    int i;

    for (i = 0; i < MAXLIST; i++) {
        if (group_list[i].group_id == 0) {
            memset(&group_list[i], 0, sizeof(group_list[i]));
            return i;
        }
    }
    return -1;
}

/**
 * Read in the contents of an ANNOUNCE.
 */
void read_announce(int listidx, const unsigned char *buf,
                   const struct sockaddr_in *src)
{
    struct uftp_h *header;
    struct announce_h *announce;
    //int i;

    header = (struct uftp_h *)buf;
    announce = (struct announce_h *)(buf + sizeof(struct uftp_h));

    group_list[listidx].group_id = ntohl(header->group_id);
    group_list[listidx].up_addr = *src;
    group_list[listidx].srcaddr.s_addr = header->srcaddr;
    group_list[listidx].announce_int = ntohs(announce->announce_int);
    group_list[listidx].status_int = ntohs(announce->status_int);
    group_list[listidx].register_int = ntohs(announce->register_int);
    group_list[listidx].done_int = ntohs(announce->done_int);
    group_list[listidx].announce_time = announce->announce_time;
    group_list[listidx].status_time = announce->status_time;
    group_list[listidx].mtu = ntohs(announce->mtu);
    group_list[listidx].payloadsize =
            group_list[listidx].mtu - 28 - sizeof(struct uftp_h);
    group_list[listidx].encpayloadsize = group_list[listidx].payloadsize;
    group_list[listidx].blocksize = group_list[listidx].payloadsize -
                                        sizeof(struct fileseg_h);
/*
    for (i = 0; i < MAX_PEND; i++) {
        group_list[listidx].pending[i].naklist =
                calloc(group_list[listidx].blocksize, 1);
        if (group_list[listidx].pending[i].naklist == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
    }
*/
    group_list[listidx].client_auth = announce->client_auth;
    group_list[listidx].hashtype = announce->hashtype;
    group_list[listidx].keytype = announce->keytype;
    group_list[listidx].sigtype = announce->sigtype;
    group_list[listidx].multi.s_addr = announce->privatemcast;
    gettimeofday(&group_list[listidx].timeout_time, NULL);
    group_list[listidx].timeout_time.tv_sec += announce->status_time;
    gettimeofday(&group_list[listidx].phase_expire_time, NULL);
    group_list[listidx].phase_expire_time.tv_sec +=
            group_list[listidx].announce_time;
}

/**
 * Calculate the master key and do key expansion to determine the symmetric
 * cypher key and IV salt, and hash key for the server
 */
int calculate_server_keys(int listidx, const struct announce_h *announce)
{
    unsigned char *seed, *prf_buf;
    int explen, len, seedlen;
    time_t t;
    uint32_t t2;

    memcpy(group_list[listidx].rand1, announce->rand1, sizeof(announce->rand1));
    if (!get_random_bytes(group_list[listidx].rand2,
                          sizeof(group_list[listidx].rand2))) {
        log(group_list[listidx].group_id, 0,
                "Failed to get random bytes for rand2");
        send_upstream_abort(listidx, 0, "Failed to get random bytes for rand2");
        return 0;
    }
    // Sets the first 4 bytes of rand2 to the current time
    t = time(NULL);
    t2 = (uint32_t)(t & 0xFFFFFFFF);
    *(uint32_t *)(group_list[listidx].rand2) = t2;
    if (!get_random_bytes(group_list[listidx].premaster,
                          sizeof(group_list[listidx].premaster))) {
        log(group_list[listidx].group_id, 0,
                "Failed to get random bytes for premaster");
        send_upstream_abort(listidx, 0,
                "Failed to get random bytes for premaster");
        return 0;
    }

    get_key_info(group_list[listidx].keytype,
                 &group_list[listidx].keylen, &group_list[listidx].ivlen);
    group_list[listidx].hmaclen = get_hash_len(group_list[listidx].hashtype);

    explen = group_list[listidx].keylen + group_list[listidx].ivlen +
             group_list[listidx].hmaclen;
    seedlen = RAND_LEN * 2;
    seed = calloc(seedlen, 1);
    prf_buf = calloc(MASTER_LEN + explen + group_list[listidx].hmaclen, 1);
    if ((seed == NULL) || (prf_buf == NULL)) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    memcpy(seed, group_list[listidx].rand1, sizeof(group_list[listidx].rand1));
    memcpy(seed + sizeof(group_list[listidx].rand1), group_list[listidx].rand2,
            sizeof(group_list[listidx].rand2));
    PRF(group_list[listidx].hashtype, MASTER_LEN, group_list[listidx].premaster,
            sizeof(group_list[listidx].premaster),
            "master secret", seed, seedlen, prf_buf, &len);
    memcpy(group_list[listidx].master,prf_buf,
            sizeof(group_list[listidx].master));

    PRF(group_list[listidx].hashtype, explen, group_list[listidx].master,
            sizeof(group_list[listidx].master), "key expansion",
            seed, seedlen, prf_buf, &len);
    memcpy(group_list[listidx].hmackey, prf_buf, group_list[listidx].hmaclen);
    memcpy(group_list[listidx].key, prf_buf + group_list[listidx].hmaclen,
            group_list[listidx].keylen);
    memcpy(group_list[listidx].salt, prf_buf + group_list[listidx].hmaclen +
            group_list[listidx].keylen, group_list[listidx].ivlen);

    free(seed);
    free(prf_buf);
    return 1;
}

/**
 * Read encryption related fields from an ANNOUNCE
 */
int handle_announce_encryption(int listidx, struct announce_h *announce,
                               unsigned char *keymod)
{
    int i;

    // Sanity check the selected encryption parameters
    if ((group_list[listidx].keytype != KEY_DES) &&
            (group_list[listidx].keytype != KEY_DES_EDE3) &&
            (group_list[listidx].keytype != KEY_AES128) &&
            (group_list[listidx].keytype != KEY_AES256)) {
        log(group_list[listidx].group_id, 0, "Invalid keytype specified");
        send_upstream_abort(listidx, 0, "Invalid keytype specified");
        return 0;
    }
    if (!cipher_supported(group_list[listidx].keytype)) {
        log(group_list[listidx].group_id, 0, "Keytype not supported here");
        send_upstream_abort(listidx, 0, "Keytype not supported here");
        return 0;
    }
    if ((group_list[listidx].hashtype != HASH_SHA1) &&
            (group_list[listidx].hashtype != HASH_SHA256)) {
        log(group_list[listidx].group_id, 0, "Invalid hashtype specified");
        send_upstream_abort(listidx, 0, "Invalid hashtype specified");
        return 0;
    }
    if (!hash_supported(group_list[listidx].hashtype)) {
        log(group_list[listidx].group_id, 0, "Hashtype not supported here");
        send_upstream_abort(listidx, 0, "Hashtype not supported here");
        return 0;
    }
    if ((group_list[listidx].sigtype != SIG_HMAC) &&
            (group_list[listidx].sigtype != SIG_RSA)) {
        log(group_list[listidx].group_id, 0, "Invalid sigtype specified");
        send_upstream_abort(listidx, 0, "Invalid sigtype specified");
        return 0;
    }

    // Load server key and select a matching client key
    if (!import_RSA_key(&group_list[listidx].serverkey, ntohl(announce->keyexp),
                        keymod, ntohs(announce->keylen))) {
        log(group_list[listidx].group_id, 0,
                "Failed to load server public key");
        send_upstream_abort(listidx, 0, "Failed to load server public key");
        return 0;
    }
    if (!verify_fingerprint(server_fp, server_fp_count,
                            keymod, announce->keyexp, ntohs(announce->keylen),
                            group_list[listidx].srcaddr.s_addr)) {
        log(group_list[listidx].group_id, 0,
                "Failed to verify server key fingerprint");
        send_upstream_abort(listidx, 0, "Failed to verify server key fingerprint");
        return 0;
    }
    group_list[listidx].server_keylen=RSA_keylen(group_list[listidx].serverkey);
    for (i = 0; i < key_count; i++) {
        if (RSA_keylen(privkey[i]) == group_list[listidx].server_keylen) {
            group_list[listidx].proxykey = privkey[i];
            group_list[listidx].proxy_keylen = RSA_keylen(privkey[i]);
            break;
        }
    }
    if (!group_list[listidx].proxykey) {
        log(group_list[listidx].group_id, 0,
                "No proxy key with keysize == server keysize of %d",
                group_list[listidx].server_keylen * 8);
        send_upstream_abort(listidx, 0,
                "No proxy key with keysize == server keysize");
        return 0;
    }

    // Calculate keys
    if (!calculate_server_keys(listidx, announce)) {
        return 0;
    }

    // Reset payload and block sizes
    group_list[listidx].encpayloadsize = group_list[listidx].payloadsize -
            sizeof(struct encrypted_h) - KEYBLSIZE -
                    ((group_list[listidx].sigtype == SIG_RSA) ?
                        group_list[listidx].server_keylen :
                        group_list[listidx].hmaclen );
    group_list[listidx].blocksize = group_list[listidx].encpayloadsize -
                                        sizeof(struct fileseg_h);

    return 1;
}

/**
 * Inserts the proxy's public key into an ANNOUNCE
 * Returns 1 on success, 0 on fail
 */
int insert_pubkey_in_announce(int listidx, unsigned char *packet)
{
    struct announce_h *announce;
    unsigned char *keymod;
    uint32_t pr_keyexp;
    uint16_t pr_keylen;

    announce = (struct announce_h *)(packet + sizeof(struct uftp_h));
    keymod = (unsigned char *)announce + sizeof(struct announce_h);

    if ((group_list[listidx].keytype != KEY_NONE) &&
            (proxy_type == CLIENT_PROXY)) {
        // Plug in proxy's public key for server's
        if (!export_RSA_key(group_list[listidx].proxykey,
                            &pr_keyexp, keymod, &pr_keylen)) {
            log(group_list[listidx].group_id, 0,
                    "Error exporting proxy public key");
            return 0;
        }
        if (pr_keylen != group_list[listidx].server_keylen) {
            log(group_list[listidx].group_id, 0,
                    "Incorrect exported proxy key size");
            return 0;
        }
        announce->keylen = htons(pr_keylen);
        announce->keyexp = htonl(pr_keyexp);
    }
    return 1;
}

/**
 * Handles an incoming ANNOUNCE message from a server.
 * Sets up encryption if specified and forwards message.
 */
void handle_announce(int listidx, const struct sockaddr_in *src,
                     unsigned char *packet)
{
    struct uftp_h *header;
    struct announce_h *announce;
    unsigned char *keymod;
    uint32_t *addrlist;
    struct hostent *hp;
    int addrlen, open, addridx, i;

    header = (struct uftp_h *)packet;
    announce = (struct announce_h *)(packet + sizeof(struct uftp_h));
    keymod = (unsigned char *)announce + sizeof(struct announce_h);
    addrlist = (uint32_t *)(keymod + ntohs(announce->keylen));

    addrlen = ntohs(announce->destcount);
    open = (addrlen == 0);

    if ((listidx != -1) && (open || group_list[listidx].foundaddr)) {
        if (insert_pubkey_in_announce(listidx, packet)) {
            forward_message(listidx, src, packet);
        }
        return;
    }

    if (listidx == -1) {
        if ((listidx = find_open_slot()) == -1 ) {
            log(ntohl(header->group_id), 0, "Error: maximum number of "
                    "incoming files exceeded: %d\n", MAXLIST);
            return;
        }
        read_announce(listidx, packet, src);

        if (!noname && (hp =
                gethostbyaddr((char *)&(group_list[listidx].srcaddr),
                              sizeof(struct in_addr), AF_INET))) {
            log(group_list[listidx].group_id, 0,
                    "Received request from %s (%s)",
                    hp->h_name, inet_ntoa(group_list[listidx].srcaddr));
        } else {
            log(group_list[listidx].group_id, 0,
                    "Received request from %s",
                    inet_ntoa(group_list[listidx].srcaddr));
        }
        log(group_list[listidx].group_id, 0,
                "Using private multicast address %s",
                inet_ntoa(group_list[listidx].multi));

        if ((group_list[listidx].keytype != KEY_NONE) &&
                (proxy_type != SERVER_PROXY)) {
            if (!handle_announce_encryption(listidx, announce, keymod)) {
                return;
            }
        }

        if ((group_list[listidx].multi.s_addr != 0) &&
                (proxy_type != CLIENT_PROXY)) {
            if (server_fp_count) {
                if (!is_multicast(group_list[listidx].multi, 1)) {
                    log(group_list[listidx].group_id, 0,
                            "Invalid source specific multicast address: %s",
                            inet_ntoa(group_list[listidx].multi));
                    send_upstream_abort(listidx, 0,
                            "Invalid source specific multicast address");
                    return;
                }
            } else {
                if (!is_multicast(group_list[listidx].multi, 0)) {
                    log(group_list[listidx].group_id, 0,
                            "Invalid multicast address: %s",
                            inet_ntoa(group_list[listidx].multi));
                    send_upstream_abort(listidx,0,"Invalid multicast address");
                    return;
                }
            }
            if (!multicast_join(listener, group_list[listidx].group_id,
                    &group_list[listidx].multi, m_interface, interface_count,
                    server_fp, server_fp_count)) {
                send_upstream_abort(listidx,0,"Error joining multicast group");
                return;
            }
            group_list[listidx].multi_join = 1;
        }
    }
    if (!open) {
        addridx = addr_in_list(addrlist, addrlen);
    } else {
        // Look for the first non-loopback interface or the UID
        addridx = 0;
        for (i = 0; i < interface_count; i++) {
            if (uid) { 
                if (m_interface[i].addr.s_addr == uid) {
                    addridx = i;
                    break;
                }
            } else if (!m_interface[i].isloopback) {
                addridx = i;
                break;
            }
        }
    }
    if (addridx == -1) {
        // The ANNOUNCE that contains our address may not have been received
        // yet, so just grab the first non-loopback interface or the UID
        // and hope it matches up.
        addridx = 0;
        for (i = 0; i < interface_count; i++) {
            if (uid) { 
                if (m_interface[i].addr.s_addr == uid) {
                    addridx = i;
                    break;
                }
            } else if (!m_interface[i].isloopback) {
                addridx = i;
                break;
            }
        }
        group_list[listidx].destaddr = m_interface[addridx].addr;
        group_list[listidx].foundaddr = 0;
    } else {
        group_list[listidx].destaddr = m_interface[addridx].addr;
        group_list[listidx].foundaddr = 1;
    }

    group_list[listidx].phase = PR_PHASE_REGISTERED;
    if (insert_pubkey_in_announce(listidx, packet)) {
        forward_message(listidx, src, packet);
    }
}

/**
 * Handles in incoming REG_CONF from a server when encryption is enabled.
 * Upon receiving this message, mark all clients listed as having received.
 * If we got a KEYINFO from the server, send a KEYINFO to all marked clients.
 */
void handle_regconf(int listidx, const unsigned char *packet)
{
    struct uftp_h *header;
    struct regconf_h *regconf;
    uint32_t *addrlist;
    int hostidx, idx;
    struct pr_destinfo_t *dest;

    header = (struct uftp_h *)packet;
    regconf = (struct regconf_h *)(packet + sizeof(struct uftp_h));
    addrlist = (uint32_t *)((char *)regconf + sizeof(struct regconf_h));

    if (ntohs(header->blsize) != sizeof(struct regconf_h) +
            (ntohs(regconf->destcount) * sizeof(uint32_t))) {
        log(group_list[listidx].group_id, 0, 
                "Rejecting REG_CONF from server: invalid message size");
        return;
    }

    log(group_list[listidx].group_id, 0, "Received REG_CONF");
    for (idx = 0; idx < ntohs(regconf->destcount); idx++) {
        hostidx = find_client(listidx, addrlist[idx]);
        if (hostidx != -1) {
            dest = &group_list[listidx].destinfo[hostidx];
            log(group_list[listidx].group_id, 0, "  for %s", dest->name);
            if (dest->state != PR_CLIENT_READY) {
                dest->state = PR_CLIENT_CONF;
            }
        }
    }
    if (group_list[listidx].phase == PR_PHASE_READY) {
        send_keyinfo(listidx, addrlist, ntohs(regconf->destcount));
    }
    set_timeout(listidx, 0);

}

/**
 * Handles an incoming KEYINFO message from a server.
 * Expected in response to a REGISTER when encryption is enabled.  The proxy
 * itself should be specified, not any clients behind it.
 */
void handle_keyinfo(int listidx, const unsigned char *packet)
{
    struct uftp_h *header;
    struct keyinfo_h *keyinfo;
    struct destkey *keylist;
    unsigned explen, declen;
    int i, j, keyidx, len;
    uint8_t decgroupmaster[MASTER_LEN], *prf_buf, *iv;

    header = (struct uftp_h *)packet;
    keyinfo = (struct keyinfo_h *)(packet + sizeof(struct uftp_h));
    keylist = (struct destkey *)((char *)keyinfo + sizeof(struct keyinfo_h));

    if (ntohs(header->blsize) != sizeof(struct keyinfo_h) +
            (keyinfo->destcount * sizeof(struct destkey))) {
        log(group_list[listidx].group_id, 0,
                "Rejecting KEYINFO from server: invalid message size");
        return;
    }

    // This duplicates addr_in_list, but here it's addressed in a struct array
    for (i = 0, keyidx = -1; (i < keyinfo->destcount) &&
                             (keyidx == -1); i++) {
        for (j = 0; j < interface_count; j++) {
            if (keylist[i].destaddr == m_interface[j].addr.s_addr) {
                keyidx = i;
                break;
            }
        }
    }

    if (keyidx != -1) {
        log(group_list[listidx].group_id, 0, "Received KEYINFO");
        if (group_list[listidx].phase != PR_PHASE_REGISTERED) {
            // We already got the KEYINFO, so no need to reprocess.
            // Just resend the INFO_ACK and reset the timeout
            send_info_ack(listidx, -1, KEYINFO);
            return;
        }
        iv = calloc(group_list[listidx].ivlen, 1);
        if (iv == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        build_iv(iv, group_list[listidx].salt, group_list[listidx].ivlen,
                 htonl(group_list[listidx].group_id), header->srcaddr,
                 keyinfo->tstamp_sec, keyinfo->tstamp_usec);
        if (!decrypt_block(group_list[listidx].keytype, iv,
                    group_list[listidx].key, keylist[keyidx].groupmaster,
                    keyinfo->groupmaster_len, decgroupmaster, &declen) ||
                (declen != MASTER_LEN - 1)) {
            log(group_list[listidx].group_id, 0, 
                    "Decrypt failed for group master");
            send_upstream_abort(listidx, 0, "Decrypt failed for group master");
            free(iv);
            return;
        }
        free(iv);
        group_list[listidx].groupmaster[0] = header->uftp_id;
        memcpy(&group_list[listidx].groupmaster[1], decgroupmaster, declen);

        explen = group_list[listidx].keylen + group_list[listidx].ivlen +
                 group_list[listidx].hmaclen;
        prf_buf = calloc(explen + group_list[listidx].hmaclen, 1);
        if (prf_buf == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        PRF(group_list[listidx].hashtype, explen,
                group_list[listidx].groupmaster,
                sizeof(group_list[listidx].groupmaster), "key expansion",
                group_list[listidx].rand1, sizeof(group_list[listidx].rand1),
                prf_buf, &len);
        memcpy(group_list[listidx].grouphmackey, prf_buf,
                group_list[listidx].hmaclen);
        memcpy(group_list[listidx].groupkey,
                prf_buf + group_list[listidx].hmaclen,
                group_list[listidx].keylen);
        memcpy(group_list[listidx].groupsalt,
                prf_buf + group_list[listidx].hmaclen +
                group_list[listidx].keylen, group_list[listidx].ivlen);

        free(prf_buf);
        group_list[listidx].phase = PR_PHASE_READY;
        // Respond to server, then send any pending REG_CONFs as KEYINFO
        send_info_ack(listidx, -1, KEYINFO);
        send_keyinfo(listidx, NULL, 0);
    }
}

/**
 * Sends a REGISTER to the server for all pending clients.
 */
void send_register(int listidx, int pendidx)
{
    struct uftp_h *header;
    struct register_h *reg;
    unsigned char *buf, *premaster;
    uint32_t *addrlist;
    int len, meslen, destcount;

    buf = calloc(group_list[listidx].mtu, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)buf;
    reg = (struct register_h *)(buf + sizeof(struct uftp_h));
    premaster = (unsigned char *)reg + sizeof(struct register_h);

    set_uftp_header(header, REGISTER, listidx);
    reg->func = REGISTER;
    if (group_list[listidx].keytype != KEY_NONE) {
        memcpy(reg->rand2, group_list[listidx].rand2, RAND_LEN);
        if (!RSA_encrypt(group_list[listidx].serverkey,
                group_list[listidx].premaster, MASTER_LEN,
                premaster, &len)) {
            log(group_list[listidx].group_id, 0,
                    "Error encrypting premaster secret");
            send_upstream_abort(listidx, 0,"Error encrypting premaster secret");
            free(buf);
            return;
        }
        reg->premaster_len = htons(len);
    } else {
        len = 0;
    }

    addrlist = (uint32_t *)(premaster + len);
    destcount = load_pending(listidx, pendidx, REGISTER, addrlist,
                             max_msg_dest(listidx, REGISTER));
    reg->destcount = htons(destcount);

    header->blsize = htons(sizeof(struct register_h) + len +
                           (destcount * sizeof(uint32_t)));
    meslen = sizeof(struct uftp_h) + ntohs(header->blsize);

    if (nb_sendto(listener, buf, meslen, 0,
               (struct sockaddr *)&(group_list[listidx].up_addr),
               sizeof(group_list[listidx].up_addr)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id, 0, "Error sending REGISTER");
    } else {
        log(group_list[listidx].group_id, 0, "REGISTER sent");
    }

    if (group_list[listidx].client_auth) {
        send_clientkey(listidx);
    }
    set_timeout(listidx, 1);
    free(buf);
}

/**
 * Sends a CLIENT_KEY message to the server if requested.
 */
void send_clientkey(int listidx)
{
    struct uftp_h *header;
    struct client_key_h *client_key;
    unsigned char *buf, *keymod, *verify;
    uint32_t exponent;
    uint16_t modlen;
    uint8_t modulus[PUBKEY_LEN];
    uint8_t *verifydata;
    unsigned int siglen, meslen;
    int verifylen;

    buf = calloc(group_list[listidx].mtu, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)buf;
    client_key = (struct client_key_h *)(buf + sizeof(struct uftp_h));
    keymod = (unsigned char *)client_key + sizeof(struct client_key_h);
    verify = keymod + group_list[listidx].proxy_keylen;

    set_uftp_header(header, CLIENT_KEY, listidx);

    client_key->func = CLIENT_KEY;
    if (!export_RSA_key(group_list[listidx].proxykey, &exponent,
                        modulus, &modlen)) {
        log(group_list[listidx].group_id, 0, "Error exporting public key");
        send_upstream_abort(listidx, 0, "Error exporting public key");
        free(buf);
        return;
    }
    client_key->keyexp = htonl(exponent);
    memcpy(keymod, modulus, group_list[listidx].proxy_keylen);
    client_key->keylen = htons(modlen);

    verifydata = build_verify_data(listidx, -1, &verifylen, 0);
    if (!verifydata) {
        log(group_list[listidx].group_id, 0, "Error getting verify data");
        send_upstream_abort(listidx, 0, "Error getting verify data");
        free(verifydata);
        free(buf);
        return;
    }
    if (!create_RSA_sig(group_list[listidx].proxykey,
                        group_list[listidx].hashtype, verifydata,
                        verifylen, verify, &siglen) ||
                siglen > group_list[listidx].proxy_keylen) {
        log(group_list[listidx].group_id, 0, "Error signing verify data");
        send_upstream_abort(listidx, 0, "Error signing verify data");
        free(verifydata);
        free(buf);
        return;
    }
    free(verifydata);
    client_key->verifylen = htons(siglen);
    header->blsize = htons(sizeof(struct client_key_h) + modlen + siglen);

    meslen = sizeof(struct uftp_h) + ntohs(header->blsize);
    if (nb_sendto(listener, buf, meslen, 0,
               (struct sockaddr *)&(group_list[listidx].up_addr),
               sizeof(group_list[listidx].up_addr)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id, 0, "Error sending CLIENT_KEY");
    } else {
        log(group_list[listidx].group_id, 0, "CLIENT_KEY sent");
    }
    free(buf);
}

/**
 * Sends an INFO_ACK to the server in response to a KEYINFO or FILEINFO
 */
void send_info_ack(int listidx, int pendidx, int func)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct infoack_h *info_ack;
    struct pr_pending_info_t *pending;
    unsigned char *verifydata, *verify_hash, *verify_val;
    unsigned int payloadlen, hashlen;
    int verifylen, len, destcount;
    uint32_t *addrlist;

    buf = calloc(group_list[listidx].mtu, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)buf;
    info_ack = (struct infoack_h *)(buf + sizeof(struct uftp_h));
    addrlist = (uint32_t *)((char *)info_ack + sizeof(struct infoack_h));

    payloadlen = sizeof(struct infoack_h);
    set_uftp_header(header, INFO_ACK, listidx);
    info_ack->func = INFO_ACK;
    // If we're responding to a FILEINFO, populate addrlist
    if (func == FILEINFO) {
        pending = &group_list[listidx].pending[pendidx];
        info_ack->file_id = htons(pending->file_id);
        if (pending->partial) {
            info_ack->flags |= FLAG_PARTIAL;
        }
        destcount = load_pending(listidx, pendidx, INFO_ACK, addrlist,
                                 max_msg_dest(listidx, INFO_ACK));
        payloadlen += destcount * sizeof(uint32_t);
        info_ack->destcount = htons(destcount);
    }
    if (group_list[listidx].keytype != KEY_NONE) {
        // If we're responding to a KEYINFO, populate verify_data
        if (func == KEYINFO) {
            info_ack->file_id = 0;
            info_ack->destcount = 0;
            verifydata = build_verify_data(listidx, -1, &verifylen, 1);
            if (!verifydata) {
                log(group_list[listidx].group_id, 0,
                        "Error getting verify data");
                send_upstream_abort(listidx, 0, "Error getting verify data");
                free(buf);
                return;
            }

            verify_hash = calloc(group_list[listidx].hmaclen, 1);
            verify_val = calloc(VERIFY_LEN + group_list[listidx].hmaclen, 1);
            if ((verify_hash == NULL) || (verify_val == NULL)){
                syserror(0, 0, "calloc failed!");
                exit(1);
            }
            hash(group_list[listidx].hashtype, verifydata, verifylen,
                 verify_hash, &hashlen);
            PRF(group_list[listidx].hashtype, VERIFY_LEN,
                    group_list[listidx].groupmaster,
                    sizeof(group_list[listidx].groupmaster),
                    "client finished", verify_hash, hashlen, verify_val, &len);
            memcpy(info_ack->verify_data, verify_val, VERIFY_LEN);
            free(verifydata);
            free(verify_hash);
            free(verify_val);
        }
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen,
                group_list[listidx].mtu, group_list[listidx].keytype,
                group_list[listidx].groupkey, group_list[listidx].groupsalt,
                group_list[listidx].ivlen, group_list[listidx].hashtype,
                group_list[listidx].grouphmackey,
                group_list[listidx].hmaclen, group_list[listidx].sigtype,
                group_list[listidx].proxykey,
                group_list[listidx].proxy_keylen)) {
            log(group_list[listidx].group_id,
                    (func == FILEINFO) ? pending->file_id : 0,
                    "Error encrypting INFO_ACK");
            free(buf);
            return;
        }
        outpacket = encrypted;
        payloadlen = ntohs(((struct uftp_h *)outpacket)->blsize);
    } else {
        encrypted = NULL;
        outpacket = buf;
        header->blsize = htons(payloadlen);
    }
    payloadlen += sizeof(struct uftp_h);

    if (nb_sendto(listener, outpacket, payloadlen, 0,
               (struct sockaddr *)&(group_list[listidx].up_addr),
               sizeof(group_list[listidx].up_addr)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id,
                  (func == FILEINFO) ? pending->file_id : 0,
                  "Error sending INFO_ACK");
    } else {
        log(group_list[listidx].group_id,
                (func == FILEINFO) ? pending->file_id : 0,
                "INFO_ACK sent");
    }
    set_timeout(listidx, (func == FILEINFO));
    free(encrypted);
    free(buf);
}

/**
 * Sends a PRSTATUS to the server for all pending clients.
 */
void send_prstatus(int listidx, int pendidx)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct prstatus_h *prstatus;
    uint32_t *addrlist;
    struct pr_pending_info_t *pending;
    int payloadlen, destcount;

    buf = calloc(group_list[listidx].mtu, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    pending = &group_list[listidx].pending[pendidx];

    header = (struct uftp_h *)buf;
    prstatus = (struct prstatus_h *)(buf + sizeof(struct uftp_h));
    addrlist = (uint32_t *)((char *)prstatus + sizeof(struct prstatus_h));

    set_uftp_header(header, PRSTATUS, listidx);
    prstatus->func = PRSTATUS;
    prstatus->file_id = htons(pending->file_id);
    prstatus->pass = pending->pass;
    prstatus->seq = pending->seq;
    prstatus->section = htons(pending->section);

    destcount = load_pending(listidx, pendidx, STATUS, addrlist,
                             max_msg_dest(listidx, STATUS));
    payloadlen = sizeof(struct prstatus_h) + (destcount * sizeof(uint32_t));
    prstatus->destcount = htons(destcount);

    if (group_list[listidx].keytype != KEY_NONE) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen,
                group_list[listidx].mtu, group_list[listidx].keytype,
                group_list[listidx].groupkey, group_list[listidx].groupsalt,
                group_list[listidx].ivlen, group_list[listidx].hashtype,
                group_list[listidx].grouphmackey,
                group_list[listidx].hmaclen, group_list[listidx].sigtype,
                group_list[listidx].proxykey,
                group_list[listidx].proxy_keylen)) {
            log(group_list[listidx].group_id, pending->file_id,
                    "Error encrypting PRSTATUS");
            free(buf);
            return;
        }
        outpacket = encrypted;
        payloadlen = ntohs(((struct uftp_h *)outpacket)->blsize);
    } else {
        encrypted = NULL;
        outpacket = buf;
        header->blsize = htons(payloadlen);
    }
    payloadlen += sizeof(struct uftp_h);

    if (nb_sendto(listener, outpacket, payloadlen, 0,
               (struct sockaddr *)&group_list[listidx].up_addr,
               sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id, pending->file_id,
                  "Error sending PRSTATUS");
    } else {
        log(group_list[listidx].group_id, pending->file_id,
                "Sent PRSTATUS for pass %d section %d seq %d" ,
                pending->pass, pending->section, pending->seq);
    }

    free(buf);
    free(encrypted);
}

/**
 * Counts the pending naks for the given group
 */
int count_naks(int listidx, int pendidx)
{
    unsigned nak_count, i;

    for (nak_count = 0, i = 0; i < group_list[listidx].blocksize * 8; i++) {
        if ((group_list[listidx].pending[pendidx].naklist[i >> 3] &
                                                  (1 << (i & 7))) != 0) {
            nak_count++;
        }
    }
    // Highly verbose debugging -- print aggregate NAKs before sending
    if (verbose >= 3) {
        for (nak_count = 0, i = 0; i < group_list[listidx].blocksize; i++) {
            sclog("%02X ", group_list[listidx].pending[pendidx].naklist[i]);
            if (i % 25 == 24) slog("");
        }
        slog("");
    }
    return nak_count;
}

/**
 * Sends a STATUS to the server for all pending clients.
 */
void send_status(int listidx, int pendidx)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct status_h *status;
    unsigned char *sent_naks;
    struct pr_pending_info_t *pending;
    int payloadlen, nak_count;

    send_prstatus(listidx, pendidx);

    buf = calloc(group_list[listidx].mtu, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    pending = &group_list[listidx].pending[pendidx];

    header = (struct uftp_h *)buf;
    status = (struct status_h *)(buf + sizeof(struct uftp_h));

    nak_count = count_naks(listidx, pendidx);
    set_uftp_header(header, STATUS, listidx);
    status->func = STATUS;
    status->file_id = htons(pending->file_id);
    status->pass = pending->pass;
    status->seq = pending->seq;
    status->section = htons(pending->section);
    status->nak_count = htonl(nak_count);
    if (nak_count) {
        payloadlen = group_list[listidx].blocksize;
        sent_naks = (unsigned char *)status + sizeof(struct status_h);
        memcpy(sent_naks, pending->naklist, payloadlen);
        memset(pending->naklist, 0, payloadlen);
    } else {
        payloadlen = 0;
    }

    payloadlen += sizeof(struct status_h);
    if (group_list[listidx].keytype != KEY_NONE) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen,
                group_list[listidx].mtu, group_list[listidx].keytype,
                group_list[listidx].groupkey, group_list[listidx].groupsalt,
                group_list[listidx].ivlen, group_list[listidx].hashtype,
                group_list[listidx].grouphmackey,
                group_list[listidx].hmaclen, group_list[listidx].sigtype,
                group_list[listidx].proxykey,
                group_list[listidx].proxy_keylen)) {
            log(group_list[listidx].group_id, pending->file_id,
                    "Error encrypting STATUS");
            free(buf);
            return;
        }
        outpacket = encrypted;
        payloadlen = ntohs(((struct uftp_h *)outpacket)->blsize);
    } else {
        encrypted = NULL;
        outpacket = buf;
        header->blsize = htons(payloadlen);
    }
    payloadlen += sizeof(struct uftp_h);

    if (nb_sendto(listener, outpacket, payloadlen, 0,
               (struct sockaddr *)&group_list[listidx].up_addr,
               sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id, pending->file_id,
                  "Error sending STATUS");
    } else {
        log(group_list[listidx].group_id, pending->file_id,
                "Sent %d NAKs for pass %d section %d seq %d", nak_count, 
                pending->pass, pending->section, pending->seq);
    }
    group_list[listidx].last_seq++;
    set_timeout(listidx, 1);

    free(buf);
    free(encrypted);
}

/**
 * Sends a COMPLETE to the server for all pending clients.
 */
void send_complete(int listidx, int pendidx)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct complete_h *complete;
    uint32_t *addrlist;
    struct pr_pending_info_t *pending;
    int payloadlen, destcount;

    buf = calloc(group_list[listidx].mtu, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    pending = &group_list[listidx].pending[pendidx];

    header = (struct uftp_h *)buf;
    complete = (struct complete_h *)(buf + sizeof(struct uftp_h));
    addrlist = (uint32_t *)((char *)complete + sizeof(struct complete_h));

    set_uftp_header(header, COMPLETE, listidx);
    complete->func = COMPLETE;
    complete->file_id = htons(pending->file_id);

    destcount = load_pending(listidx, pendidx, COMPLETE, addrlist,
                             max_msg_dest(listidx, COMPLETE));
    payloadlen = sizeof(struct complete_h) + (destcount * sizeof(uint32_t));
    complete->destcount = htons(destcount);

    if (group_list[listidx].keytype != KEY_NONE) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen,
                group_list[listidx].mtu, group_list[listidx].keytype,
                group_list[listidx].groupkey, group_list[listidx].groupsalt,
                group_list[listidx].ivlen, group_list[listidx].hashtype,
                group_list[listidx].grouphmackey,
                group_list[listidx].hmaclen, group_list[listidx].sigtype,
                group_list[listidx].proxykey,
                group_list[listidx].proxy_keylen)) {
            log(group_list[listidx].group_id, pending->file_id,
                    "Error encrypting COMPLETE");
            free(buf);
            return;
        }
        outpacket = encrypted;
        payloadlen = ntohs(((struct uftp_h *)outpacket)->blsize);
    } else {
        encrypted = NULL;
        outpacket = buf;
        header->blsize = htons(payloadlen);
    }
    payloadlen += sizeof(struct uftp_h);

    if (nb_sendto(listener, outpacket, payloadlen, 0,
               (struct sockaddr *)&group_list[listidx].up_addr,
               sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id, pending->file_id,
                  "Error sending COMPLETE");
    } else {
        log(group_list[listidx].group_id, pending->file_id, "Sent COMPLETE");
    }
    set_timeout(listidx, 1);

    free(buf);
    free(encrypted);
}

