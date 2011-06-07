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

#else  // if WINDOWS

#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>

#endif

#include "server.h"
#include "server_common.h"
#include "server_announce.h"

/**
 * Send the ANNOUNCE message
 * For open group membership, just send one.  For closed group membership,
 * list as many destinations as will fit and send multiple packets so that
 * each receiver is listed.
 * Returns 1 on success, 0 on fail.
 */
int send_announce(const struct finfo_t *finfo, int attempt, int open)
{
    int packetlen, rval;
    unsigned char *buf, *keymod;
    struct uftp_h *header;
    struct announce_h *announce;
    uint32_t *addrlist;
    uint32_t keyexp;
    uint16_t keylen;

    buf = calloc(mtu, 1); 
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)buf;
    announce = (struct announce_h *)(buf + sizeof(struct uftp_h));
    keymod = (unsigned char *)announce + sizeof(struct announce_h);

    set_uftp_header(header, ANNOUNCE, finfo, &listen_dest);
    announce->func = ANNOUNCE;
    if (restart_groupid) {
        announce->flags |= FLAG_RESTART;
    }
    announce->announce_int = htons(announce_int);
    announce->status_int = htons(status_int);
    announce->register_int = htons(register_int);
    announce->done_int = htons(done_int);
    announce->announce_time = announce_time;
    announce->status_time = status_time;
    announce->privatemcast = unicast ? 0 : receive_dest.sin_addr.s_addr;
    announce->mtu = htons(mtu);
    announce->client_auth = client_auth;
    announce->sigtype = sigtype;
    announce->hashtype = hashtype;
    announce->keytype = keytype;
    if (keytype != KEY_NONE) {
        if (!export_RSA_key(privkey, &keyexp, keymod, &keylen)) {
            log(0, 0, "Error exporting server public key");
            free(buf);
            return 0;
        }
        announce->keylen = htons(keylen);
        announce->keyexp = htonl(keyexp);
    } else {
        keylen = 0;
    }
    memcpy(announce->rand1, rand1, sizeof(rand1));

    addrlist = (uint32_t *)(keymod + keylen);
    if (open) {
        packetlen = sizeof(struct uftp_h) + sizeof(struct announce_h) + keylen;
        header->blsize = htons(sizeof(struct announce_h) + keylen);
        announce->destcount = 0;
        log(0, 0, "Sending ANNOUNCE %d", attempt);
        if (nb_sendto(sock, buf, packetlen, 0, (struct sockaddr *)&listen_dest,
                   sizeof(listen_dest)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error sending ANNOUNCE");
            // So we don't spin our wheels...
            sleep(1);
            free(buf);
            return 0;
        }
        free(buf);
        return 1;
    } else {
        rval = send_multiple(finfo, buf, ANNOUNCE, attempt, addrlist,
                DEST_MUTE, &announce->destcount, 0, &listen_dest, 0);
        free(buf);
        return rval;
    }
}

/**
 * Send out REG_CONF messages specifiying all registered clients.
 * Sent when encryption is disabled, or if the client is behind a proxy.
 * Returns 1 on success, 0 on fail
 */
int send_regconf(const struct finfo_t *finfo, int attempt, int do_regconf)
{
    int rval;
    unsigned char *buf;
    struct uftp_h *header;
    struct regconf_h *regconf;
    uint32_t *addrlist;

    buf = calloc(mtu, 1); 
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)buf;
    regconf = (struct regconf_h *)(buf + sizeof(struct uftp_h));
    addrlist = (uint32_t *)((char *)regconf + sizeof(struct regconf_h));

    set_uftp_header(header, REG_CONF, finfo, &receive_dest);
    regconf->func = REG_CONF;
    rval = send_multiple(finfo, buf, REG_CONF, attempt, addrlist, DEST_ACTIVE,
            &regconf->destcount, 0, &receive_dest, do_regconf);
    free(buf);
    return rval;
}

/**
 * Send a KEYINFO message.  Sent during the Announce phase for a group
 * with encryption enabled.
 * Returns 1 on success, 0 on fail.
 */
int send_keyinfo(const struct finfo_t *finfo, int attempt)
{
    unsigned char *buf, *iv;
    struct uftp_h *header;
    struct keyinfo_h *keyinfo;
    struct destkey *keylist;
    struct timeval tv;
    unsigned int hsize, payloadlen, len;
    int maxdest, packetcnt, dests, i;

    buf = calloc(mtu, 1);
    iv = calloc(ivlen, 1);
    if ((buf == NULL) || (iv == NULL)) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)buf;
    keyinfo = (struct keyinfo_h *)(buf + sizeof(struct uftp_h));
    keylist = (struct destkey *)((char *)keyinfo + sizeof(struct keyinfo_h));

    set_uftp_header(header, KEYINFO, finfo, &receive_dest);
    keyinfo->func = KEYINFO;

    hsize = sizeof(struct keyinfo_h);
    maxdest = (payloadsize - hsize) / sizeof(struct destkey);
    packetcnt = 1;
    gettimeofday(&tv, NULL);
    keyinfo->tstamp_sec = htonl(tv.tv_sec);
    keyinfo->tstamp_usec = htonl(tv.tv_usec);
    for (i = 0, dests = 0; i < destcount; i++) {
        if (destlist[i].status == DEST_REGISTERED) {
            keylist[dests].destaddr = destlist[i].addr.s_addr;
            build_iv(iv, destlist[i].salt, ivlen, htonl(finfo->group_id), 
                     out_addr.s_addr, htonl(tv.tv_sec), htonl(tv.tv_usec));
            if (!encrypt_block(keytype, iv, destlist[i].key,
                               &groupmaster[1], sizeof(groupmaster) - 1,
                               keylist[dests].groupmaster, &len)) {
                log(0, 0, "Error encrypting KEYINFO for %s", destlist[i].name);
                free(buf);
                free(iv);
                return 0;
            }
            if (!keyinfo->groupmaster_len) keyinfo->groupmaster_len = len;
            dests++;
        }
        if ((dests >= maxdest) || ((i == destcount - 1) && (dests > 0))) {
            payloadlen = hsize + (dests * sizeof(struct destkey));
            header->blsize = htons(payloadlen);
            keyinfo->destcount = dests;
            log(0, 0, "Sending KEYINFO %d.%d", attempt, packetcnt);
            if (nb_sendto(sock, buf, payloadlen + sizeof(struct uftp_h), 0,
                       (struct sockaddr *)&receive_dest,
                       sizeof(receive_dest)) == SOCKET_ERROR) {
                sockerror(0, 0, "Error sending KEYINFO");
                sleep(1);
                free(buf);
                free(iv);
                return 0;
            }
            if (packet_wait) usleep(packet_wait);
            memset(keylist, 0, maxdest * sizeof(struct destkey));
            dests = 0;
            packetcnt++;
        }
    }
    free(buf);
    free(iv);
    return 1;
}

/**
 * Send a FILEINFO message.  Sent for each individual file.
 * Returns 1 on success, 0 on fail.
 */
int send_fileinfo(const struct finfo_t *finfo, int attempt)
{
    int rval;
    unsigned char *buf;
    struct uftp_h *header;
    struct fileinfo_h *fileinfo;
    uint32_t *addrlist;
    char *linkname;

    buf = calloc(mtu, 1); 
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)buf;
    fileinfo = (struct fileinfo_h *)(buf + sizeof(struct uftp_h));
    addrlist = (uint32_t *)((char *)fileinfo + sizeof(struct fileinfo_h));

    set_uftp_header(header, FILEINFO, finfo, &receive_dest);
    fileinfo->func = FILEINFO;
    fileinfo->ftype = finfo->ftype;
    fileinfo->file_id = htons(finfo->file_id);
    fileinfo->block_total = htonl(finfo->blocks);
    fileinfo->section_total = htons(finfo->sections);
    fileinfo->lofsize = htonl((finfo->size & 0xFFFFFFFF));
    fileinfo->hifsize = htonl((finfo->size >> 32));
    strncpy(fileinfo->name, finfo->destfname, sizeof(fileinfo->name));
    fileinfo->name[strlen(finfo->destfname)] = '\x0';
    if (finfo->ftype == FTYPE_LINK) {
        linkname = fileinfo->name + strlen(finfo->destfname) + 1;
        strncpy(linkname, finfo->linkname,
                sizeof(fileinfo->name) - (fileinfo->name - linkname));
        linkname[strlen(finfo->linkname)] = '\x0';
    }

    rval = send_multiple(finfo, buf, FILEINFO, attempt, addrlist,
            DEST_REGISTERED, &fileinfo->destcount, (keytype != KEY_NONE),
            &receive_dest, 0);
    free(buf);
    return rval;
}

/**
 * Adds a registered host to the hostlist.  Returns the list index.
 */
int add_dest_by_addr(uint32_t addr, struct finfo_t *finfo,
                     int state, int proxyidx, int clientcnt)
{
    struct hostent *hp;
    struct in_addr inaddr; 

    inaddr.s_addr = addr;
    if (ntohl(addr) <= 0xffffff) {
        sprintf(destlist[destcount].name, "0x%06X", ntohl(addr));
    } else {
        if (!noname && (hp = gethostbyaddr((char *)&inaddr, 
                                           sizeof(struct in_addr), AF_INET))) {
            strncpy(destlist[destcount].name, hp->h_name,
                    sizeof(destlist[destcount].name)-1);
        } else {
            strncpy(destlist[destcount].name, inet_ntoa(inaddr),
                    sizeof(destlist[destcount].name)-1);
        }
        destlist[destcount].name[sizeof(destlist[destcount].name)-1] = '\x0';
    }
    destlist[destcount].addr = inaddr;
    destlist[destcount].status = state;
    destlist[destcount].proxyidx = proxyidx;
    destlist[destcount].clientcnt = clientcnt;
    return destcount++;
}

/**
 * When a proxy registers, process the clients the proxy is serving
 */
void add_proxy_dests(struct finfo_t *finfo, const uint32_t *addr,
                     const struct sockaddr_in *sin, int clientcnt,
                     int proxyidx, int open)
{
    int startcnt, hostidx, i, dupmsg;

    if (destlist[proxyidx].clientcnt == -1) {
        // True when using open group membership and
        // we get a CLIENT_KEY before the REGSITER for a proxy
        destlist[proxyidx].clientcnt = 0;
    }
    startcnt = destlist[proxyidx].clientcnt;
    for (i = 0; i < clientcnt; i++) {
        dupmsg = 0;
        hostidx = find_client(addr[i]);
        if (hostidx == -1) {
            if (open) {
                hostidx = add_dest_by_addr(addr[i], finfo, DEST_ACTIVE,
                                           proxyidx, -1);
            } else {
                struct in_addr inaddr = to_addr(addr[i]);
                log(0, 0, "Host %s not in host list", inet_ntoa(inaddr));
                send_abort(finfo, "Not in host list", sin, &inaddr, 0);
                continue;
            }
        } else {
            dupmsg = (destlist[hostidx].status == DEST_ACTIVE);
            destlist[hostidx].status = DEST_ACTIVE;
            destlist[hostidx].proxyidx = proxyidx;
        }
        finfo->deststate[hostidx].conf_sent = 0;
        log(0, 0, "  For client%s %s", dupmsg ? "+" : "",
                  destlist[hostidx].name);
        destlist[proxyidx].clients[i + startcnt] = hostidx;
    }
    destlist[proxyidx].clientcnt += clientcnt;
}

/**
 * Returns the verify_data string used in certain messages.  This value
 * is then run through the PRF with the result going into the message
 */
uint8_t *build_verify_data(const struct finfo_t *finfo, int hostidx,
                           int *verifylen)
{
    uint8_t *verifydata;
    uint32_t blank;
    uint32_t exponent;
    uint16_t modlen;
    uint8_t modulus[PUBKEY_LEN];
    uint32_t n_group_id;

    memset(&blank, 0, sizeof(blank));
    *verifylen = 0;
    if (destlist[hostidx].status == DEST_MUTE) {
        verifydata = calloc(sizeof(finfo->group_id) +
                sizeof(receive_dest.sin_addr.s_addr) + sizeof(rand1) +
                sizeof(destlist[hostidx].rand2) +
                sizeof(destlist[hostidx].premaster), 1);
    } else {
        verifydata = calloc(sizeof(finfo->group_id) +
                sizeof(receive_dest.sin_addr.s_addr) + sizeof(rand1) +
                sizeof(destlist[hostidx].rand2) +
                sizeof(destlist[hostidx].premaster) + PUBKEY_LEN + 4 +
                sizeof(groupmaster), 1);
    }
    if (verifydata == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    n_group_id = htonl(finfo->group_id);
    memcpy(verifydata, &n_group_id, sizeof(n_group_id));
    *verifylen += sizeof(n_group_id);
    memcpy(verifydata + *verifylen,
            unicast ? &blank : &receive_dest.sin_addr.s_addr,
            sizeof(receive_dest.sin_addr.s_addr));
    *verifylen += sizeof(receive_dest.sin_addr.s_addr);
    memcpy(verifydata + *verifylen, rand1, sizeof(rand1));
    *verifylen += sizeof(rand1);
    memcpy(verifydata + *verifylen, destlist[hostidx].rand2,
            sizeof(destlist[hostidx].rand2));
    *verifylen += sizeof(destlist[hostidx].rand2);
    memcpy(verifydata + *verifylen, destlist[hostidx].premaster,
            sizeof(destlist[hostidx].premaster));
    *verifylen += sizeof(destlist[hostidx].premaster);

    if (destlist[hostidx].status != DEST_MUTE) {
        if (destlist[hostidx].pubkey) {
            if (!export_RSA_key(destlist[hostidx].pubkey,
                                &exponent, modulus, &modlen)) {
                free(verifydata);
                return NULL;
            }
            exponent = htonl(exponent);
            memcpy(verifydata + *verifylen, &exponent, sizeof(exponent));
            *verifylen += sizeof(exponent);
            memcpy(verifydata + *verifylen, modulus, modlen);
            *verifylen += modlen;
        }
        memcpy(verifydata + *verifylen, groupmaster, sizeof(groupmaster));
        *verifylen += sizeof(groupmaster);
    }

    return verifydata;
}

/**
 * Verifies the data in a CLIENT_KEY message signed by the client's public key
 */
int verify_client_key(struct finfo_t *finfo, int hostidx)
{
    uint8_t *verifydata;
    int verifylen;

    // build_verify_data should never fail in this case
    verifydata = build_verify_data(finfo, hostidx, &verifylen);

    if (!verify_RSA_sig(destlist[hostidx].pubkey, hashtype, verifydata,
            verifylen, destlist[hostidx].verifydata,
            destlist[hostidx].verifylen)) {
        log(0, 0, "Rejecting CLIENT_KEY from %s: verify data mismatch",
                   destlist[hostidx].name);
        free(verifydata);
        return 0;
    }

    destlist[hostidx].status = DEST_REGISTERED;
    free(verifydata);
    return 1;
}

/**
 * For a given client, calculate the master key and do key expansion
 * to determine the symmetric cypher key and IV salt, and hash key
 */
void calculate_client_keys(int hostidx)
{
    unsigned char *seed, *prf_buf;
    int explen, len, seedlen;

    explen = keylen + ivlen + hmaclen;
    seedlen = sizeof(rand1) * 2;
    seed = calloc(seedlen, 1);
    prf_buf = calloc(MASTER_LEN + explen + hmaclen, 1);
    if ((seed == NULL) || (prf_buf == NULL)) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    memcpy(seed, rand1, sizeof(rand1));
    memcpy(seed + sizeof(rand1), destlist[hostidx].rand2,
            sizeof(destlist[hostidx].rand2));
    PRF(hashtype, MASTER_LEN, destlist[hostidx].premaster,
            sizeof(destlist[hostidx].premaster),
            "master secret", seed, seedlen, prf_buf, &len);
    memcpy(destlist[hostidx].master,prf_buf,
            sizeof(destlist[hostidx].master));

    PRF(hashtype, explen, destlist[hostidx].master, 
            sizeof(destlist[hostidx].master), "key expansion",
            seed, seedlen, prf_buf, &len);
    memcpy(destlist[hostidx].hmackey, prf_buf, hmaclen);
    memcpy(destlist[hostidx].key, prf_buf + hmaclen, keylen);
    memcpy(destlist[hostidx].salt, prf_buf + hmaclen + keylen, ivlen);

    free(seed);
    free(prf_buf);
}

/**
 * Processes encryption key information received in a REGISTER message
 */
int handle_register_keys(const struct register_h *reg,
                         const unsigned char *enckey, struct finfo_t *finfo,
                         int hostidx)
{
    unsigned char *decrypted;
    int len;

    decrypted = calloc(PUBKEY_LEN, 1);
    if (decrypted == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    memcpy(destlist[hostidx].rand2, reg->rand2,
           sizeof(destlist[hostidx].rand2));
    if (!RSA_decrypt(privkey, enckey, ntohs(reg->premaster_len),
                     decrypted, &len)) {
        log(0, 0, "Rejecting REGISTER from %s: failed to decrypt "
                  "premaster secret", destlist[hostidx].name);
        free(decrypted);
        return 0;
    }
    if (len > ntohs(reg->premaster_len)) {
        log(0, 0, "Rejecting REGISTER from %s: decrypted "
                  "premaster secret too long", destlist[hostidx].name);
        free(decrypted);
        return 0;
    }
    memcpy(destlist[hostidx].premaster, decrypted, len);
    calculate_client_keys(hostidx);
    free(decrypted);

    if (destlist[hostidx].pubkey) {
        if (!verify_client_key(finfo, hostidx)) {
            return 0;
        }
    }

    return 1;
}

/**
 * Process an expected REGISTER with open group membership
 */
void handle_open_register(const unsigned char *message, int meslen,
                          struct finfo_t *finfo, const struct sockaddr_in *sin,
                          const struct in_addr *hostaddr, int regconf)
{
    struct register_h *reg;
    uint32_t *addrlist;
    unsigned char *enckey;
    int clientcnt, hostidx;

    reg = (struct register_h *)message;
    enckey = (unsigned char *)reg + sizeof(struct register_h);
    addrlist = (uint32_t *)(enckey + ntohs(reg->premaster_len));

    if (destcount == MAXDEST) {
        log(0, 0, "Rejecting REGISTER from %s: max destinations exceeded",
                   inet_ntoa(*hostaddr));
        send_abort(finfo, "Max destinations exceeded", sin, hostaddr, 0);
        return;
    }
    clientcnt = ntohs(reg->destcount);
    if (meslen != sizeof(struct register_h) + ntohs(reg->premaster_len) +
                  (clientcnt * sizeof(uint32_t))) {
        log(0, 0, "Rejecting REGISTER from %s: invalid message size",
                   inet_ntoa(*hostaddr));
        send_abort(finfo, "Invalid message size", sin, hostaddr, 0);
        return;
    }

    hostidx = add_dest_by_addr(hostaddr->s_addr, finfo, DEST_MUTE, -1,
                               (clientcnt > 0) ? 0 : -1);
    if (keytype != KEY_NONE) {
        if (!handle_register_keys(reg, enckey, finfo, hostidx)) {
            return;
        }
    }
    if (regconf) {
        finfo->deststate[hostidx].conf_sent = 0;
    }
    destlist[hostidx].registered = 1;
    destlist[hostidx].status =
            regconf ? DEST_ACTIVE : (client_auth ? DEST_MUTE : DEST_REGISTERED);
    log(0, 0, "Received REGISTER from %s %s",
              (clientcnt > 0) ? "proxy" : "client", destlist[hostidx].name);
    if (clientcnt > 0) {
        add_proxy_dests(finfo, addrlist, sin, clientcnt, hostidx, 1);
    }
}

/**
 * Process an expected REGISTER with closed group membership,
 * or with open group membership if CLIENT_KEY was received first.
 */
void handle_register(const unsigned char *message, int meslen,
                     struct finfo_t *finfo, const struct sockaddr_in *sin,
                     const struct in_addr *hostaddr, int hostidx,
                     int regconf, int open)
{
    struct register_h *reg;
    uint32_t *addrlist;
    unsigned char *enckey;
    int clientcnt, dupmsg, isproxy;

    reg = (struct register_h *)message;
    enckey = (unsigned char *)reg + sizeof(struct register_h);
    addrlist = (uint32_t *)(enckey + ntohs(reg->premaster_len));

    clientcnt = ntohs(reg->destcount);
    if ((clientcnt > 0) && (destlist[hostidx].clientcnt == -1) && (!open)) {
        log(0, 0, "Rejecting REGISTER from %s: specified multiple clients "
                  "but not a proxy", destlist[hostidx].name);
        send_abort(finfo, "specified multiple clients but not a proxy", sin,
                   hostaddr, 0);
        destlist[hostidx].status = DEST_ABORT;
        return;
    }    
    if (meslen != sizeof(struct register_h) + ntohs(reg->premaster_len) +
                  (clientcnt * sizeof(uint32_t))) {
        log(0, 0, "Rejecting REGISTER from %s: invalid message size",
                   destlist[hostidx].name);
        send_abort(finfo, "Invalid message size", sin, hostaddr, 0);
        return;
    }
    if (finfo->file_id != 0) {
        log(0, 0, "Received REGISTER+ from %s", destlist[hostidx].name);
        return;
    }

    if (destlist[hostidx].status == DEST_MUTE) {
        if (keytype != KEY_NONE) {
            if (!handle_register_keys(reg, enckey, finfo, hostidx)) {
                return;
            }
        }
        destlist[hostidx].status = regconf ? DEST_ACTIVE : 
                ((client_auth && (!destlist[hostidx].pubkey))
                    ? DEST_MUTE : DEST_REGISTERED);
    }
    dupmsg = (destlist[hostidx].registered);
    destlist[hostidx].registered = 1;
    if (regconf) {
        finfo->deststate[hostidx].conf_sent = 0;
    }
    isproxy = (destlist[hostidx].clientcnt != -1);
    log(0, 0, "Received REGISTER%s from %s %s", (dupmsg && !isproxy) ? "+" : "",
              (isproxy) ? "proxy" : "client", destlist[hostidx].name);
    if (clientcnt > 0) {
        add_proxy_dests(finfo, addrlist, sin, clientcnt, hostidx, open);
    }
}

/**
 * Verifies a client's public key fingerprint
 */
int verify_client_fingerprint(const struct client_key_h *clientkey,
                              const unsigned char *keymod,
                              const unsigned char *verify, int hostidx)
{
    unsigned char *verifydata, fingerprint[HMAC_LEN];
    unsigned int verifylen, fplen;

    if (destlist[hostidx].verified) {
        return 1;
    }

    if (!import_RSA_key(&destlist[hostidx].pubkey, ntohl(clientkey->keyexp),
                        keymod, ntohs(clientkey->keylen))) {
        log(0, 0, "Rejecting CLIENT_KEY from %s: failed to import key",
                   destlist[hostidx].name);
        return 0;
    }
    destlist[hostidx].pubkeylen = RSA_keylen(destlist[hostidx].pubkey);
    if (destlist[hostidx].has_fingerprint) {
        verifylen = 0;
        verifydata = calloc(sizeof(clientkey->keyexp) +
                            ntohs(clientkey->keylen), 1);
        if (verifydata == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        memcpy(verifydata, &clientkey->keyexp, sizeof(clientkey->keyexp));
        verifylen += sizeof(clientkey->keyexp);
        memcpy(verifydata + verifylen, keymod,
               ntohs(clientkey->keylen));
        verifylen += ntohs(clientkey->keylen);
        hash(HASH_SHA1, verifydata, verifylen, fingerprint, &fplen);
        if (memcmp(destlist[hostidx].keyfingerprint, fingerprint, fplen)) {
            log(0, 0, "Rejecting CLIENT_KEY from %s: key fingerprint mismatch",
                       destlist[hostidx].name);
            free(verifydata);
            free_RSA_key(destlist[hostidx].pubkey);
            destlist[hostidx].pubkey = (RSA_key_t)NULL;
            destlist[hostidx].pubkeylen = 0;
            return 0;
        }
        free(verifydata);
    }

    destlist[hostidx].verified = 1;
    return 1;
}

/**
 * Process an expected CLIENT_KEY with open group membership
 */
void handle_open_clientkey(const unsigned char *message, int meslen,
                           struct finfo_t *finfo, const struct sockaddr_in *sin,
                           const struct in_addr *hostaddr)
{
    struct client_key_h *clientkey;
    unsigned char *keymod, *verify;
    int hostidx;

    clientkey = (struct client_key_h *)message;
    keymod = (unsigned char *)clientkey + sizeof(struct client_key_h);
    verify = keymod + ntohs(clientkey->keylen);

    if (destcount == MAXDEST) {
        log(0, 0, "Rejecting CLIENT_KEY from %s: max destinations exceeded",
                   inet_ntoa(*hostaddr));
        send_abort(finfo, "Max destinations exceeded", sin, hostaddr, 0);
        return;
    }
    if (meslen != sizeof(struct client_key_h) + ntohs(clientkey->keylen) +
                  ntohs(clientkey->verifylen)) {
        log(0, 0, "Rejecting CLIENT_KEY from %s: invalid message size",
                   inet_ntoa(*hostaddr));
        send_abort(finfo, "Invalid message size", sin, hostaddr, 0);
        return;
    }

    hostidx = add_dest_by_addr(hostaddr->s_addr, finfo, DEST_MUTE, -1, -1);
    if (!verify_client_fingerprint(clientkey, keymod, verify, hostidx)) {
        return;
    }
    memcpy(destlist[hostidx].verifydata, verify, ntohs(clientkey->verifylen));
    destlist[hostidx].verifylen = ntohs(clientkey->verifylen);
    log(0, 0, "Received CLIENT_KEY from %s", destlist[hostidx].name);
}

/**
 * Process an expected CLIENT_KEY with closed group membership,
 * or with open group membersip if REGISTER was received first.
 */
void handle_clientkey(const unsigned char *message, int meslen,
                      struct finfo_t *finfo, const struct sockaddr_in *sin,
                      const struct in_addr *hostaddr, int hostidx)
{
    struct client_key_h *clientkey;
    unsigned char *keymod, *verify;

    clientkey = (struct client_key_h *)message;
    keymod = (unsigned char *)clientkey + sizeof(struct client_key_h);
    verify = keymod + ntohs(clientkey->keylen);

    if (meslen != sizeof(struct client_key_h) + ntohs(clientkey->keylen) +
                  ntohs(clientkey->verifylen)) {
        log(0, 0, "Rejecting CLIENT_KEY from %s: invalid message size",
                   destlist[hostidx].name);
        send_abort(finfo, "Invalid message size", sin, hostaddr, 0);
        return;
    }
    if (finfo->file_id != 0) {
        log(0, 0, "Received CLIENT_KEY+ from %s", destlist[hostidx].name);
        return;
    }

    if (!verify_client_fingerprint(clientkey, keymod, verify, hostidx)) {
        return;
    }
    memcpy(destlist[hostidx].verifydata, verify, ntohs(clientkey->verifylen));
    destlist[hostidx].verifylen = ntohs(clientkey->verifylen);
    if (destlist[hostidx].registered) {
        if (!verify_client_key(finfo, hostidx)) {
            return;
        }
    }
    log(0, 0, "Received CLIENT_KEY from %s", destlist[hostidx].name);
}

/**
 * Process an expected INFO_ACK.  If received in response to a KEYINFO
 * message, validate the verify_data field.
 */
void handle_info_ack(const unsigned char *message, int meslen,
                     struct finfo_t *finfo, const struct sockaddr_in *sin,
                     const struct in_addr *hostaddr, int hostidx, int announce)
{
    struct infoack_h *infoack;
    uint32_t *addr;
    unsigned char *verifydata, *verify_hash, *verify_test;
    int verifylen, len, clientcnt, dupmsg, isproxy, clientidx, i;
    unsigned int hashlen;

    infoack = (struct infoack_h *)message;
    addr = (uint32_t *)((char *)infoack + sizeof(struct infoack_h));
    clientcnt = ntohs(infoack->destcount);

    if (meslen != sizeof(struct infoack_h) + 
                  (clientcnt * sizeof(uint32_t))) {
        log(0, 0, "Rejecting INFO_ACK from %s: invalid message size",
                   destlist[hostidx].name);
        send_abort(finfo, "Invalid message size", sin, hostaddr, 0);
        return;
    }
    if ((clientcnt > 0) && (destlist[hostidx].clientcnt == -1)) {
        log(0, 0, "Rejecting INFO_ACK from %s: specified multiple clients "
                  "but not a proxy", destlist[hostidx].name);
        send_abort(finfo, "specified multiple clients but not a proxy", sin,
                   hostaddr, 0);
        return;
    }    

    // If in response to a KEYINFO, check the verify data
    if ((keytype != KEY_NONE) && announce) {
        if (!(verifydata = build_verify_data(finfo, hostidx, &verifylen))) {
            log(0, 0, "Rejecting INFO_ACK from %s: error exporting "
                      "client public key", destlist[hostidx].name);
            return;
        }
        verify_hash = calloc(hmaclen, 1);
        verify_test = calloc(VERIFY_LEN + hmaclen, 1);
        if ((verify_hash == NULL) || (verify_test == NULL)){
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        hash(hashtype, verifydata, verifylen, verify_hash, &hashlen);
        PRF(hashtype, VERIFY_LEN, groupmaster, sizeof(groupmaster),
                "client finished", verify_hash, hashlen, verify_test, &len);
        if (memcmp(infoack->verify_data, verify_test, VERIFY_LEN)) {
            log(0, 0, "Rejecting INFO_ACK from %s: verify data mismatch",
                      destlist[hostidx].name);
            free(verifydata);
            free(verify_hash);
            free(verify_test);
            return;
        }

        free(verifydata);
        free(verify_hash);
        free(verify_test);
    } else if (!announce) {
        if (ntohs(infoack->file_id) != finfo->file_id) {
            log(0, 0, "Rejecting INFO_ACK from %s: invalid file ID %04X, "
                      "expected %04X ", destlist[hostidx].name,
                      ntohs(infoack->file_id), finfo->file_id );
            return;
        }
        finfo->partial = finfo->partial &&
                ((infoack->flags & FLAG_PARTIAL) != 0);
    }

    isproxy = (destlist[hostidx].clientcnt != -1);
    dupmsg = (destlist[hostidx].status == DEST_ACTIVE);
    log(0, 0, "Received INFO_ACK%s from %s %s", (dupmsg && !isproxy) ? "+" : "",
              (isproxy) ? "proxy" : "client", destlist[hostidx].name);
    destlist[hostidx].status = DEST_ACTIVE;
    clientcnt = ntohs(infoack->destcount);
    if (clientcnt > 0) {
        addr = (uint32_t *)((char *)infoack + sizeof(struct infoack_h));
        for (i = 0; i < clientcnt; i++) {
            dupmsg = 0;
            clientidx = find_client(addr[i]);
            if (clientidx == -1) {
                log(0, 0, "Host %s not in host list",
                          inet_ntoa(to_addr(addr[i])));
                continue;
            } else {
                dupmsg = (destlist[clientidx].status == DEST_ACTIVE);
                destlist[clientidx].status = DEST_ACTIVE;
            }
            log(0, 0, "  For client%s %s", dupmsg ? "+" : "",
                       destlist[clientidx].name);
        }
    }

    return;
}

