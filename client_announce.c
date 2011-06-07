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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#ifdef WINDOWS

#include <ws2tcpip.h>
#include <io.h>
#include <direct.h>

#include "win_func.h"

#else  // if WINDOWS

#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#endif

#include "client.h"
#include "client_common.h"
#include "client_announce.h"
#include "client_transfer.h"

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
 * Returns the verify_data string used in certain messages.  This value
 * is then run through the PRF with the result going into the message.
 */
uint8_t *build_verify_data(int listidx, int *verifylen)
{
    uint8_t *verifydata;
    uint32_t exponent;
    uint16_t modlen;
    uint8_t modulus[PUBKEY_LEN];
    uint32_t group_id;

    *verifylen = 0;
    if (group_list[listidx].phase == PHASE_REGISTERED) {
        verifydata = calloc(sizeof(group_list[listidx].group_id) +
                sizeof(group_list[listidx].multi.s_addr) +
                sizeof(group_list[listidx].rand1) +
                sizeof(group_list[listidx].rand2) +
                sizeof(group_list[listidx].premaster), 1);
    } else {
        verifydata = calloc(sizeof(group_list[listidx].group_id) +
                sizeof(group_list[listidx].multi.s_addr) +
                sizeof(group_list[listidx].rand1) +
                sizeof(group_list[listidx].rand2) +
                sizeof(group_list[listidx].premaster) +
                PUBKEY_LEN + 4 + sizeof(group_list[listidx].groupmaster), 1);
    }
    if (verifydata == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    group_id = htonl(group_list[listidx].group_id);
    memcpy(verifydata, &group_id, sizeof(group_id));
    *verifylen += sizeof(group_id);
    memcpy(verifydata + *verifylen,
            &group_list[listidx].multi.s_addr,
            sizeof(group_list[listidx].multi.s_addr));
    *verifylen += sizeof(group_list[listidx].multi.s_addr);
    memcpy(verifydata + *verifylen, group_list[listidx].rand1,
            sizeof(group_list[listidx].rand1));
    *verifylen += sizeof(group_list[listidx].rand1);
    memcpy(verifydata + *verifylen, group_list[listidx].rand2,
            sizeof(group_list[listidx].rand2));
    *verifylen += sizeof(group_list[listidx].rand2);
    memcpy(verifydata + *verifylen, group_list[listidx].premaster,
            sizeof(group_list[listidx].premaster));
    *verifylen += sizeof(group_list[listidx].premaster);

    if (group_list[listidx].phase != PHASE_REGISTERED) {
        if (group_list[listidx].client_auth) {
            if (!export_RSA_key(group_list[listidx].clientkey, &exponent,
                                modulus, &modlen)) {
                free(verifydata);
                return NULL;
            }
            exponent = htonl(exponent);
            memcpy(verifydata + *verifylen, &exponent, sizeof(exponent));
            *verifylen += sizeof(exponent);
            memcpy(verifydata + *verifylen, modulus, modlen);
            *verifylen += modlen;
        }
        memcpy(verifydata + *verifylen, group_list[listidx].groupmaster,
                sizeof(group_list[listidx].groupmaster));
        *verifylen += sizeof(group_list[listidx].groupmaster);
    }

    return verifydata;
}

/**
 * Sends a CLIENT_KEY message if the server requested it.
 * Always sent right after a REGISTER.
 */
void send_client_key(int listidx)
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
    verify = keymod + group_list[listidx].client_keylen;

    set_uftp_header(header, CLIENT_KEY, listidx);

    client_key->func = CLIENT_KEY;
    if (!export_RSA_key(group_list[listidx].clientkey, &exponent,
                        modulus, &modlen)) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Error exporting public key");
        send_abort(listidx, "Error exporting public key");
        free(buf);
        return;
    }
    client_key->keyexp = htonl(exponent);
    memcpy(keymod, modulus, group_list[listidx].client_keylen);
    client_key->keylen = htons(modlen);

    verifydata = build_verify_data(listidx, &verifylen);
    if (!verifydata) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Error getting verify data");
        send_abort(listidx, "Error getting verify data");
        free(verifydata);
        free(buf);
        return;
    }
    if (!create_RSA_sig(group_list[listidx].clientkey,
                        group_list[listidx].hashtype, verifydata,
                        verifylen, verify, &siglen) || 
                siglen > group_list[listidx].client_keylen) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Error signing verify data");
        send_abort(listidx, "Error signing verify data");
        free(verifydata);
        free(buf);
        return;
    }
    free(verifydata);
    client_key->verifylen = htons(siglen);
    header->blsize = htons(sizeof(struct client_key_h) + modlen + siglen);

    meslen = sizeof(struct uftp_h) + ntohs(header->blsize);
    if (nb_sendto(listener, buf, meslen, 0,
               (struct sockaddr *)&(group_list[listidx].replyaddr),
               sizeof(group_list[listidx].replyaddr)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id, group_list[listidx].file_id,
                  "Error sending CLIENT_KEY");
    } else {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "CLIENT_KEY sent");
    }
    free(buf);
}

/**
 * Sends a REGISTER message in response to an ANNOUNCE or on timeout when
 * waiting for a KEYINFO or REG_CONF.  If the register timeout expired, abort.
 */
void send_register(int listidx)
{
    struct uftp_h *header;
    struct register_h *reg;
    struct uftp2_h *v2_header;
    unsigned char *buf, *premaster;
    struct timeval tv;
    int len, meslen;
    RSA_key_t key;

    gettimeofday(&tv, NULL);
    if (diff_usec(group_list[listidx].expire_time, tv) <= 0) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Registration unconfirmed by server");
        send_abort(listidx, "Registration unconfirmed");
        return;
    }

    buf = calloc(group_list[listidx].mtu, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    if (group_list[listidx].version == UFTP_V2_VER) {
        v2_header = (struct uftp2_h *)buf;
        v2_header->uftp_id = htonl(V2_UFTP_ID);
        v2_header->func = htonl(V2_REGISTER);
        v2_header->tx_id = htonl(group_list[listidx].group_id);
        v2_header->blsize = 0;
        meslen = sizeof(struct uftp2_h);
    } else {
        header = (struct uftp_h *)buf;
        reg = (struct register_h *)(buf + sizeof(struct uftp_h));
        premaster = (unsigned char *)reg + sizeof(struct register_h);
        set_uftp_header(header, REGISTER, listidx);
        reg->func = REGISTER;
        reg->destcount = 0;
        if (group_list[listidx].keytype != KEY_NONE) {
            memcpy(reg->rand2, group_list[listidx].rand2, RAND_LEN);
            if (has_proxy) {
                key = proxy_key;
            } else {
                key = group_list[listidx].serverkey;
            }
            if (!RSA_encrypt(key, group_list[listidx].premaster, MASTER_LEN,
                             premaster, &len)) {
                log(group_list[listidx].group_id, group_list[listidx].file_id,
                        "Error encrypting premaster secret");
                send_abort(listidx, "Error encrypting premaster secret");
                free(buf);
                return;
            }
            reg->premaster_len = htons(len); 
        } else {
            len = 0;
        }
        header->blsize = htons(sizeof(struct register_h) + len);
        meslen = sizeof(struct uftp_h) + ntohs(header->blsize);
    }

    if (nb_sendto(listener, buf, meslen, 0,
               (struct sockaddr *)&(group_list[listidx].replyaddr),
               sizeof(group_list[listidx].replyaddr)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id, group_list[listidx].file_id,
                  "Error sending REGISTER");
    } else {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "REGISTER sent");
    }

    set_timeout(listidx);
    if (group_list[listidx].client_auth) {
        send_client_key(listidx);
    }
    free(buf);
}

/**
 * Sends an INFO_ACK in response to a FILEINFO or KEYINFO
 */
void send_info_ack(int listidx, int restart)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct infoack_h *info_ack;
    unsigned char *verifydata, *verify_hash, *verify_val;
    unsigned int payloadlen, hashlen;
    int verifylen, len;

    buf = calloc(group_list[listidx].mtu, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)buf;
    info_ack = (struct infoack_h *)(buf + sizeof(struct uftp_h));

    payloadlen = sizeof(struct infoack_h);
    set_uftp_header(header, INFO_ACK, listidx);
    if (restart) {
        info_ack->flags |= FLAG_PARTIAL;
    }
    info_ack->func = INFO_ACK;
    info_ack->destcount = 0;
    info_ack->file_id = htons(group_list[listidx].file_id);
    if (group_list[listidx].keytype != KEY_NONE) {
        // If we're responding to a KEYINFO, populate verify_data
        if (group_list[listidx].file_id == 0) {
            verifydata = build_verify_data(listidx, &verifylen);
            if (!verifydata) {
                log(group_list[listidx].group_id, group_list[listidx].file_id,
                        "Error getting verify data");
                send_abort(listidx, "Error getting verify data");
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
                group_list[listidx].clientkey,
                group_list[listidx].client_keylen)) {
            log(0, 0, "Error encrypting INFO_ACK");
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
               (struct sockaddr *)&(group_list[listidx].replyaddr),
               sizeof(group_list[listidx].replyaddr)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id, group_list[listidx].file_id,
                  "Error sending INFO_ACK");
    } else {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "INFO_ACK sent");
    }
    free(encrypted);
    free(buf);
}

/**
 * Verifies a server's public key fingerprint
 */
int verify_server_fingerprint(const unsigned char *keymod, uint32_t keyexp,
                              int keylen, int listidx)
{
    unsigned char *verifydata, fingerprint[HMAC_LEN];
    unsigned int verifylen, fplen;
    int found, keyidx;

    if (server_count == 0) {
        return 1;
    }

    for (keyidx = 0, found = 0; (keyidx < server_count) && !found; keyidx++) {
        if (server_keys[keyidx].addr.s_addr ==
                group_list[listidx].replyaddr.sin_addr.s_addr) {
            keyidx--;
            found = 1;
        }
    }
    if (!found) {
        return 0;
    }
    if (!server_keys[keyidx].has_fingerprint) {
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
    if (memcmp(server_keys[keyidx].fingerprint, fingerprint, fplen)) {
        free(verifydata);
        return 0;
    } else {
        free(verifydata);
        return 1;
    }
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
        send_abort(listidx, "Failed to get random bytes for rand2");
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
        send_abort(listidx, "Failed to get random bytes for premaster");
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
int handle_announce_encryption(int listidx, const struct announce_h *announce,
                               const unsigned char *keymod)
{
    int i;

    // Sanity check the selected encryption parameters
    if ((group_list[listidx].keytype != KEY_DES) &&
            (group_list[listidx].keytype != KEY_DES_EDE3) &&
            (group_list[listidx].keytype != KEY_AES128) &&
            (group_list[listidx].keytype != KEY_AES256)) {
        log(group_list[listidx].group_id, 0, "Invalid keytype specified");
        send_abort(listidx, "Invalid keytype specified");
        return 0;
    }
    if (!cipher_supported(group_list[listidx].keytype)) {
        log(group_list[listidx].group_id, 0, "Keytype not supported here");
        send_abort(listidx, "Keytype not supported here");
        return 0;
    }
    if ((group_list[listidx].hashtype != HASH_SHA1) &&
            (group_list[listidx].hashtype != HASH_SHA256)) {
        log(group_list[listidx].group_id, 0, "Invalid hashtype specified");
        send_abort(listidx, "Invalid hashtype specified");
        return 0;
    }
    if (!hash_supported(group_list[listidx].hashtype)) {
        log(group_list[listidx].group_id, 0, "Hashtype not supported here");
        send_abort(listidx, "Hashtype not supported here");
        return 0;
    }
    if ((group_list[listidx].sigtype != SIG_HMAC) &&
            (group_list[listidx].sigtype != SIG_RSA)) {
        log(group_list[listidx].group_id, 0, "Invalid sigtype specified");
        send_abort(listidx, "Invalid sigtype specified");
        return 0;
    } 

    // Load server key and select a matching client key
    if (!import_RSA_key(&group_list[listidx].serverkey, ntohl(announce->keyexp),
                        keymod, ntohs(announce->keylen))) {
        log(group_list[listidx].group_id, 0,
                "Failed to load server public key");
        send_abort(listidx, "Failed to load server public key");
        return 0;
    }
    if (!verify_server_fingerprint(keymod, announce->keyexp,
                                   ntohs(announce->keylen), listidx)) {
        log(group_list[listidx].group_id, 0,
                "Failed to verify server key fingerprint");
        send_abort(listidx, "Failed to verify server key fingerprint");
        return 0;
    }
    group_list[listidx].server_keylen=RSA_keylen(group_list[listidx].serverkey);
    for (i = 0; i < key_count; i++) {
        if (RSA_keylen(privkey[i]) == group_list[listidx].server_keylen) {
            group_list[listidx].clientkey = privkey[i];
            group_list[listidx].client_keylen = RSA_keylen(privkey[i]);
            break;
        }
    }
    if (!group_list[listidx].clientkey) {
        log(group_list[listidx].group_id, 0,
                "No client key with keysize == server keysize of %d",
                group_list[listidx].server_keylen * 8);
        send_abort(listidx, "No client key with keysize == server keysize");
        return 0;
    }
    if (has_proxy) {
        if (proxy_key == (RSA_key_t)NULL) {
            log(group_list[listidx].group_id, 0,
                    "Response proxy set but haven't gotten key yet");
            send_abort(listidx,"Response proxy set but haven't gotten key yet");
            return 0;
        }
        if (RSA_keylen(proxy_key) != group_list[listidx].server_keylen) {
            log(group_list[listidx].group_id, 0,
                    "Response proxy key size doesn't match server key size");
            send_abort(listidx, "Response proxy key size != server key size");
            return 0;
        }
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
 * Reads the file info portion of a 2.X ANNOUNCE.
 */
void read_v2_fileinfo(int listidx, const unsigned char *message)
{
    struct uftp2_h *v2_header;
    struct fileinfo2 *v2_fileinfo;

    v2_header = (struct uftp2_h *)message;
    v2_fileinfo = (struct fileinfo2 *)(message + sizeof(struct uftp2_h));

    // Load fileinfo params into list
    group_list[listidx].fileinfo.ftype = FTYPE_REG;
    strncpy(group_list[listidx].fileinfo.name, v2_fileinfo->name, 
            sizeof(group_list[listidx].fileinfo.name)-1);
    group_list[listidx].fileinfo.blocks = ntohl(v2_fileinfo->block_total);
    group_list[listidx].fileinfo.sections = ntohl(v2_fileinfo->section_total);
    if (ntohl(v2_fileinfo->fsize) == 0 ) {
        group_list[listidx].fileinfo.size = 
                (f_offset_t)ntohl(v2_fileinfo->hilargefsize) << 32;
        group_list[listidx].fileinfo.size |= ntohl(v2_fileinfo->lolargefsize);
    } else {
        group_list[listidx].fileinfo.size = ntohl(v2_fileinfo->fsize);
    }
}

/**
 * Read in the contents of a 2.X ANNOUNCE.
 */
void read_v2_announce(int listidx, int addridx, const unsigned char *message,
                      struct sockaddr_in src)
{
    struct uftp2_h *v2_header;
    struct fileinfo2 *v2_fileinfo;

    v2_header = (struct uftp2_h *)message;
    v2_fileinfo = (struct fileinfo2 *)(message + sizeof(struct uftp2_h));

    group_list[listidx].group_id = ntohl(v2_header->tx_id);
    group_list[listidx].file_id = 0;
    group_list[listidx].srcaddr = src.sin_addr;
    if (addridx != -1) {
        group_list[listidx].destaddr = m_interface[addridx].addr;
    } else {
        // unicast mode with no match -- accept anyway
        group_list[listidx].destaddr.s_addr = v2_fileinfo->addr_list[0];
    }
    group_list[listidx].replyaddr = src;
    group_list[listidx].register_int = ntohs(v2_fileinfo->rxlatency1);
    group_list[listidx].announce_time =
            group_list[listidx].register_int * 5 / 1000;
    group_list[listidx].done_int = ntohs(v2_fileinfo->rxlatency2);
    group_list[listidx].status_time =
            group_list[listidx].done_int * 5 / 1000;
    group_list[listidx].mtu = V2_PACKETSIZE;
    group_list[listidx].payloadsize = V2_PACKETSIZE;
    group_list[listidx].encpayloadsize = V2_PACKETSIZE;
    group_list[listidx].blocksize = V2_BLOCKSIZE;
    group_list[listidx].client_auth = 0;
    group_list[listidx].hashtype = HASH_NONE;
    group_list[listidx].keytype = KEY_NONE;
    group_list[listidx].multi.s_addr = v2_fileinfo->mcast;
    group_list[listidx].version = UFTP_V2_VER;
    group_list[listidx].phase = PHASE_REGISTERED;
    gettimeofday(&group_list[listidx].expire_time, NULL);
    group_list[listidx].expire_time.tv_sec += group_list[listidx].announce_time;
    group_list[listidx].fileinfo.fd = -1;
}

/**
 * Read in the contents of an ANNOUNCE.
 */
void read_announce(int listidx, int addridx, const unsigned char *buf,
                   struct sockaddr_in src)
{
    struct uftp_h *header;
    struct announce_h *announce;

    header = (struct uftp_h *)buf;
    announce = (struct announce_h *)(buf + sizeof(struct uftp_h));

    group_list[listidx].group_id = ntohl(header->group_id);
    if (header->srcaddr != 0) {
        group_list[listidx].srcaddr.s_addr = header->srcaddr;
    } else {
        group_list[listidx].srcaddr = src.sin_addr;
    }
    if (announce->destcount == 0) {
        // open group, set destaddr to 0 to make server use IP src addr
        group_list[listidx].destaddr.s_addr = 0;
    } else if (addridx != -1) {
        group_list[listidx].destaddr = m_interface[addridx].addr;
    } else {
        // unicast mode with no match -- accept anyway
        unsigned char *keymod;
        uint32_t *addrlist;
        keymod = (unsigned char *)announce + sizeof(struct announce_h);
        addrlist = (uint32_t *)(keymod + ntohs(announce->keylen));
        group_list[listidx].destaddr.s_addr = addrlist[0];
    }
    if (has_proxy) {
        group_list[listidx].replyaddr.sin_family = AF_INET;
        group_list[listidx].replyaddr.sin_addr = proxy_info.addr;
        group_list[listidx].replyaddr.sin_port = htons(port);
    } else {
        group_list[listidx].replyaddr = src;
    }
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
    group_list[listidx].client_auth = announce->client_auth;
    group_list[listidx].restart = ((announce->flags & FLAG_RESTART) != 0);
    group_list[listidx].hashtype = announce->hashtype;
    group_list[listidx].keytype = announce->keytype;
    group_list[listidx].sigtype = announce->sigtype;
    group_list[listidx].multi.s_addr = announce->privatemcast;
    group_list[listidx].version = header->uftp_id;
    group_list[listidx].phase = PHASE_REGISTERED;
    gettimeofday(&group_list[listidx].expire_time, NULL);
    group_list[listidx].expire_time.tv_sec += group_list[listidx].announce_time;
    group_list[listidx].fileinfo.fd = -1;
}

/**
 * Processes a new incoming ANNOUNCE
 */
void handle_announce(struct sockaddr_in src, uint8_t version,
                     const unsigned char *buf)
{
    struct uftp_h *header;
    struct announce_h *announce;
    unsigned char *keymod;
    uint32_t *addrlist;
    struct uftp2_h *v2_header;
    struct fileinfo2 *v2_fileinfo;
    uint32_t group_id;
    int open, addrlen, addridx, listidx, unicast, i;
    struct hostent *hp;

    header = (struct uftp_h *)buf;
    announce = (struct announce_h *)(buf + sizeof(struct uftp_h));
    v2_header = (struct uftp2_h *)buf;
    v2_fileinfo = (struct fileinfo2 *)(buf + sizeof(struct uftp2_h));

    // A little setup to make checking the address list common between versions
    if (version == UFTP_V2_VER) {
        addrlen = V2_MAXDEST;
        open = (ntohl(v2_fileinfo->open) != 0);
        addrlist = v2_fileinfo->addr_list;
        group_id = ntohl(v2_header->tx_id);
        unicast = (v2_fileinfo->mcast == 0);
    } else {
        addrlen = ntohs(announce->destcount);
        open = (addrlen == 0);
        keymod = (unsigned char *)announce + sizeof(struct announce_h);
        addrlist = (uint32_t *)(keymod + ntohs(announce->keylen));
        group_id = ntohl(header->group_id);
        unicast = (announce->privatemcast == 0);
    }

    if (!open) {
        if (((addridx = interface_in_list(addrlist, addrlen)) == -1) &&
                (!unicast)) {
            log(group_id, 0, "Name not in host list");
            return;
        }
    } else {
        addridx = 0;
        // Look for the first non-loopback interface or the UID
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

    if ((listidx = find_open_slot()) == -1 ) {
        log(group_id, 0,
            "Error: maximum number of incoming files exceeded: %d\n", MAXLIST);
        return;
    }

    if (version == UFTP_V2_VER) {
        read_v2_announce(listidx, addridx, buf, src);
    } else {
        read_announce(listidx, addridx, buf, src);
    }

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

    if (group_list[listidx].keytype != KEY_NONE) {
        if (!handle_announce_encryption(listidx, announce, keymod)) {
            return;
        }
    } else if (encrypted_only) {
        log(group_list[listidx].group_id, 0,
                "No unencrypted transfers allowed");
        send_abort(listidx, "No unencrypted transfers allowed");
        return;
    }

    if (group_list[listidx].restart) {
        read_restart_file(listidx);
    }

    if (group_list[listidx].multi.s_addr != 0) {
        if (server_count) {
            if (!is_multicast(group_list[listidx].multi, 1)) {
                log(group_list[listidx].group_id, 0,
                        "Invalid source specific multicast address: %s",
                        inet_ntoa(group_list[listidx].multi));
                send_abort(listidx, "Invalid source specific "
                                    "multicast address");
                return;
            }
        } else {
            if (!is_multicast(group_list[listidx].multi, 0)) {
                log(group_list[listidx].group_id, 0,
                        "Invalid multicast address: %s",
                        inet_ntoa(group_list[listidx].multi));
                send_abort(listidx, "Invalid multicast address");
                return;
            }
        }
        if (server_count > 0) {
            if (!multicast_join(listener, group_list[listidx].group_id,
                    &group_list[listidx].multi, m_interface,
                    interface_count, server_keys, server_count)) {
                send_abort(listidx, "Error joining multicast group");
                return;
            }
            if (has_proxy) {
                if (!multicast_join(listener, group_list[listidx].group_id,
                        &group_list[listidx].multi, m_interface,
                        interface_count, &proxy_info, 1)) {
                    send_abort(listidx, "Error joining multicast group");
                    return;
                }
            }
        } else {
            if (!multicast_join(listener, group_list[listidx].group_id,
                    &group_list[listidx].multi, m_interface, interface_count,
                    NULL, 0)) {
                send_abort(listidx, "Error joining multicast group");
                return;
            }
        }
        group_list[listidx].multi_join = 1;
    }

    // A 2.X ANNOUNCE also contains file info, so process that as well
    if ((version == UFTP_V2_VER) && (!handle_fileinfo(listidx, buf, 0))) {
        return;
    }

    send_register(listidx);
}

/**
 * Processes an incoming REG_CONF message.
 * Expected in response to a REGISTER when encryption is disabled.
 * For 2.X, always expected in response to a REGISTER.
 */
void handle_regconf(int listidx, const unsigned char *message, int meslen)
{
    struct regconf_h *regconf;
    uint32_t *addrlist;
    struct uftp2_h *v2_header;
    struct statusinfo2 *v2_statusinfo;

    if (group_list[listidx].version == UFTP_V2_VER) {
        v2_header = (struct uftp2_h *)message;
        v2_statusinfo = (struct statusinfo2 *)(message + sizeof(struct uftp2_h));

        if (ntohl(v2_header->func) != V2_REG_CONF) {
            log(group_list[listidx].group_id, group_list[listidx].file_id,
                    "Expected REG_CONF, got %s", 
                    v2_func_name(ntohl(v2_header->func)));
            return;
        }
        if (addr_in_list(listidx, v2_statusinfo->addr_list, V2_MAXINFODEST)) {
            log(group_list[listidx].group_id, group_list[listidx].file_id,
                    "Registration confirmed");
            group_list[listidx].phase = PHASE_RECEIVING;
            set_timeout(listidx);
        }
    } else {
        regconf = (struct regconf_h *)message;
        addrlist = (uint32_t *)((char *)regconf + sizeof(struct regconf_h));

        if (meslen != sizeof(struct regconf_h) +
                (ntohs(regconf->destcount) * sizeof(uint32_t))) {
            log(group_list[listidx].group_id, group_list[listidx].file_id,
                    "Rejecting REG_CONF from server: invalid message size");
            return;
        }
        if (addr_in_list(listidx, addrlist, ntohs(regconf->destcount))) {
            log(group_list[listidx].group_id, group_list[listidx].file_id,
                    "Registration confirmed");
            group_list[listidx].phase = PHASE_MIDGROUP;
            set_timeout(listidx);
        }
    }
}

/**
 * Process an incoming KEYINFO message.
 * Expected in response to a REGISTER when encryption is enabled.
 */
void handle_keyinfo(int listidx, const unsigned char *buf)
{
    struct uftp_h *header;
    struct keyinfo_h *keyinfo;
    struct destkey *keylist;
    int i, j, keyidx, len;
    unsigned explen, declen;
    uint8_t decgroupmaster[MASTER_LEN], *prf_buf, *iv;

    header = (struct uftp_h *)buf;
    keyinfo = (struct keyinfo_h *)(buf + sizeof(struct uftp_h));
    keylist = (struct destkey *)((char *)keyinfo + sizeof(struct keyinfo_h));

    if (ntohs(header->blsize) != sizeof(struct keyinfo_h) +
            (keyinfo->destcount * sizeof(struct destkey))) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Rejecting KEYINFO from server: invalid message size");
        return;
    }

    // This duplicates addr_in_list, but here it's addressed in a struct array
    for (i = 0, keyidx = -1; (i < keyinfo->destcount) &&
                             (keyidx == -1); i++) {
        if (group_list[listidx].destaddr.s_addr == 0) {
            for (j = 0; j < interface_count; j++) {
                if (keylist[i].destaddr == m_interface[j].addr.s_addr) {
                   group_list[listidx].destaddr = m_interface[j].addr;
                    keyidx = i;
                    break;
                }
            }
        } else {
            if (group_list[listidx].destaddr.s_addr == keylist[i].destaddr) {
                keyidx = i;
                break;
            }
        }
    }

    if (keyidx != -1) {
        log(group_list[listidx].group_id, 0, "Received KEYINFO");
        if (group_list[listidx].phase == PHASE_MIDGROUP) {
            // We already got the KEYINFO, so no need to reprocess.
            // Just resend the INFO_ACK and reset the timeout
            send_info_ack(listidx, 0);
            set_timeout(listidx);
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
            log(group_list[listidx].group_id, group_list[listidx].file_id,
                    "Decrypt failed for group master");
            send_abort(listidx, "Decrypt failed for group master");
            free(iv);
            return;
        }
        free(iv);
        group_list[listidx].groupmaster[0] = group_list[listidx].version;
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
        group_list[listidx].phase = PHASE_MIDGROUP;
        send_info_ack(listidx, 0);
        set_timeout(listidx);
    }
}

/**
 * Read in the contents of a FILEINFO message
 * Returns 1 on success, 0 on error or ignore
 */
int read_fileinfo(int listidx, const unsigned char *message, int meslen)
{
    struct fileinfo_h *fileinfo;
    uint32_t *addrlist;
    char *p;

    fileinfo = (struct fileinfo_h *)message;
    addrlist = (uint32_t *)((char *)fileinfo + sizeof(struct fileinfo_h));

    if (meslen != (sizeof(struct fileinfo_h) + 
                   ntohs(fileinfo->destcount) * sizeof(uint32_t))) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Rejecting FILEINFO from server: invalid message size");
        send_abort(listidx, "Rejecting FILEINFO: invalid message size");
        return 0;
    }

    if (group_list[listidx].phase == PHASE_RECEIVING) {
        // We already got the FILEINFO, so no need to reprocess.
        // Just resend the INFO_ACK if requested and reset the timeout
        if (addr_in_list(listidx, addrlist, ntohs(fileinfo->destcount))) {
            send_info_ack(listidx, group_list[listidx].fileinfo.restart);
        }
        set_timeout(listidx);
        return 0;
    }
    if ((group_list[listidx].phase == PHASE_MIDGROUP) &&
            (group_list[listidx].file_id == ntohs(fileinfo->file_id))) {
        // We already got the FILEINFO, and it's for a completed file.
        // So resend the COMPLETE if requested and reset the timeout
        if (addr_in_list(listidx, addrlist, ntohs(fileinfo->destcount))) {
            send_complete(listidx);
        }
        set_timeout(listidx);
        return 0;
    }

    // Load fileinfo params into list
    if (strlen(fileinfo->name) == 0) {
        log(group_list[listidx].group_id, ntohs(fileinfo->file_id),
                "Rejecting FILEINFO from server: blank file name");
        send_abort(listidx, "Rejecting FILEINFO: blank file name");
        return 0;
    }
    p = strstr(fileinfo->name, "..");
    if ((p != NULL) && ((p[2] == '\x0') || (p[2] == '/') || (p[2] == '\\')) &&
            ((p == fileinfo->name) || (p[-1] == '/') || (p[-1] == '\\'))) {
        log(group_list[listidx].group_id, ntohs(fileinfo->file_id),
                "Rejecting FILEINFO from server: filename contains ..");
        send_abort(listidx, "Rejecting FILEINFO: filename contains ..");
        return 0;
    }

    memset(&group_list[listidx].fileinfo, 0, sizeof(struct file_t));
    group_list[listidx].fileinfo.ftype = fileinfo->ftype;
    group_list[listidx].file_id = ntohs(fileinfo->file_id);
    strncpy(group_list[listidx].fileinfo.name, fileinfo->name, 
            sizeof(group_list[listidx].fileinfo.name)-1);
    if (fileinfo->ftype == FTYPE_LINK) {
        p = fileinfo->name + strlen(fileinfo->name) + 1;
        if (p - fileinfo->name >= sizeof(fileinfo->name)) {
            log(group_list[listidx].group_id, group_list[listidx].file_id,
                    "Rejecting FILEINFO from server: bad link name");
            send_abort(listidx, "Rejecting FILEINFO: bad link name");
            return 0;
        }
        if (strlen(p) == 0) {
            log(group_list[listidx].group_id, group_list[listidx].file_id,
                    "Rejecting FILEINFO from server: blank link name");
            send_abort(listidx, "Rejecting FILEINFO: blank link name");
            return 0;
        }
        strncpy(group_list[listidx].fileinfo.linkname, p,
                sizeof(group_list[listidx].fileinfo.linkname)-1);
    }
    group_list[listidx].fileinfo.blocks = ntohl(fileinfo->block_total);
    group_list[listidx].fileinfo.sections = ntohs(fileinfo->section_total);
    group_list[listidx].fileinfo.size = 
            (f_offset_t)ntohl(fileinfo->hifsize) << 32;
    group_list[listidx].fileinfo.size |= ntohl(fileinfo->lofsize);
    group_list[listidx].fileinfo.fd = -1;

    return 1;
}

/**
 * Process an incoming FILEINFO message.
 * Expected in the middle of a group with no current file.
 * For version 2, process the file info portion of an ANNOUNCE message.
 * Returns 1 on success, 0 on error or ignore
 */
int handle_fileinfo(int listidx, const unsigned char *message, int meslen)
{
    char filepath[MAXPATHNAME];
    stat_struct statbuf;
    int found_dir;

    if (group_list[listidx].version == UFTP_V2_VER) {
        read_v2_fileinfo(listidx, message);
    } else if (!read_fileinfo(listidx, message, meslen)) {
        return 0;
    }

    log(group_list[listidx].group_id, group_list[listidx].file_id,
            "Name of file to receive: %s", group_list[listidx].fileinfo.name);
    switch (group_list[listidx].fileinfo.ftype) {
    case FTYPE_REG:
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Bytes: %s, Blocks: %d, Sections: %d",
                printll(group_list[listidx].fileinfo.size),
                group_list[listidx].fileinfo.blocks,
                group_list[listidx].fileinfo.sections);
        break;
    case FTYPE_DIR:
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Empty directory");
        break;
    case FTYPE_LINK:
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Symbolic link to %s", group_list[listidx].fileinfo.linkname);
        break;
    default:
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                 "Invalid file type: %d", group_list[listidx].fileinfo.ftype);
        send_abort(listidx, "Invalid file type");
        return 0;
    }

    if (!strcmp(tempdir, "")) {
        snprintf(filepath, sizeof(filepath), "%s%c%s", destdir, PATH_SEP,
                 group_list[listidx].fileinfo.name);
    } else {
        snprintf(filepath, sizeof(filepath), "%s%c_group_%08X%c%s", tempdir,
                 PATH_SEP, group_list[listidx].group_id, PATH_SEP,
                 group_list[listidx].fileinfo.name);
    }
    if (!create_path_to_file(listidx, filepath)) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                 "Error creating path to data file");
        send_abort(listidx, "Error creating path to data file");
        return 0;
    }
    found_dir = 0;
    if (lstat_func(filepath, &statbuf) != -1) {
        if ((group_list[listidx].fileinfo.ftype != FTYPE_DIR) ||
                !S_ISDIR(statbuf.st_mode)) {
            if ((group_list[listidx].fileinfo.ftype != FTYPE_REG) ||
                    !S_ISREG(statbuf.st_mode) ||
                    (!group_list[listidx].restart)) {
                // Don't clear_path if we're receiving a regular file
                // and we're in restart mode
                clear_path(filepath, listidx);
            }
        } else {
            found_dir = 1;
        }
    }
    switch (group_list[listidx].fileinfo.ftype) {
    case FTYPE_REG:
        if (group_list[listidx].restartinfo) {
            if ((!strcmp(group_list[listidx].fileinfo.name,
                        group_list[listidx].restartinfo->name)) &&
                    (group_list[listidx].fileinfo.size ==
                        group_list[listidx].restartinfo->size) &&
                    (group_list[listidx].fileinfo.blocks ==
                        group_list[listidx].restartinfo->blocks) &&
                    (group_list[listidx].fileinfo.sections ==
                        group_list[listidx].restartinfo->sections)) {
                // Flag this file to restart a failed transfer
                group_list[listidx].fileinfo.restart = 1;
            } else if ((lstat_func(filepath, &statbuf) != -1) &&
                       S_ISREG(statbuf.st_mode) &&
                       (statbuf.st_size == group_list[listidx].fileinfo.size)) {
                // This file was finished on the last attempt,
                // so respond with a COMPLETE right away
                group_list[listidx].phase = PHASE_MIDGROUP;
                send_complete(listidx);
                set_timeout(listidx);
                return 1;
            }
        }
        if (group_list[listidx].fileinfo.restart) {
            group_list[listidx].fileinfo.fd = open(filepath, OPENWRITE);
        } else {
            group_list[listidx].fileinfo.fd =
                    open(filepath, OPENWRITE | O_CREAT | O_TRUNC, 0644);
        }
        if (group_list[listidx].fileinfo.fd == -1) {
            syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                     "Error opening data file");
            send_abort(listidx, "Error opening data file");
            return 0;
        }
        break;
    case FTYPE_DIR:
        if (!found_dir) {
            if (mkdir(filepath, 0755) == -1) {
                syserror(group_list[listidx].group_id,
                         group_list[listidx].file_id,
                         "Failed to create directory %s", filepath);
                send_abort(listidx, "Failed to create directory");
                return 0;
            }
        }
        group_list[listidx].phase = PHASE_MIDGROUP;
        send_complete(listidx);
        set_timeout(listidx);
        return 1;
        break;
    case FTYPE_LINK:
#ifndef WINDOWS
        if (symlink(group_list[listidx].fileinfo.linkname, filepath) == -1) {
            syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                     "Failed to create symlink %s", filepath);
            send_abort(listidx, "Failed to create symlink");
            return 0;
        }
#endif
        group_list[listidx].phase = PHASE_MIDGROUP;
        send_complete(listidx);
        set_timeout(listidx);
        return 1;
        break;
    }

    if (group_list[listidx].fileinfo.restart) {
        group_list[listidx].fileinfo.naklist =
                group_list[listidx].restartinfo->naklist;
        group_list[listidx].fileinfo.section_done =
                group_list[listidx].restartinfo->section_done;
        group_list[listidx].restartinfo->naklist = NULL;
        group_list[listidx].restartinfo->section_done = NULL;
        free(group_list[listidx].restartinfo);
        group_list[listidx].restartinfo = NULL;
    } else {
        group_list[listidx].fileinfo.naklist =
                calloc(group_list[listidx].fileinfo.blocks, 1);
        if (group_list[listidx].fileinfo.naklist == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        group_list[listidx].fileinfo.section_done =
                calloc(group_list[listidx].fileinfo.sections, 1);
        if (group_list[listidx].fileinfo.section_done == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        memset(group_list[listidx].fileinfo.naklist, 1,
               group_list[listidx].fileinfo.blocks);
    }
    group_list[listidx].fileinfo.last_block = -1;
    group_list[listidx].fileinfo.curr_offset = 0;
    group_list[listidx].fileinfo.wait = 0;

    if (group_list[listidx].version != UFTP_V2_VER) {
        group_list[listidx].phase = PHASE_RECEIVING;
        send_info_ack(listidx, group_list[listidx].fileinfo.restart);
        set_timeout(listidx);
    }

    return 1;
}
