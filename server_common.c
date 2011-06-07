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

// none

#else  // if WINDOWS

#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#endif

#include "server.h"
#include "server_common.h"

/**
 * Initializes the uftp header of an outgoing packet
 * blsize is initialized to 0, but must be set later before sending
 */
void set_uftp_header(struct uftp_h *header, int func,
                     const struct finfo_t *finfo,
                     const struct sockaddr_in *dest)
{
    header->uftp_id = UFTP_VER_NUM;
    header->func = func;
    header->blsize = 0;
    header->group_id = htonl(finfo->group_id);
    header->srcaddr = out_addr.s_addr;
    header->destaddr = dest->sin_addr.s_addr;
}

/**
 * Sends an ABORT message to one or more clients
 */
void send_abort(const struct finfo_t *finfo, const char *message,
                const struct sockaddr_in *destaddr,
                const struct in_addr *dest, int encrypt)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct abort_h *abort;
    int payloadlen;

    buf = calloc(mtu, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)buf;
    abort = (struct abort_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, ABORT, finfo, destaddr);
    abort->func = ABORT;
    if (dest) {
        abort->host = dest->s_addr;
    }
    strncpy(abort->message, message, sizeof(abort->message) - 1);

    payloadlen = sizeof(struct abort_h);
    if (encrypt) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen, mtu, keytype,
                groupkey, groupsalt, ivlen, hashtype, grouphmackey, hmaclen,
                sigtype, privkey, rsalen)) {
            log(0, 0, "Error encrypting ABORT");
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

    if (nb_sendto(sock, outpacket, payloadlen + sizeof(struct uftp_h), 0,
               (struct sockaddr *)destaddr,
               sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error sending ABORT");
    }
    free(buf); 
    free(encrypted);
} 

/**
 * For messages that send a list of clients in the body, append all clients
 * in the specified state to the packet, then send the message of the given
 * type when either the body is full or the end of the client list has been
 * reached.  All header fields besides uftp_h.blsize and message.destcount
 * must be populated before calling.
 * Returns 1 on success, 0 on fail.
 */
int send_multiple(const struct finfo_t *finfo, unsigned char *packet,
                  int message, int attempt, uint32_t *addrlist, int state,
                  uint16_t *mes_destcount, int encrypt,
                  const struct sockaddr_in *destaddr, int regconf)
{
    struct uftp_h *header;
    int hsize, payloadlen;
    int maxdest, packetcnt, dests, i;
    unsigned char *mheader, *encpacket, *outpacket;

    header = (struct uftp_h *)packet;
    mheader = packet + sizeof(struct uftp_h);
    hsize = (unsigned char *)addrlist - mheader;
    maxdest = ((encrypt ? encpayloadsize : payloadsize) - hsize) /
              sizeof(struct in_addr);
    packetcnt = 1;
    if (encrypt) {
        encpacket = calloc(mtu + keylen, 1); 
        if (encpacket == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
    } else {
        encpacket = NULL;
    }
    for (i = 0, dests = 0; i < destcount; i++) {
        if (message == REG_CONF) {
            // Only send REG_CONF for a particular client if either it's
            // behind a proxy or we're sending them to everyone.
            // Also, don't send if we already sent one and we haven't
            // gotten another REGISTER
            if ((destlist[i].status == state) &&
                    (!finfo->deststate[i].conf_sent) &&
                    (regconf || (destlist[i].proxyidx != -1))) {
                addrlist[dests++] = destlist[i].addr.s_addr;
                finfo->deststate[i].conf_sent = 1;
            }
        } else if (message == DONE_CONF) {
            // As with REG_CONF, don't send a DONE_CONF for a client
            // if we already sent one and we haven't gotten another COMPLETE
            if ((destlist[i].status == state) &&
                    (!finfo->deststate[i].conf_sent)) {
                addrlist[dests++] = destlist[i].addr.s_addr;
                finfo->deststate[i].conf_sent = 1;
            }
        } else if (destlist[i].status == state) {
            addrlist[dests++] = destlist[i].addr.s_addr;
        }
        if ((dests >= maxdest) || ((i == destcount - 1) && (dests > 0))) {
            payloadlen = hsize + (dests * sizeof(uint32_t));
            *mes_destcount = htons(dests);
            if (encrypt) {
                if (!encrypt_and_sign(packet, &encpacket, payloadlen, mtu,
                        keytype, groupkey, groupsalt, ivlen, hashtype,
                        grouphmackey, hmaclen, sigtype, privkey, rsalen)) {
                    log(0, 0, "Error encrypting %s", func_name(message));
                    free(encpacket);
                    return 0;
                }
                outpacket = encpacket;
                payloadlen = ntohs(((struct uftp_h *)outpacket)->blsize);
            } else {
                outpacket = packet;
                header->blsize = htons(payloadlen);
            }
            log(0, 0, "Sending %s %d.%d", func_name(message), 
                       attempt, packetcnt);
            if (nb_sendto(sock, outpacket, payloadlen + sizeof(struct uftp_h),0,
                       (struct sockaddr *)destaddr,
                       sizeof(*destaddr)) == SOCKET_ERROR) {
                sockerror(0, 0, "Error sending %s", func_name(message));
                sleep(1);
                free(encpacket);
                return 0;
            }
            if (packet_wait) usleep(packet_wait);
            memset(addrlist, 0, maxdest * sizeof(uint32_t));
            dests = 0;
            packetcnt++;
        }
    }
    free(encpacket);
    return 1;
}

/**
 * Do basic checking on a received packet, like checking the version
 * and making sure the size matches the size in the header.
 * Returns 1 on success, 0 on fail.
 */
int validate_packet(const unsigned char *packet, int len,
                    const struct finfo_t *finfo)
{
    struct uftp_h *header;

    header = (struct uftp_h *)packet;
    if (header->uftp_id != UFTP_VER_NUM) {
        log(0, 0, "Invalid version %02X", header->uftp_id);
        return 0;
    }
    if (len - sizeof(struct uftp_h) != ntohs(header->blsize)) {
        log(0, 0, "Invalid packet size %d, expected %d",
                   len - sizeof(struct uftp_h), ntohs(header->blsize));
        return 0;
    }
    if (ntohl(header->group_id) != finfo->group_id) {
        log(0, 0, "Invalid group ID %08X, expected %08X",
                   ntohl(header->group_id), finfo->group_id);
        return 0;
    }
    if ((header->func == ENCRYPTED) && (keytype == KEY_NONE)) {
        log(0, 0, "Received encrypted packet with encryption disabled");
        return 0;
    }
    return 1;
}

/**
 * Look for a given client in the global client list
 * Returns the client's index in the list, or -1 if not found
 */
int find_client(uint32_t addr)
{
    int i;

    // TODO: This can be a lot more efficient.  Should probably sort by
    // addr and keep an index, then do a binary search.
    for (i = 0; i < destcount; i++) {
        if (destlist[i].addr.s_addr == addr) {
            return i;
        }
    }
    return -1;
}

/**
 * Check to see if a client is in an error state
 * Returns 1 if true, 0 if false
 */
int client_error(int listidx)
{
    return ((destlist[listidx].status == DEST_MUTE) ||
            (destlist[listidx].status == DEST_LOST) ||
            (destlist[listidx].status == DEST_ABORT));
}

/**
 * Process an ABORT message
 */
void handle_abort(const unsigned char *message, int meslen, int idx,
                  struct finfo_t *finfo, const struct in_addr *hostaddr)
{
    struct abort_h *abort;
    int i;

    abort = (struct abort_h *)message;
    if (meslen != sizeof(struct abort_h)) {
        log(0, 0, "Rejecting ABORT from %s: invalid message size",
                  (idx == -1) ? inet_ntoa(*hostaddr) : destlist[idx].name);
        return;
    }
    if (idx == -1) {
        log(0, 0, "Transfer aborted by %s: %s",
                   inet_ntoa(*hostaddr), abort->message);
        return;
    }

    if (abort->host != 0) {
        idx = find_client(abort->host);
    }
    if (idx == -1) {
        log(0, 0, "Transfer aborted by %s: %s",
                   inet_ntoa(*hostaddr), abort->message);
    } else {
        destlist[idx].status = DEST_ABORT;
        log(0, 0, "Transfer aborted by %s: %s",
                   destlist[idx].name, abort->message);
    }
    if (quit_on_error) {
        log(0, 0, "Aboring all clients");
        send_abort(finfo, "A client aborted, aborting all",
                &receive_dest, NULL, 0);
        // If encryption enabled, send ABORT both encrypted and unencrypted
        // since we can't be sure what phase we're currently in.
        if (keytype != KEY_NONE) {
            send_abort(finfo, "A client aborted, aborting all",
                    &receive_dest, NULL, 1);
        }
        for (i = 0; i < destcount; i++) {
            if ((destlist[i].status == DEST_ACTIVE) ||
                    (destlist[i].status == DEST_REGISTERED) ||
                    (destlist[i].status == DEST_STATUS)) {
                destlist[i].status = DEST_ABORT;
            }
        }
    }
}

