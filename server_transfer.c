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

#include "win_func.h"

#else  // if WINDOWS

#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif

#include "server.h"
#include "server_common.h"
#include "server_transfer.h"

/**
 * Send out DONE_CONF messages specifiying all completed clients.
 * Returns 1 on success, 0 on fail
 */
int send_doneconf(const struct finfo_t *finfo, int attempt)
{
    unsigned char *buf;
    struct uftp_h *header;
    struct doneconf_h *doneconf;
    uint32_t *addrlist;
    int rval;

    if (finfo->file_id != 0) {
        return 1;
    }

    buf = calloc(mtu, 1); 
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)buf;
    doneconf = (struct doneconf_h *)(buf + sizeof(struct uftp_h));
    addrlist = (uint32_t *)((char *)doneconf + sizeof(struct doneconf_h));

    set_uftp_header(header, DONE_CONF, finfo, &receive_dest);
    doneconf->func = DONE_CONF;
    doneconf->file_id = htons(finfo->file_id);
    rval = send_multiple(finfo, buf, DONE_CONF, attempt, addrlist, DEST_DONE,
            &doneconf->destcount, (keytype != KEY_NONE), &receive_dest, 0);
    free(buf);
    return rval;
}

/**
 * Send out DONE messages specifiying active clients that haven't yet responded.
 * Returns 1 on success, 0 on fail
 */
int send_done(const struct finfo_t *finfo, int attempt, int pass, int section)
{
    unsigned char *buf;
    struct uftp_h *header;
    struct done_h *done;
    uint32_t *addrlist;
    int rval;

    buf = calloc(mtu, 1); 
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)buf;
    done = (struct done_h *)(buf + sizeof(struct uftp_h));
    addrlist = (uint32_t *)((char *)done + sizeof(struct done_h));

    set_uftp_header(header, DONE, finfo, &receive_dest);
    done->func = DONE;
    done->file_id = htons(finfo->file_id);
    done->pass = pass;
    done->section = htons(section);

    rval = send_multiple(finfo, buf, DONE, attempt, addrlist, DEST_STATUS,
            &done->destcount, (keytype != KEY_NONE), &receive_dest, 0);
    free(buf);
    return rval;
}

/**
 * Process an expected COMPLETE message
 */
void handle_complete(const unsigned char *message, int meslen,
                     struct finfo_t *finfo, int hostidx)
{
    struct complete_h *complete;
    uint32_t *addrlist;
    int clientcnt, clientidx, dupmsg, isproxy, i;

    complete = (struct complete_h *)message;
    addrlist = (uint32_t *)((char *)complete + sizeof(struct complete_h));
    clientcnt = ntohs(complete->destcount);

    if (meslen != sizeof(struct complete_h) +
                  (clientcnt * sizeof(uint32_t))) {
        log(0, 0, "Rejecting COMPLETE from %s: invalid message size",
                   destlist[hostidx].name);
        return;
    }
    if (ntohs(complete->file_id) != finfo->file_id) {
        log(0, 0, "Rejecting COMPLETE from %s: invalid file ID %04X, "
                  "expected %04X ", destlist[hostidx].name,
                  ntohs(complete->file_id), finfo->file_id);
        return;
    }

    dupmsg = (destlist[hostidx].status == DEST_DONE);
    isproxy = (destlist[hostidx].clientcnt != -1);
    log(0, 0, "Got COMPLETE%s from %s %s", (dupmsg && !isproxy) ? "+" : "",
               (isproxy) ? "proxy" : "client", destlist[hostidx].name);
    if (destlist[hostidx].clientcnt != -1) {
        for (i = 0; i < clientcnt; i++) {
            clientidx = find_client(addrlist[i]);
            if (clientidx == -1) {
                log(0, 0, "Client %s via proxy %s not found",
                           inet_ntoa(to_addr(addrlist[i])),
                           destlist[hostidx].name);
            } else if (destlist[clientidx].proxyidx != hostidx) {
                log(0, 0, "Client %s found via proxy %s, expected proxy %s",
                           destlist[clientidx].name,
                           destlist[destlist[clientidx].proxyidx].name,
                           destlist[hostidx].name);
            } else {
                dupmsg = (destlist[clientidx].status == DEST_DONE);
                log(0, 0, "  For client%s %s", dupmsg ? "+" : "",
                           destlist[clientidx].name);
                finfo->deststate[clientidx].conf_sent = 0;
                destlist[clientidx].status = DEST_DONE;
                gettimeofday(&finfo->deststate[clientidx].time, NULL);
            }
        }
    } else {
        finfo->deststate[hostidx].conf_sent = 0;
        destlist[hostidx].status = DEST_DONE;
        gettimeofday(&finfo->deststate[hostidx].time, NULL);
    }
}

/**
 * Apply the given NAKs to the naklist
 */
void apply_naks(unsigned char *naklist, struct finfo_t *finfo,
                int blocks_this_sec, int section_offset)
{
    int nakidx, listidx, i;

    for (i = 0; i < blocks_this_sec; i++) {
        // Each bit represents a NAK; check each one
        // Simplified: (naklist[listidx / 8] & (1 << (listidx % 8)))
        nakidx = i + section_offset;
        listidx = i;
        if ((naklist[listidx >> 3] & (1 << (listidx & 7))) != 0) {
            if (verbose >= 2) {
                log(0, 0, "Got NAK for %d", nakidx);
            }
            finfo->naklist[nakidx] = 1;
        }
    }
}

/**
 * Mark clients as having sent status as specified by PRSTATUS
 */
void set_proxy_status(struct finfo_t *finfo, const unsigned char *data,
                      int hostidx, int nak_count)
{
    struct prstatus_h *prstatus;
    uint32_t *addrlist;
    int clientcnt, clientidx, dupmsg, i;

    prstatus = (struct prstatus_h *)data;
    addrlist = (uint32_t *)(data + sizeof(struct prstatus_h));

    clientcnt = ntohs(prstatus->destcount);
    for (i = 0; i < clientcnt; i++) {
        clientidx = find_client(addrlist[i]);
        if (clientidx == -1) {
            log(0, 0, "Client %s via proxy %s not found",
                       inet_ntoa(to_addr(addrlist[i])), destlist[hostidx].name);
        } else if (destlist[clientidx].proxyidx != hostidx) {
            log(0, 0, "Client %s found via proxy %s, expected proxy %s",
                       destlist[clientidx].name,
                       destlist[destlist[clientidx].proxyidx].name,
                       destlist[hostidx].name);
        } else if (!client_error(clientidx)) {
            dupmsg = (destlist[clientidx].status == DEST_ACTIVE);
            destlist[clientidx].status = DEST_ACTIVE;
            log(0, 0, "  For client%s %s", dupmsg ? "+" : "",
                       destlist[clientidx].name);
            if (!dupmsg) {
                finfo->deststate[clientidx].naks += nak_count;
            }
        }
    }
}

/**
 * Process an expected PRSTATUS message
 */
void handle_prstatus(const unsigned char *message, int meslen,
                     struct finfo_t *finfo, int hostidx,
                     int blocks_this_sec, int section_offset,
                     int pass, int section)
{
    struct status_h *status;
    struct prstatus_h *prstatus, *tmp_prstatus;
    unsigned char *naklist;
    int clientcnt, maxseq;
    int mes_pass, mes_section, nak_count, i;

    if (destlist[hostidx].clientcnt == -1) {
        log(0, 0, "Rejecting PRSTATUS from %s: not a proxy",
                   destlist[hostidx].name);
        return;
    }

    prstatus = (struct prstatus_h *)message;
    mes_pass = prstatus->pass;
    mes_section = ntohs(prstatus->section);
    clientcnt = ntohs(prstatus->destcount);
    if (meslen != sizeof(struct prstatus_h) + 
                  (clientcnt * sizeof(uint32_t))) {
        log(0, 0, "Rejecting PRSTATUS from %s: invalid message size",
                   destlist[hostidx].name);
        return;
    }
    if (ntohs(prstatus->file_id) != finfo->file_id) {
        log(0, 0, "Rejecting PRSTATUS from %s: invalid file ID %04X, "
                  "expected %04X ", destlist[hostidx].name,
                  ntohs(prstatus->file_id), finfo->file_id );
        return;
    }

    if ((mes_pass == pass) && (mes_section == section)) {
        if (destlist[hostidx].last_status) {
            // If we have a STATUS with matching pass/section/seq,
            // apply the NAKs to all listed clients and mark the clients
            // as having received status
            status = (struct status_h *)destlist[hostidx].last_status;
            nak_count = ntohl(status->nak_count);
            naklist = ((unsigned char *)status) + sizeof(struct status_h);
            if ((status->pass == pass) &&
                    (ntohs(status->section) == section) &&
                    (status->seq == prstatus->seq)) {
                log(0, 0, "Got %d NAKs for pass %d section %d from proxy %s",
                           nak_count, mes_pass, mes_section,
                           destlist[hostidx].name);
                set_proxy_status(finfo, (unsigned char *)prstatus, hostidx,
                                 nak_count);
                if (nak_count) {
                    apply_naks(naklist, finfo, blocks_this_sec, section_offset);
                }
            }
        }

        // Add this PRSTATUS to the last_prstatus list, clearing the list
        // if existing messages don't match the pass/section/seq of this one
        maxseq = destlist[hostidx].last_prstatus_cnt;
        if (maxseq > 0) {
            tmp_prstatus =
                    (struct prstatus_h *)destlist[hostidx].last_prstatus[0];
            if ((tmp_prstatus->pass != pass) ||
                    (ntohs(tmp_prstatus->section) != section) ||
                    (tmp_prstatus->seq != prstatus->seq)) {
                for (i = 0; i < maxseq; i++) {
                    free(destlist[hostidx].last_prstatus[i]);
                }
                maxseq = 0;
            }
        }
        destlist[hostidx].last_prstatus[maxseq] = calloc(meslen, 1);
        if (destlist[hostidx].last_prstatus[maxseq] == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        memcpy(destlist[hostidx].last_prstatus[maxseq], prstatus, meslen);
        destlist[hostidx].last_prstatus_cnt = maxseq + 1;
    }
}

/**
 * Process an expected STATUS message
 */
void handle_status(const unsigned char *message, int meslen,
                   struct finfo_t *finfo, int hostidx,
                   int blocks_this_sec, int section_offset,
                   int pass, int section)
{
    struct status_h *status;
    struct prstatus_h *prstatus;
    unsigned char *naklist;
    int mes_pass, mes_section, nak_count, i, dupmsg;

    status = (struct status_h *)message;
    naklist = ((unsigned char *)status) + sizeof(struct status_h);
    mes_pass = status->pass;
    mes_section = ntohs(status->section);
    nak_count = ntohl(status->nak_count);
    if (meslen != sizeof(struct status_h) + (nak_count ? blocksize : 0)) {
        log(0, 0, "Rejecting STATUS from %s: invalid message size",
                   destlist[hostidx].name);
        return;
    }
    if (ntohs(status->file_id) != finfo->file_id) {
        log(0, 0, "Rejecting STATUS from %s: invalid file ID %04X, "
                  "expected %04X ", destlist[hostidx].name,
                  ntohs(status->file_id), finfo->file_id );
        return;
    }

    if ((mes_pass == pass) && (mes_section == section)) {
        if (destlist[hostidx].clientcnt != -1) {
            // If we have one or more PRSTATUS with matching pass/section/seq,
            // apply the NAKs to all listed clients and mark the clients
            // as having received status
            if (destlist[hostidx].last_prstatus_cnt > 0) {
                prstatus =
                    (struct prstatus_h *)destlist[hostidx].last_prstatus[0];
                if ((prstatus->pass == pass) &&
                        (ntohs(prstatus->section) == section) &&
                        (prstatus->seq == status->seq)) {
                    log(0, 0,"Got %d NAKs for pass %d section %d from proxy %s",
                               nak_count, mes_pass, mes_section,
                               destlist[hostidx].name);
                    for (i = 0; i < destlist[hostidx].last_prstatus_cnt; i++) {
                        set_proxy_status(finfo,
                                destlist[hostidx].last_prstatus[i],
                                hostidx, nak_count);
                    }
                    if (nak_count) {
                        apply_naks(naklist, finfo,
                                   blocks_this_sec, section_offset);
                    }
                }
            }
            free(destlist[hostidx].last_status);
            destlist[hostidx].last_status = calloc(meslen, 1);
            if (destlist[hostidx].last_status == NULL) {
                syserror(0, 0, "calloc failed!");
                exit(1);
            }
            memcpy(destlist[hostidx].last_status, status, meslen);
        } else {
            log(0, 0, "Got %d NAKs for pass %d section %d from client %s",
                      nak_count, mes_pass, mes_section, destlist[hostidx].name);
            dupmsg = (destlist[hostidx].status == DEST_ACTIVE);
            destlist[hostidx].status = DEST_ACTIVE;
            if (!dupmsg) {
                finfo->deststate[hostidx].naks += nak_count;
            }
            if (nak_count) {
                apply_naks(naklist, finfo, blocks_this_sec, section_offset);
            }
        }
    } else {
        log(0, 0, "Got %d NAKs for pass %d section %d from %s",
                  nak_count, mes_pass, mes_section, destlist[hostidx].name);
    }
}

/**
 * Sends out a data packet.  All headers should be populated except blsize
 */
int send_data(const struct finfo_t *finfo, unsigned char *packet, int datalen,
              unsigned char *encpacket)
{
    struct uftp_h *header;
    struct fileseg_h *fileseg;
    int payloadlen;
    unsigned char *outpacket;

    header = (struct uftp_h *)packet;
    fileseg = (struct fileseg_h *)(packet + sizeof(struct uftp_h));

    payloadlen = sizeof(struct fileseg_h) + datalen;
    if (keytype != KEY_NONE) {
        if (!encrypt_and_sign(packet, &encpacket, payloadlen, mtu, keytype,
                groupkey, groupsalt, ivlen, hashtype, grouphmackey, hmaclen,
                sigtype, privkey, rsalen)) {
            log(0, 0, "Error encrypting FILESEG");
            return 0;
        }
        outpacket = encpacket;
        payloadlen = ntohs(((struct uftp_h *)outpacket)->blsize);
    } else {
        outpacket = packet;
        header->blsize = htons(payloadlen);
    }

    if (nb_sendto(sock, outpacket, payloadlen + sizeof(struct uftp_h), 0,
               (struct sockaddr *)&receive_dest,
               sizeof(receive_dest)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error sending FILESEG");
        return 0;
    }

    return 1;
}

/**
 * Print the final statistics for the given file
 */
void print_status(const struct finfo_t *finfo, struct timeval start_time)
{
    struct timeval done_time;
    double elapsed_time;
    int i;

    if (finfo->file_id == 0) {
        log(0, 0, "Group complete");
        return;
    }

    log(0, 0, "Transfer status:");
    for (done_time = start_time, i = 0; i < destcount; i++) {
        if (destlist[i].clientcnt >= 0) {
            continue;
        }
        clog(0, 0, "Host: %-15s  Status: ", destlist[i].name);
        switch (destlist[i].status) {
        case DEST_MUTE:
            slog("Mute");
            break;
        case DEST_LOST:
            slog("Lost connection");
            break;
        case DEST_ABORT:
            slog("Aborted");
            break;
        case DEST_DONE:
            if (diff_usec(finfo->deststate[i].time, done_time) > 0) {
                done_time = finfo->deststate[i].time;
            }
            elapsed_time = (double)diff_usec(finfo->deststate[i].time,
                                             start_time) / 1000000;
            slog("Completed   time: %7.3f seconds    NAKs: %d",
                 elapsed_time, finfo->deststate[i].naks);
            break;
        default:
            slog("Unknown  code: %d", destlist[i].status);
            break;
        }
    }
    elapsed_time = (double)diff_usec(done_time, start_time) / 1000000;
    log(0, 0, "Total elapsed time: %.3f seconds", elapsed_time);
    log(0, 0, "Overall throughput: %.2f KB/s",
               (elapsed_time != 0) ? (finfo->size / elapsed_time / 1024) : 0);
}

