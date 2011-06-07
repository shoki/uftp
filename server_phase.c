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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <math.h>

#ifdef WINDOWS

#include <io.h>
#include "win_func.h"

#else  // if WINDOWS

#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif

#include "server.h"
#include "server_common.h"
#include "server_announce.h"
#include "server_transfer.h"


/**
 * Check an announce phase message and pass to appropriate message handler,
 * decrypting first if necessary
 * Returns 1 on success, 0 on error
 */
int handle_announce_phase(const unsigned char *packet, unsigned char *decrypted,
                          const struct sockaddr_in *receiver,
                          struct finfo_t *finfo,
                          int announce, int open, int regconf)
{
    struct uftp_h *header;
    const unsigned char *message;
    int hostidx;
    unsigned decryptlen, meslen;
    uint8_t *func;
    struct in_addr srcaddr;

    header = (struct uftp_h *)packet;
    hostidx = find_client(header->srcaddr);
    if (header->srcaddr == 0) {
        srcaddr = receiver->sin_addr;
    } else {
        srcaddr.s_addr = header->srcaddr;
    }
    if ((keytype != KEY_NONE) && (header->func == ENCRYPTED)) {
        if (hostidx == -1) {
            log(0, 0, "Got encrypted packet from unknown receiver %s",
                      inet_ntoa(srcaddr));
            return 0;
        }
        if (!validate_and_decrypt(packet, &decrypted, &decryptlen, mtu,
                keytype, groupkey, groupsalt, ivlen, hashtype, grouphmackey,
                hmaclen, sigtype, destlist[hostidx].pubkey,
                destlist[hostidx].pubkeylen)) {
            log(0, 0, "Rejecting message from %s: decrypt/validate failed",
                       destlist[hostidx].name);
            return 0;
        }
        func = (uint8_t *)decrypted;
        message = decrypted;
        meslen = decryptlen;
    } else {
        if ((keytype != KEY_NONE) && (header->func == INFO_ACK)) {
            log(0, 0, "Rejecting %s message from %s: not encrypted",
                      func_name(header->func), inet_ntoa(srcaddr));
            return 0;
        }
        func = (uint8_t *)&header->func;
        message = packet + sizeof(struct uftp_h);
        meslen = ntohs(header->blsize);
    }

    if (*func == ABORT) {
        handle_abort(message, meslen, hostidx, finfo, &srcaddr);
        return 1;
    }

    if (hostidx == -1) {
        if (open) {
            if (*func == REGISTER) {
                handle_open_register(message, meslen, finfo, receiver,
                                     &srcaddr, regconf);
            } else if (*func == CLIENT_KEY) {
                handle_open_clientkey(message, meslen, finfo, receiver,
                                      &srcaddr);
            } else {
                log(0, 0, "Invalid function: expected "
                          "REGISTER or CLIENT_KEY, got %s", func_name(*func));
            }
        } else {
            log(0, 0, "Host %s not in host list", inet_ntoa(srcaddr));
            send_abort(finfo, "Not in host list", receiver, &srcaddr, 0);
        }
    } else {
        switch (destlist[hostidx].status) {
        case DEST_MUTE:
            if (*func == REGISTER) {
                handle_register(message, meslen, finfo, receiver,
                                &srcaddr, hostidx, regconf, open);
            } else if (*func == CLIENT_KEY) {
                handle_clientkey(message, meslen, finfo, receiver,
                                 &srcaddr, hostidx);
            } else {
                log(0, 0, "Invalid function: expected "
                          "REGISTER or CLIENT_KEY, got %s", func_name(*func));
            }
            break;
        case DEST_REGISTERED:
            if (*func == INFO_ACK) {
                handle_info_ack(message, meslen, finfo, receiver,
                                &srcaddr, hostidx, announce);
            } else if (*func == REGISTER) {
                handle_register(message, meslen, finfo, receiver,
                                &srcaddr, hostidx, regconf, open);
            } else if (*func == CLIENT_KEY) {
                log(0, 0, "Received CLIENT_KEY+ from %s",
                          destlist[hostidx].name);
            } else if (!announce && (*func == COMPLETE)) {
                handle_complete(message, meslen, finfo, hostidx);
            } else {
                log(0, 0, "Received invalid message %s from %s",
                          func_name(*func), destlist[hostidx].name);
            }
            break;
        case DEST_ACTIVE:
            if (*func == REGISTER) {
                handle_register(message, meslen, finfo, receiver,
                                &srcaddr, hostidx, regconf, open);
            } else if (*func == CLIENT_KEY) {
                log(0, 0, "Received CLIENT_KEY+ from %s",
                          destlist[hostidx].name);
            } else if (*func == INFO_ACK) {
                finfo->deststate[hostidx].conf_sent = 0;
                handle_info_ack(message, meslen, finfo, receiver,
                                &srcaddr, hostidx, announce);
            } else if (!announce && (*func == COMPLETE)) {
                handle_complete(message, meslen, finfo, hostidx);
            } else {
                log(0, 0, "Received invalid message %s from %s",
                          func_name(*func), destlist[hostidx].name);
            }
            break;
        default:
            log(0, 0, "Received invalid message %s from %s",
                      func_name(*func), destlist[hostidx].name);
            break;
        }
    }

    return 1;
}

/**
 * Perform the Announce/Register phase for a particular group/file
 * Group & encryption: ->ANNOUNCE <-REGISTER ->KEYINFO <-INFO_ACK
 * Group & no encryption: ->ANNOUNCE <-REGISTER ->REG_CONF
 * Files within a group: ->FILEINFO <-INFO_ACK
 * If client_key == 1, REGISTER is followed by CLIENT_KEY
 * Returns 1 if at least one client responded, 0 if none responded
 */
int announce_phase(struct finfo_t *finfo)
{
    time_t endtime;
    int attempt, resend, announce, regconf, keyinfo, fileinfo, open, anyerror;
    int len, rval, rcv_status, last_pass, gotall, gotone, allreg, regdone, i;
    unsigned char *packet, *decrypted;
    struct uftp_h *header;
    struct timeval timeout;
    struct sockaddr_in receiver;

    if (finfo->file_id) {
        log(0, 0, "File ID: %04X  Name: %s", finfo->file_id, finfo->filename);
        switch (finfo->ftype) {
        case FTYPE_REG:
            log(0, 0, "Bytes: %s  Blocks: %d  Sections: %d", 
                       printll(finfo->size), finfo->blocks, finfo->sections);
            break;
        case FTYPE_DIR:
            log(0, 0, "Empty directory");
            break;
        case FTYPE_LINK:
            log(0, 0, "Symbolic link to %s", finfo->linkname);
            break;
        }
    } else {
        log(0, 0, "Initializing group");
    }

    rval = 1;
    packet = calloc(mtu, 1);
    decrypted = calloc(mtu, 1);
    if ((packet == NULL) || (decrypted == NULL)) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)packet;
    endtime = time(NULL) + announce_time;
    announce = (finfo->file_id == 0);
    regconf = (announce && (keytype == KEY_NONE));
    keyinfo = (announce && (keytype != KEY_NONE));
    fileinfo = (finfo->file_id != 0);
    open = (destcount == 0);
    for (i = 0; i < destcount; i++) {
        // At start of group, initialize all clients/proxies to DEST_MUTE.
        // At start of file, initialize proxies to DEST_ACTIVE (since they
        // don't respond directly to a FILEINFO) and clients to DEST_REGISTERED.
        if (announce) {
            destlist[i].status = DEST_MUTE;
        } else if (!client_error(i)) {
            if (destlist[i].clientcnt != -1) {
                destlist[i].status = DEST_ACTIVE;
            } else {
                destlist[i].status = DEST_REGISTERED;
            }
        }
    }

    timeout.tv_sec = announce_int / 1000;
    timeout.tv_usec = (announce_int % 1000) * 1000;
    resend = 1;
    attempt = 1;
    last_pass = 0;
    regdone = 0;
    while (time(NULL) < endtime) {
        // On the initial pass, or when the announce timeout trips,
        // send any necessary messages.
        if (resend) {
            if (keyinfo && !send_keyinfo(finfo, attempt)) {
                continue;
            }
            if (announce && !send_regconf(finfo, attempt, regconf)) {
                continue;
            }
            if (fileinfo && !send_fileinfo(finfo, attempt)) {
                continue;
            }
            if (announce && !send_announce(finfo, attempt, open)) {
                continue;
            }
            resend = 0;
        }
        // TODO: Currently, the interval between sends is really an inactivity
        // timer, not the actual time between sends.  We might want to change
        // it to that, and perhaps add an extra "overage" timer in case we're
        // still processing responses when we're due to resend, that way we'll
        // always wait some minimum amount of time.
        if ((rcv_status = read_packet(sock, &receiver, packet, &len,
                                      mtu, &timeout)) == -1) {
            continue;
        } else if (rcv_status == 0) {
            attempt++;
            resend = 1;
            if (last_pass) break;
            continue;
        }
        if (!validate_packet(packet, len, finfo)) {
            continue;
        }

        if (!handle_announce_phase(packet, decrypted, &receiver, finfo,
                                   announce, open, regconf)) {
            continue;
        }
        if (!open) {
            for (i = 0, gotall = 1, allreg = 1;
                    (i < destcount) && (gotall || allreg); i++) {
                if (announce) {
                    gotall = gotall && ((destlist[i].status == DEST_ACTIVE) ||
                                        (destlist[i].status == DEST_ABORT));
                    allreg = allreg && ((destlist[i].status == DEST_ACTIVE) ||
                                (destlist[i].status == DEST_REGISTERED) ||
                                (destlist[i].status == DEST_ABORT));
                } else {
                    gotall = gotall && ((destlist[i].status == DEST_ACTIVE) ||
                                        (destlist[i].status == DEST_DONE) ||
                                        (client_error(i)));
                }
            }
            if (gotall) {
                // Break out right away if this is a file registration.
                // For group registration, do one last wait, even if 
                // encryption is enabled since we can still send a
                // REG_CONF for a client behind a proxy.
                // Change the wait interval to the client's register_int * 1.5
                // to allow for late registers.
                // Be careful not to overrun the phase timeout!
                if (finfo->file_id != 0) break;
                timeout.tv_sec = (int)(register_int / 1000 * 1.5);
                timeout.tv_usec = (int)((register_int % 1000) * 1000 * 1.5);
                if (timeout.tv_sec > endtime) {
#ifdef WINDOWS
                    timeout.tv_sec = (long)endtime;
#else
                    timeout.tv_sec = endtime;
#endif
                    timeout.tv_usec = 0;
                }
                if (!last_pass) {
                    log(0, 0, "Late registers:");
                }
                last_pass = 1;
                send_regconf(finfo, attempt + 1, regconf);
            } else if (announce && allreg && !regdone) {
                // All have registered, so don't wait to send the next message
                resend = 1;
                regdone = 1;
            }
        }
    }
    for (i = 0, gotone = 0, anyerror = 0; i < destcount; i++) {
        gotone = gotone || (((destlist[i].status == DEST_ACTIVE) || 
                             (destlist[i].status == DEST_DONE)) && 
                            (destlist[i].clientcnt == -1));
        if (destlist[i].status == DEST_REGISTERED) {
            log(0, 0, "Couldn't get INFO_ACK from %s", destlist[i].name);
            destlist[i].status = DEST_LOST;
            anyerror = 1;
        }
        if ((destlist[i].status == DEST_MUTE) ||
                (destlist[i].status == DEST_ABORT)) {
            anyerror = 1;
        }
    }
    if (anyerror && quit_on_error) {
        log(0, 0, "Aboring all clients");
        send_abort(finfo, "A client dropped out, aborting all",
                &receive_dest, NULL, (keytype != KEY_NONE));
        for (i = 0; i < destcount; i++) {
            if (destlist[i].status == DEST_ACTIVE) {
                destlist[i].status = DEST_ABORT;
            }
        }
        rval = 0;
    }
    if (!gotone) {
        log(0, 0, "Announce timed out");
        rval = 0;
    }
    if (open) {
        send_regconf(finfo, attempt, regconf);
    }
    free(packet);
    free(decrypted);
    return rval;
}

/**
 * Check a transfer phase message and pass to appropriate message handler,
 * decrypting first if necessary
 * Returns 1 on success, 0 on error
 */
int handle_transfer_phase(const unsigned char *packet, unsigned char *decrypted,
                          const struct sockaddr_in *receiver,
                          int blocks_this_sec, int section_offset,
                          int pass, int section, struct finfo_t *finfo)
{
    struct uftp_h *header;
    const unsigned char *message;
    int hostidx;
    unsigned int decryptlen, meslen;
    uint8_t *func;
    struct in_addr srcaddr;

    header = (struct uftp_h *)packet;
    hostidx = find_client(header->srcaddr);
    srcaddr.s_addr = header->srcaddr;
    if ((keytype != KEY_NONE) && (header->func == ENCRYPTED)) {
        if (hostidx == -1) {
            log(0, 0, "Host %s not in host list", inet_ntoa(srcaddr));
            send_abort(finfo, "Not in host list", receiver, &srcaddr, 0);
            return 0;
        }
        if (!validate_and_decrypt(packet, &decrypted, &decryptlen, mtu,
                keytype, groupkey, groupsalt, ivlen, hashtype, grouphmackey,
                hmaclen, sigtype, destlist[hostidx].pubkey,
                destlist[hostidx].pubkeylen)) {
            log(0, 0, "Rejecting message from %s: decrypt/validate failed",
                       destlist[hostidx].name);
            return 0;
        }
        func = (uint8_t *)decrypted;
        message = decrypted;
        meslen = decryptlen;
    } else {
        if ((keytype != KEY_NONE) && ((header->func == PRSTATUS) ||
                (header->func == STATUS) || (header->func == COMPLETE) ||
                (header->func == ABORT))) {
            log(0, 0, "Rejecting %s message from %s: not encrypted",
                      func_name(header->func), inet_ntoa(srcaddr));
            return 0;
        }
        func = (uint8_t *)&header->func;
        message = packet + sizeof(struct uftp_h);
        meslen = ntohs(header->blsize);
    }

    if (*func == ABORT) {
        handle_abort(message, meslen, hostidx, finfo, &srcaddr);
    } else if (hostidx == -1) {
        log(0, 0, "Host %s not in host list", inet_ntoa(srcaddr));
        send_abort(finfo, "Not in host list", receiver, &srcaddr, 0);
    } else {
        switch (destlist[hostidx].status) {
        case DEST_ACTIVE:
            if (*func == STATUS) {
                handle_status(message, meslen, finfo, hostidx,
                        blocks_this_sec, section_offset, pass, section);
            } else if (*func == COMPLETE) {
                handle_complete(message, meslen, finfo, hostidx);
            } else if ((destlist[hostidx].clientcnt != -1) &&
                       (*func == PRSTATUS)) {
                handle_prstatus(message, meslen, finfo, hostidx,
                        blocks_this_sec, section_offset, pass, section);
            } else {
                log(0, 0, "Received invalid message %s from %s",
                           func_name(*func), destlist[hostidx].name);
            }
            break;
        case DEST_STATUS:
            if (*func == COMPLETE) {
                handle_complete(message, meslen, finfo, hostidx);
            } else if (*func == STATUS) {
                handle_status(message, meslen, finfo, hostidx,
                              blocks_this_sec, section_offset, pass, section);
            } else {
                log(0, 0, "Received invalid message %s from %s",
                           func_name(*func), destlist[hostidx].name);
            }
            break;
        case DEST_DONE:
            if (*func == COMPLETE) {
                handle_complete(message, meslen, finfo, hostidx);
            } else {
                log(0, 0, "Received invalid message %s from %s",
                           func_name(*func), destlist[hostidx].name);
            }
            break;
        }
    }
    return 1;
}
/**
 * Request NAKs from all clients.
 * Returns the aggregate number of NAKs for the section.
 */
int get_naks(struct finfo_t *finfo, unsigned int pass, unsigned int section,
             int *alldone)
{
    unsigned char *packet, *decrypted;
    struct uftp_h *header;
    struct timeval timeout;
    struct sockaddr_in receiver;
    int resend, attempt, last_pass, gotall, anyerror;
    int blocks_this_sec, section_offset;
    int rcv_status, len, nakidx, numnaks, i, j;
    time_t endtime;

    packet = calloc(mtu, 1);
    decrypted = calloc(mtu, 1);
    if ((packet == NULL) || (decrypted == NULL)) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)packet;

    section_offset = (blocksize * 8) * (section - 1);
    blocks_this_sec = ((section < finfo->sections) ? (blocksize * 8) :
                            (finfo->blocks % (blocksize * 8)));
    if (finfo->sections && !blocks_this_sec) blocks_this_sec = blocksize * 8;
    for (i = 0; i < blocks_this_sec; i++) {
        nakidx = i + section_offset;
        finfo->naklist[nakidx] = 0;
    }

    for (i = 0; i < destcount; i++) {
        if (client_error(i)) {
            continue;
        }
        if (destlist[i].clientcnt != -1) {
            destlist[i].status = DEST_ACTIVE;
        } else if (destlist[i].status == DEST_ACTIVE) {
            destlist[i].status = DEST_STATUS;
        }
        free(destlist[i].last_status);
        destlist[i].last_status = NULL;
        for (j = 0; j < destlist[i].last_prstatus_cnt; j++) {
            free(destlist[i].last_prstatus[j]);
            destlist[i].last_prstatus[j] = NULL;
        }
        destlist[i].last_prstatus_cnt = 0;
    }

    endtime = time(NULL) + status_time;
    timeout.tv_sec = status_int / 1000;
    timeout.tv_usec = (status_int % 1000) * 1000;
    resend = 1;
    attempt = 1;
    gotall = 0;
    last_pass = 0;
    while ((time(NULL) < endtime) && (!gotall)) {
        if (resend) {
            if (!send_doneconf(finfo, attempt)) {
                continue;
            }
            if (!send_done(finfo, attempt, pass, section)) {
                continue;
            }
            resend = 0;
        }
        // See comments in announce_phase regarding timing
        if ((rcv_status = read_packet(sock, &receiver, packet, &len,
                                      mtu, &timeout)) == -1) {
            continue;
        } else if (rcv_status == 0) {
            attempt++;
            resend = 1;
            if (last_pass) break;
            continue;
        }
        if (!validate_packet(packet, len, finfo)) {
            continue;
        }

        if (!handle_transfer_phase(packet, decrypted, &receiver,
                blocks_this_sec, section_offset, pass, section, finfo)) {
            continue;
        }
        for (i = 0, gotall = 1, *alldone = 1;
                (i < destcount) && (gotall || *alldone); i++) {
            gotall = gotall && (destlist[i].status != DEST_STATUS);
            *alldone = *alldone && ((destlist[i].status == DEST_DONE) ||
                            (client_error(i)) || (destlist[i].clientcnt != -1));
        }
        if (*alldone) {
            if (finfo->file_id != 0) break;
            // Change the wait interval to the client's done_int * 1.5
            // to allow for late completions
            timeout.tv_sec = (int)(done_int / 1000 * 1.5);
            timeout.tv_usec = (int)((done_int % 1000) * 1000 * 1.5);
            if (!last_pass) {
                log(0, 0, "Late completions:");
            }
            last_pass = 1;
            gotall = 0;
            send_doneconf(finfo, attempt + 1);
        } 
    }

    anyerror = 0;
    if (*alldone) {
        send_doneconf(finfo, attempt + 1);
    } else if (!gotall) {
        for (i = 0, *alldone = 1; i < destcount; i++) {
            if (destlist[i].status == DEST_STATUS) {
                log(0, 0, "Couldn't get STATUS from %s", destlist[i].name);
                destlist[i].status = DEST_LOST;
                anyerror = 1;
            }
            *alldone = *alldone && ((destlist[i].status == DEST_DONE) ||
                            (client_error(i)) || (destlist[i].clientcnt != -1));
        }
    }
    if (anyerror && quit_on_error) {
        log(0, 0, "Aboring all clients");
        send_abort(finfo, "A client dropped out, aborting all",
                &receive_dest, NULL, (keytype != KEY_NONE));
        for (i = 0; i < destcount; i++) {
            if (destlist[i].status == DEST_ACTIVE) {
                destlist[i].status = DEST_ABORT;
            }
        }
        *alldone = 1;
    }

    for (i = 0, numnaks = 0; i < blocks_this_sec; i++) {
        nakidx = i + section_offset;
        if (finfo->naklist[nakidx]) {
            numnaks++;
        }
    }

    free(packet);
    free(decrypted);
    return numnaks;
}

/**
 * Seeks to a particular block in a file
 * Returns 1 on success, 0 on error
 */
int seek_block(int file, int block, f_offset_t *offset, f_offset_t curr_offset)
{
    if ((*offset = lseek_func(file, 
            ((f_offset_t)block * blocksize) - curr_offset, SEEK_CUR)) == -1) {
        syserror(0, 0, "lseek failed for file");
        return 0;
    }
    if (*offset != (f_offset_t)block * blocksize) {
        log(0, 0, "block %d: offset is %s", block, printll(*offset));
        log(0, 0, "  should be %s", printll((f_offset_t)block * blocksize));
        if ((*offset = lseek_func(file, 
                ((f_offset_t)block * blocksize) - (*offset), SEEK_CUR)) == -1) {
            syserror(0, 0, "lseek failed for file");
            return 0;
        }
    }
    return 1;
}

/**
 * Performs the Transfer phase for a particular file
 * Returns 1 if at least one client finished, 0 if all are dropped or aborted
 */
int transfer_phase(struct finfo_t *finfo)
{
    unsigned char *packet, *encpacket, *data;
    char path[MAXPATHNAME];
    struct uftp_h *header;
    struct fileseg_h *fileseg;
    int max_time, alldone, numbytes;
    unsigned int pass, section, numnaks, naksthissec, block;
    struct timeval start_time, last_sent, current_sent;
    int64_t avgwait, waitcnt, overage, tdiff;
    f_offset_t offset, curr_offset;
    int file, i;

    if (finfo->file_id != 0) {
        // First check to see if all clients are already done for this file.
        // This can happen on a restart when the file finished on the
        // last attempt and responded to the FILEINFO with a COMPLETE
        for (i = 0, alldone = 1; (i < destcount) && alldone; i++) {
            alldone = alldone && ((destlist[i].status == DEST_DONE) ||
                        (client_error(i)) || (destlist[i].clientcnt != -1));
        }
        if (alldone) {
            return 1;
        }
    }

    // If rate is -1, use 100Mbps for purpose of calculating max time
    max_time = (int)floor(((double)weight / 100) *
           ((double)finfo->size / (((rate == -1) ? 100000 : rate) / 8) / 1024));
    if (max_time < min_time) {
        max_time = min_time;
    }

    if ((finfo->file_id != 0) && (finfo->ftype == FTYPE_REG)) {
        log(0, 0, "Maximum file transfer time: %d seconds", max_time);
        snprintf(path, sizeof(path), "%s%c%s", finfo->basedir, PATH_SEP,
                                               finfo->filename);
        if ((file = open(path, OPENREAD, 0)) == -1) {
            syserror(0, 0, "Error opening file");
            return 1;
        }
    } else {
        // At end of group, all non-errored client are DEST_DONE from the
        // last file, so reset them to DEST_ACTIVE to get the final COMPLETE.
        for (i = 0; i < destcount; i++) {
            if (!client_error(i)) {
                destlist[i].status = DEST_ACTIVE;
            }
        }
    }

    packet = calloc(mtu, 1);
    encpacket = calloc(mtu, 1);
    if ((packet == NULL) || (encpacket == NULL)) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)packet;
    fileseg = (struct fileseg_h *)(packet + sizeof(struct uftp_h));
    data = (unsigned char *)fileseg + sizeof(struct fileseg_h);
    set_uftp_header(header, FILESEG, finfo, &receive_dest);    

    pass = 1;
    alldone = 0;
    gettimeofday(&start_time, NULL);
    do {
        avgwait = 0;
        waitcnt = 0;
        numnaks = 0;
        overage = 0;
        section = 1;
        naksthissec = 0;
        curr_offset = 0;

        gettimeofday(&last_sent, NULL);
        if (finfo->file_id != 0) {
            log(0, 0, "Sending file...pass %d", pass);
            lseek_func(file, 0, SEEK_SET);
        } else {
            log(0, 0, "Finishing group");
        }
        fileseg->func = FILESEG;
        fileseg->file_id = htons(finfo->file_id);
        fileseg->pass = pass;
        fileseg->section = htons(section);
        for (block = 0; block < finfo->blocks; block++) {
            // If all clients received this file partially on a prior attempt
            // and it's the first pass, request NAKs for all sections
            // right away and don't send any data packets.
            if (((pass == 1) || finfo->naklist[block]) &&
                    !((pass == 1) && finfo->partial)) {
                naksthissec = 1;
                if (diff_sec(last_sent, start_time) > max_time) {
                    log(0, 0, "Max file transfer time exceeded");
                    send_abort(finfo, "Max file transfer time exceeded",
                            &receive_dest, NULL, (keytype != KEY_NONE));
                    alldone = 1;
                    for (i = 0; i < destcount; i++) {
                        if (destlist[i].status == DEST_ACTIVE) {
                            destlist[i].status = DEST_ABORT;
                        }
                    }
                    break;
                }
                // On the first pass, go straight through the file.
                // On later passes, seek to the next packet.
                if (pass != 1) {
                    if (verbose >= 2) {
                        log(0, 0, "Resending %d", block);
                    }
                    if (!seek_block(file, block, &offset, curr_offset)) {
                        continue;
                    }
                }
                if ((numbytes = read(file, data, blocksize)) == -1) {
                    syserror(0, 0, "read failed");
                    continue;
                }
                if (pass != 1) {
                    curr_offset = offset + numbytes;
                }

                // Keep track of how long we really slept compared to how
                // long we expected to sleep.  If we went over, subtract the
                // time over from the next sleep time.  This way we maintain
                // the proper average sleep time.  This can result in multiple
                // packets going out at once, potentially losing packets.
                if (packet_wait > overage) {
                    usleep(packet_wait - (int32_t)overage);
                }
                gettimeofday(&current_sent, NULL);
                tdiff = diff_usec(current_sent, last_sent);
                avgwait += tdiff;
                waitcnt++;
                if (packet_wait) overage += tdiff - packet_wait;
                last_sent = current_sent;

                fileseg->seq_num = htonl(block);
                send_data(finfo, packet, numbytes, encpacket);
            }
            if ((block % (blocksize * 8) == (blocksize * 8) - 1) ||
                    (block == finfo->blocks - 1)) {
                if ((pass == 1) || naksthissec) {
                    numnaks += get_naks(finfo, pass, section, &alldone);
                    if (alldone) break;
                }
                naksthissec = 0;
                gettimeofday(&last_sent, NULL);
                fileseg->section = htons(++section);
            }
        }
        if ((finfo->size == 0) && !alldone) {
            // If it's the end of the group, or an empty file, a DONE was
            // never sent, so send it now
            numnaks += get_naks(finfo, pass, section, &alldone);
        }
        if (finfo->file_id != 0) {
            log(0, 0, "Average wait time = %.2f us",
                       (waitcnt == 0) ? 0 : (float)avgwait / waitcnt);
            log(0, 0, "Received %d distinct NAKs for pass %d", numnaks, pass);
        }
        pass++;
    } while (!alldone);

    if ((finfo->file_id != 0) && (finfo->ftype == FTYPE_REG)) {
        close(file);
    }
    print_status(finfo, start_time);

    free(packet);
    free(encpacket);

    for (i = 0; i < destcount; i++) {
        if (quit_on_error) {
            // Check to see that all finished
            if (destlist[i].status != DEST_DONE) {
                return 0;
            }
        } else {
            // Check to see if at least one finished
            if (destlist[i].status == DEST_DONE) {
                return 1;
            }
        }
    }
    if (quit_on_error) {
        return 1;
    } else {
        return 0;
    }
}

