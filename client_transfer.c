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
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef WINDOWS

#include <io.h>
#include <direct.h>

#include "win_func.h"

#else  // if WINDOWS

#include <unistd.h>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#endif

#include "client.h"
#include "client_common.h"
#include "client_transfer.h"

/**
 * Move all files from temp to destination directory if at end of group
 * TODO: add option to move files one at a time?
 */
void move_files(int listidx)
{
    char temppath[MAXPATHNAME], destpath[MAXPATHNAME];
    int len;

    if (!strcmp(tempdir, "") || (group_list[listidx].file_id != 0)) {
        return;
    }

    {
#ifdef WINDOWS
        intptr_t ffhandle;
        struct _finddatai64_t finfo;
        char dirglob[MAXPATHNAME];

        snprintf(dirglob, sizeof(dirglob), "%s%c_group_%08X%c*", tempdir,
                 PATH_SEP, group_list[listidx].group_id, PATH_SEP);
        if ((ffhandle = _findfirsti64(dirglob, &finfo)) == -1) {
            syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                     "Failed to open directory %s", dirglob);
            return;
        }
        do {
            len = snprintf(temppath, sizeof(temppath), "%s%c_group_%08X%c%s",
                           tempdir, PATH_SEP, group_list[listidx].group_id,
                           PATH_SEP, finfo.name);
            if ((len >= sizeof(temppath)) || (len == -1)) {
                log(group_list[listidx].group_id, group_list[listidx].file_id,
                        "Max pathname length exceeded: %s%c_group_%08X%c%s",
                        tempdir, PATH_SEP, group_list[listidx].group_id,
                        PATH_SEP, finfo.name);
                continue;
            }
            len = snprintf(destpath, sizeof(destpath), "%s%c%s",
                           destdir, PATH_SEP, finfo.name);
            if ((len >= sizeof(destpath)) || (len == -1)) {
                log(group_list[listidx].group_id, group_list[listidx].file_id,
                        "Max pathname length exceeded: %s%c%s",
                        destdir, PATH_SEP, finfo.name);
                continue;
            }
            // do the move
            if (strcmp(finfo.name, ".") && strcmp(finfo.name, "..")) {
                clear_path(destpath, listidx);
                if (!MoveFile(temppath, destpath)) {
                    char errbuf[300];
                    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
                            GetLastError(), 0, errbuf, sizeof(errbuf), NULL);
                    log(group_list[listidx].group_id,
                            group_list[listidx].file_id,
                            "error (%d): %s", GetLastError(), errbuf);
                }
            }
        } while (_findnexti64(ffhandle, &finfo) == 0);
        _findclose(ffhandle);
#else
        DIR *dir;
        struct dirent *de;
        char dirname[MAXPATHNAME];

        snprintf(dirname, sizeof(dirname), "%s%c_group_%08X", tempdir,
                 PATH_SEP, group_list[listidx].group_id);
        if ((dir = opendir(dirname)) == NULL) {
            syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                     "Failed to open directory %s", dirname);
            return;
        }
        // errno needs to be set to 0 before calling readdir, otherwise
        // we'll report a false error when we exhaust the directory
        while ((errno = 0, de = readdir(dir)) != NULL) {
            len = snprintf(temppath, sizeof(temppath), "%s%c%s", dirname,
                           PATH_SEP, de->d_name);
            if ((len >= sizeof(temppath)) || (len == -1)) {
                log(group_list[listidx].group_id, group_list[listidx].file_id,
                        "Max pathname length exceeded: %s%c%s", dirname,
                        PATH_SEP, de->d_name);
                continue;
            }
            len = snprintf(destpath, sizeof(destpath), "%s%c%s", destdir,
                           PATH_SEP, de->d_name);
            if ((len >= sizeof(destpath)) || (len == -1)) {
                log(group_list[listidx].group_id, group_list[listidx].file_id,
                        "Max pathname length exceeded: %s%c%s", destdir,
                        PATH_SEP, de->d_name);
                continue;
            }
            if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
                clear_path(destpath, listidx);
                if (rename(temppath, destpath) == -1) {
                    syserror(group_list[listidx].group_id,
                             group_list[listidx].file_id, "Couldn't move file");
                }
            }
        }
        if (errno && (errno != ENOENT)) {
            syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                     "Failed to read directory %s", dirname);
        }
        closedir(dir);
#endif
    }
    snprintf(temppath, sizeof(temppath), "%s%c_group_%08X", tempdir,
             PATH_SEP, group_list[listidx].group_id);
    if (rmdir(temppath) == -1) {
        syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                 "Failed remove temp directory %s", temppath);
    }
}

/**
 * Sends back a STATUS message with the given NAK list
 */
void send_status(int listidx, unsigned int pass, unsigned int section,
                 const unsigned char *naks, unsigned int nak_count)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct status_h *status;
    struct uftp2_h *v2_header;
    unsigned char *sent_naks;
    int payloadlen;

    buf = calloc(group_list[listidx].mtu, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    if (group_list[listidx].version == UFTP_V2_VER) {
        v2_header = (struct uftp2_h *)buf;
        v2_header->uftp_id = htonl(V2_UFTP_ID);
        v2_header->func = htonl(V2_STATUS);
        v2_header->tx_id = htonl(group_list[listidx].group_id);
        v2_header->nak_count = htonl(nak_count);
        v2_header->section_num = htonl(section);
        v2_header->pass = htonl(pass);
        v2_header->blsize = (nak_count ? htonl(V2_BLOCKSIZE) : 0);
        payloadlen = sizeof(struct uftp2_h) + ntohl(v2_header->blsize);
        if (nak_count) {
            sent_naks = buf + sizeof(struct uftp2_h);
            memcpy(sent_naks, naks, V2_BLOCKSIZE);
        }
        encrypted = NULL;
        outpacket = buf;
    } else {
        header = (struct uftp_h *)buf;
        status = (struct status_h *)(buf + sizeof(struct uftp_h));

        set_uftp_header(header, STATUS, listidx);
        status->func = STATUS;
        status->file_id = htons(group_list[listidx].file_id);
        status->pass = pass;
        status->seq = 0;
        status->section = htons(section);
        status->nak_count = htonl(nak_count);
        if (nak_count) {
            payloadlen = group_list[listidx].blocksize;
            sent_naks = (unsigned char *)status + sizeof(struct status_h);
            memcpy(sent_naks, naks, payloadlen);
        } else {
            payloadlen = 0;
        }

        payloadlen += sizeof(struct status_h);
        if ((group_list[listidx].phase != PHASE_REGISTERED) &&
                (group_list[listidx].keytype != KEY_NONE)) {
            encrypted = NULL;
            if (!encrypt_and_sign(buf, &encrypted, payloadlen,
                    group_list[listidx].mtu, group_list[listidx].keytype,
                    group_list[listidx].groupkey, group_list[listidx].groupsalt,
                    group_list[listidx].ivlen, group_list[listidx].hashtype,
                    group_list[listidx].grouphmackey,
                    group_list[listidx].hmaclen, group_list[listidx].sigtype,
                    group_list[listidx].clientkey,
                    group_list[listidx].client_keylen)) {
                log(group_list[listidx].group_id, group_list[listidx].file_id,
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
    }

    if (nb_sendto(listener, outpacket, payloadlen, 0,
               (struct sockaddr *)&group_list[listidx].replyaddr,
               sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id, group_list[listidx].file_id,
                "Error sending STATUS");
    } else {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Sent %d NAKs for pass %d section %d", nak_count,pass,section);
    }

    free(buf);
    free(encrypted);
}

/**
 * Sends back a COMPLETE message in response to a DONE or FILEINFO
 */
void send_complete(int listidx)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct complete_h *complete;
    struct uftp2_h *v2_header;
    int payloadlen;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    if ((group_list[listidx].phase == PHASE_COMPLETE) &&
            (diff_usec(group_list[listidx].expire_time, tv) <= 0)) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Completion unconfirmed by server");
        move_files(listidx);
        file_cleanup(listidx, 0);
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
        v2_header->func = htonl(V2_STATUS);
        v2_header->tx_id = htonl(group_list[listidx].group_id);
        v2_header->nak_count = htonl(-1);
        v2_header->blsize = 0;
        payloadlen = sizeof(struct uftp2_h);
        encrypted = NULL;
        outpacket = buf;
    } else {
        header = (struct uftp_h *)buf;
        complete = (struct complete_h *)(buf + sizeof(struct uftp_h));

        set_uftp_header(header, COMPLETE, listidx);
        complete->func = COMPLETE;
        complete->file_id = htons(group_list[listidx].file_id);
        complete->destcount = 0;

        payloadlen = sizeof(struct complete_h);
        if ((group_list[listidx].phase != PHASE_REGISTERED) &&
                (group_list[listidx].keytype != KEY_NONE)) {
            encrypted = NULL;
            if (!encrypt_and_sign(buf, &encrypted, payloadlen,
                    group_list[listidx].mtu, group_list[listidx].keytype,
                    group_list[listidx].groupkey, group_list[listidx].groupsalt,
                    group_list[listidx].ivlen, group_list[listidx].hashtype,
                    group_list[listidx].grouphmackey,
                    group_list[listidx].hmaclen, group_list[listidx].sigtype,
                    group_list[listidx].clientkey,
                    group_list[listidx].client_keylen)) {
                log(0, 0, "Error encrypting COMPLETE");
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
    }

    if (nb_sendto(listener, outpacket, payloadlen, 0,
               (struct sockaddr *)&group_list[listidx].replyaddr,
               sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id, group_list[listidx].file_id,
                "Error sending COMPLETE");
    } else {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "COMPLETE sent");
    }
    set_timeout(listidx);

    free(buf);
    free(encrypted);
}

/**
 * Reads an expected FILESEG and writes it to the proper place in the file
 */
void handle_fileseg(int listidx, const unsigned char *message, int meslen)
{
    struct uftp2_h *v2_header;
    struct fileseg_h *fileseg;
    const unsigned char *data;
    int datalen, pass, section, seq, wrote_len;
    f_offset_t offset, seek_rval;

    if (group_list[listidx].fileinfo.ftype != FTYPE_REG) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Rejecting FILESEG: not a regular file");
        return;
    }
    if (group_list[listidx].version == UFTP_V2_VER) {
        v2_header = (struct uftp2_h *)message;
        data = message + sizeof(struct uftp2_h);
        datalen = ntohl(v2_header->blsize);
        pass = ntohl(v2_header->pass);
        section = ntohl(v2_header->section_num);
        seq = ntohl(v2_header->seq_num);
    } else {
        fileseg = (struct fileseg_h *)message;
        data = message + sizeof(struct fileseg_h);
        datalen = meslen - sizeof(struct fileseg_h);
        pass = fileseg->pass;
        section = ntohs(fileseg->section);
        seq = ntohl(fileseg->seq_num);
        if (ntohs(fileseg->file_id) != group_list[listidx].file_id) {
            log(group_list[listidx].group_id, group_list[listidx].file_id,
                    "Rejecting FILESEG: got incorrect file_id %04X",
                    ntohs(fileseg->file_id));
            return;
        }
    }

    if ((datalen != group_list[listidx].blocksize) &&
            (seq != group_list[listidx].fileinfo.blocks - 1)) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Rejecting FILESEG: invalid message size %d", datalen);
        return;
    }
    if (verbose >= 2) {
        if (pass != 1) {
            log(group_list[listidx].group_id, group_list[listidx].file_id,
                    "Got packet %d", seq);
        }
    } else if (verbose == 1) {
        if (seq != group_list[listidx].fileinfo.last_block + 1) {
            log(group_list[listidx].group_id, group_list[listidx].file_id,
                    "Got packet %d, last was %d",
                    seq, group_list[listidx].fileinfo.last_block);
        }
        group_list[listidx].fileinfo.last_block = seq;
    }
    offset = (f_offset_t) seq * group_list[listidx].blocksize;
    if ((seek_rval = lseek_func(group_list[listidx].fileinfo.fd,
            offset - group_list[listidx].fileinfo.curr_offset,
            SEEK_CUR)) == -1) {
        syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                 "lseek failed for file");
    }
    if (seek_rval != offset) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "offset is %s", printll(seek_rval));
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "  should be %s", printll(offset));
        if ((seek_rval = lseek_func(group_list[listidx].fileinfo.fd,
                seek_rval - group_list[listidx].fileinfo.curr_offset,
                SEEK_CUR)) == -1) {
            syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                     "lseek failed for file");
            return;
        }

    }
    if ((wrote_len = write(group_list[listidx].fileinfo.fd,
                           data, datalen)) == -1) {
        syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                "Write failed for segment %d", seq);
    }
    group_list[listidx].fileinfo.curr_offset = offset + wrote_len;
    if (wrote_len != datalen) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Write failed for segment %d, only wrote %d bytes",
                seq, wrote_len);
    }
    group_list[listidx].fileinfo.naklist[seq] = 0;
    set_timeout(listidx);
}

/**
 * Returns 1 if a file has been completely received, 0 otherwise
 */
int file_done(int listidx, int section)
{
    unsigned int i;

    if ((group_list[listidx].version == UFTP_V2_VER) &&
            (section != group_list[listidx].fileinfo.sections)) {
        // For version 2, don't check until the DONE for the last section
        return 0;
    }
    if ((group_list[listidx].version != UFTP_V2_VER) &&
            ((group_list[listidx].phase == PHASE_MIDGROUP) ||
            (group_list[listidx].file_id == 0))) {
        return 1;
    }
    for (i = 0; i < group_list[listidx].fileinfo.sections; i++) {
        if (!group_list[listidx].fileinfo.section_done[i]) {
            return 0;
        }
    }
    return 1;
}

/**
 * Build the NAK list for a given pass and section.  Returns the NAK count.
 */
int get_naks(int listidx, unsigned int pass, unsigned int section,
             unsigned char **naks)
{
    unsigned int section_offset, blocks_this_sec, i;
    int nakidx, naklistidx, numnaks;
    
    if ((group_list[listidx].version != UFTP_V2_VER) &&
            ((group_list[listidx].phase == PHASE_MIDGROUP) ||
            (group_list[listidx].file_id == 0))) {
        *naks = NULL;
        return 0;
    }

    section_offset = (group_list[listidx].blocksize * 8) * (section - 1);
    blocks_this_sec = ((section < group_list[listidx].fileinfo.sections) ?
            (group_list[listidx].blocksize * 8) :
            (group_list[listidx].fileinfo.blocks %
                (group_list[listidx].blocksize * 8)));
    if (group_list[listidx].fileinfo.sections && !blocks_this_sec) {
        blocks_this_sec = group_list[listidx].blocksize * 8;
    }

    *naks = calloc(group_list[listidx].blocksize, 1);
    if (*naks == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    // Build NAK list
    numnaks = 0;
    for (i = 0; i < blocks_this_sec; i++) {
        nakidx = i + section_offset;
        naklistidx = i;
        if (group_list[listidx].fileinfo.naklist[nakidx]) {
            if (verbose >= 2) {
                log(group_list[listidx].group_id, group_list[listidx].file_id,
                        "NAK for %d", nakidx);
            }
            // Each bit represents a NAK; set each one we have a NAK for
            // Simplified: *naks[naklistidx / 8] |= (1 << (naklistidx % 8))
            (*naks)[naklistidx >> 3] |= (1 << (naklistidx & 7));
            numnaks++;
        }
    }

    // Highly verbose debugging -- print NAK list to send
    if (verbose >= 3) {
        for (i = 0; i < group_list[listidx].blocksize; i++) {
            sclog("%02X ", (*naks)[i]);
            if (i % 25 == 24) slog("");
        }
        slog("");
    }

    if (numnaks == 0) {
        group_list[listidx].fileinfo.section_done[section - 1] = 1;
    }
    return numnaks;
}

/**
 * Processes an expected DONE message
 */
void handle_done(int listidx, const unsigned char *message, int meslen)
{
    struct uftp2_h *v2_header;
    struct statusinfo2 *v2_statusinfo;
    struct done_h *done;
    uint32_t *addrlist;
    unsigned char *naks;
    unsigned int pass, section, listlen, nak_count, n_index;

    if (group_list[listidx].version == UFTP_V2_VER) {
        v2_header = (struct uftp2_h *)message;
        v2_statusinfo = (struct statusinfo2 *)(message + sizeof(struct uftp2_h));
        pass = ntohl(v2_header->pass);
        section = ntohl(v2_header->section_num);
        addrlist = v2_statusinfo->addr_list;
        listlen = V2_MAXINFODEST;
    } else {
        done = (struct done_h *)message;
        addrlist = (uint32_t *)((char *)done + sizeof(struct done_h));
        pass = done->pass;
        section = ntohs(done->section);
        listlen = ntohs(done->destcount);
        if ((ntohs(done->file_id) != group_list[listidx].file_id) &&
                (ntohs(done->file_id) != 0)) {
            // Silently reject if not for this file and not end of group
            return;
        }
        if (meslen != (sizeof(struct done_h) + 
                       ntohs(done->destcount) * sizeof(uint32_t))) {
            log(group_list[listidx].group_id, group_list[listidx].file_id,
                    "Rejecting DONE: invalid message size");
            return;
        }
        if (ntohs(done->file_id) == 0) {
            // We're at end of group, so set local file_id=0 to flag this
            group_list[listidx].file_id = 0;
        }
    }

    log(group_list[listidx].group_id, group_list[listidx].file_id,
            "Got DONE message for pass %d section %d", pass, section);
    if (addr_in_list(listidx, addrlist, listlen)) {
        nak_count = get_naks(listidx, pass, section, &naks);
        if (file_done(listidx, section)) {
            if (group_list[listidx].file_id != 0) {
                log(group_list[listidx].group_id, group_list[listidx].file_id,
                        "File transfer complete");
                file_cleanup(listidx, 0);
            } else {
                log(group_list[listidx].group_id, 0, "Group complete");
                group_list[listidx].phase = PHASE_COMPLETE;
                gettimeofday(&group_list[listidx].expire_time, NULL);
                group_list[listidx].expire_time.tv_sec +=
                        group_list[listidx].status_time;
            }
            send_complete(listidx);
        } else {
            if (!group_list[listidx].fileinfo.wait && (nak_count == 1)) {
                // Check to see if we're missing only the last packet in the
                // section.  If so, wait for the next DONE message in case the
                // DONE and last data packet were swapped on the way in.  If
                // we're still missing the last packet, then send the STATUS.
                if (section == group_list[listidx].fileinfo.sections) {
                    n_index = group_list[listidx].fileinfo.blocks - 1;
                } else {
                    n_index = (group_list[listidx].blocksize * 8 * section) - 1;
                }
                if (group_list[listidx].fileinfo.naklist[n_index]) {
                    log(group_list[listidx].group_id,
                            group_list[listidx].file_id,
                            "Waiting for last packet in section...");
                    group_list[listidx].fileinfo.wait = 1;
                }
            } else {
                group_list[listidx].fileinfo.wait = 0;
            }
            if (!group_list[listidx].fileinfo.wait) {
                send_status(listidx, pass, section, naks, nak_count);
            }
        }
        free(naks);
    }
    set_timeout(listidx);
}

/**
 * Processes an expected DONE_CONF message
 */
void handle_done_conf(int listidx, const unsigned char *message, int meslen)
{
    struct uftp2_h *v2_header;
    struct statusinfo2 *v2_statusinfo;
    struct doneconf_h *doneconf;
    uint32_t *addrlist;
    int listlen;

    if (group_list[listidx].version == UFTP_V2_VER) {
        v2_header = (struct uftp2_h *)message;
        v2_statusinfo = (struct statusinfo2 *)(message + sizeof(struct uftp2_h));
        addrlist = v2_statusinfo->addr_list;
        listlen = V2_MAXINFODEST;
    } else {
        doneconf = (struct doneconf_h *)message;
        addrlist = (uint32_t *)((char *)doneconf + sizeof(struct done_h));
        listlen = ntohs(doneconf->destcount);
        if (ntohs(doneconf->file_id) != group_list[listidx].file_id) {
            log(group_list[listidx].group_id, group_list[listidx].file_id,
                    "Rejecting DONE_CONF: got incorrect file_id %04X",
                    ntohs(doneconf->file_id));
            return;
        }
        if (meslen != (sizeof(struct doneconf_h) + 
                       ntohs(doneconf->destcount) * sizeof(uint32_t))) {
            log(group_list[listidx].group_id, group_list[listidx].file_id,
                    "Rejecting DONE_CONF: invalid message size");
            return;
        }
    }

    if (addr_in_list(listidx, addrlist, listlen)) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Group file transfer confirmed");
        move_files(listidx);
        file_cleanup(listidx, 0);
    }
}

