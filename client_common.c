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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef WINDOWS

#include <ws2tcpip.h>
#include <io.h>
#include <direct.h>

#include "win_func.h"

#else  // if WINDOWS

#include <dirent.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#endif

#include "client.h"
#include "client_common.h"

/**
 * Look for a given file in the global group list
 * Returns the file's index in the list, or -1 if not found
 */
int find_file(uint32_t group_id)
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
 * Looks for one of the local listening addresses in a list of addresses.
 * Returns the index in m_interface of the match, or -1 if no match
 */
int interface_in_list(uint32_t *addrlist, int size)
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
 * Looks for the group's matched destination address in a list of addresses.
 * Returns 1 if found, 0 if not found
 */
int addr_in_list(int listidx, uint32_t *addrlist, int size)
{
    int i, rval;

    if (group_list[listidx].destaddr.s_addr == 0) {
        rval = interface_in_list(addrlist, size);
        if (rval == -1) {
            return 0;
        } else {
            group_list[listidx].destaddr = m_interface[rval].addr;
            return 1;
        }
    }

    for (i = 0; i < size; i++) {
        if (addrlist[i] == 0) {
            return 0;
        }
        if (group_list[listidx].destaddr.s_addr == addrlist[i]) {
            return 1;
        }
    }
    return 0;
}

/**
 * Reads in the contents of the restart file.
 */
void read_restart_file(int listidx)
{
    struct client_restart_t *restart;
    char restart_name[MAXPATHNAME];
    int fd;

    // Don't bother if we're not using a temp directory.
    if (!strcmp(tempdir, "")) {
        return;
    }

    log(group_list[listidx].group_id, 0, "Reading restart file");
    snprintf(restart_name, sizeof(restart_name), "%s%c_group_%08X_restart",
             tempdir, PATH_SEP, group_list[listidx].group_id);
    if ((fd = open(restart_name, OPENREAD, 0644)) == -1) {
        syserror(group_list[listidx].group_id, 0,
                 "Failed to read restart file");
        return;
    }

    // Read header
    restart = calloc(sizeof(struct client_restart_t), 1);
    if (restart == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    if (file_read(fd, restart, sizeof(struct client_restart_t), 0) == -1) {
        log(group_list[listidx].group_id, 0,
                "Failed to read header for restart file");
        goto err1;
    }

    // Read NAK list
    if (restart->blocks) {
        restart->naklist = calloc(restart->blocks, 1);
        if (restart->naklist == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        if (file_read(fd, restart->naklist, restart->blocks, 0) == -1) {
            log(group_list[listidx].group_id, 0,
                    "Failed to read NAK list for restart file");
            goto err2;
        }
    }

    // Read section_done list
    if (restart->sections) {
        restart->section_done = calloc(restart->sections, 1);
        if (restart->section_done == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        if (file_read(fd, restart->section_done, restart->sections, 0) == -1) {
            log(group_list[listidx].group_id, 0,
                    "Failed to read section_done list for restart file");
            goto err3;
        }
    }
    close(fd);
    unlink(restart_name);
    group_list[listidx].restartinfo = restart;
    return;

err3:
    free(restart->section_done);
err2:
    free(restart->naklist);
err1:
    free(restart);
    close(fd);
}

/**
 * Save the state of a failed transfer so it can restarted later.
 */
void write_restart_file(int listidx)
{
    struct file_t *fileinfo;
    struct client_restart_t restart;
    char restart_name[MAXPATHNAME];
    int fd;

    // Don't bother if we're not using a temp directory.
    if (!strcmp(tempdir, "")) {
        return;
    }

    log(group_list[listidx].group_id, 0, "Writing restart file");
    memset(&restart, 0, sizeof(restart));
    fileinfo = &group_list[listidx].fileinfo;
    if (group_list[listidx].phase != PHASE_MIDGROUP) {
        restart.blocks = fileinfo->blocks;
        restart.sections = fileinfo->sections;
        restart.size = fileinfo->size;
        strcpy(restart.name, fileinfo->name);
    }

    snprintf(restart_name, sizeof(restart_name), "%s%c_group_%08X_restart",
             tempdir, PATH_SEP, group_list[listidx].group_id);
    if ((fd = open(restart_name, OPENWRITE | O_CREAT | O_TRUNC, 0644)) == -1) {
        syserror(group_list[listidx].group_id, 0,
                 "Failed to create restart file");
        return;
    }

    if (file_write(fd, &restart, sizeof(restart)) == -1) {
        log(group_list[listidx].group_id, 0,
                "Failed to write header for restart file");
        goto errexit;
    }
    if (fileinfo->blocks && fileinfo->naklist) {
        if (file_write(fd, fileinfo->naklist, fileinfo->blocks) == -1) {
            log(group_list[listidx].group_id, 0,
                    "Failed to write NAK list for restart file");
            goto errexit;
        }
    }
    if (fileinfo->sections && fileinfo->section_done) {
        if (file_write(fd, fileinfo->section_done, fileinfo->sections) == -1) {
            log(group_list[listidx].group_id, 0,
                    "Failed to write section_done list for restart file");
            goto errexit;
        }
    }
    close(fd);
    return;

errexit:
    close(fd);
    unlink(restart_name);
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
 * Clean up a group list entry.  Close the file if open,
 * free malloc'ed structures, drop the multicast group
 * (if no one else is using it) and free the slot.
 */
void file_cleanup(int listidx, int abort)
{
    if (group_list[listidx].fileinfo.fd >= 0) {
        close(group_list[listidx].fileinfo.fd);
        group_list[listidx].fileinfo.fd = -1;
    }

    if ((group_list[listidx].version == UFTP_V2_VER) ||
            abort || (group_list[listidx].file_id == 0)) {
        if ((group_list[listidx].multi.s_addr != 0) &&
                !other_mcast_users(listidx) && group_list[listidx].multi_join) {
            if (server_count > 0) {
                multicast_leave(listener, group_list[listidx].group_id,
                        &group_list[listidx].multi, m_interface,
                        interface_count, server_keys, server_count);
                if (has_proxy) {
                    multicast_leave(listener, group_list[listidx].group_id,
                            &group_list[listidx].multi, m_interface,
                            interface_count, &proxy_info, 1);
                }
            } else {
                multicast_leave(listener, group_list[listidx].group_id,
                        &group_list[listidx].multi,
                        m_interface, interface_count, NULL, 0);
            }
        }
        if (group_list[listidx].serverkey) {
            free_RSA_key(group_list[listidx].serverkey);
        }
        if (group_list[listidx].restartinfo &&
                (strcmp(group_list[listidx].restartinfo->name, ""))) {
            // We have unused restart info from the last run.
            // Chalk this up as a loss and delete the data file
            char filepath[MAXPATHNAME];
            snprintf(filepath, sizeof(filepath), "%s%c_group_%08X%c%s", tempdir,
                     PATH_SEP, group_list[listidx].group_id, PATH_SEP,
                     group_list[listidx].restartinfo->name);
            unlink(filepath);
        }
        if (abort) {
            write_restart_file(listidx);
        }

        free(group_list[listidx].fileinfo.naklist);
        free(group_list[listidx].fileinfo.section_done);
        if (group_list[listidx].restartinfo) {
            free(group_list[listidx].restartinfo->naklist);
            free(group_list[listidx].restartinfo->section_done);
            free(group_list[listidx].restartinfo);
        }
        memset(&group_list[listidx], 0, sizeof(group_list[listidx]));
    } else {
        // Don't clear the file_id in case we need to respond to late DONEs
        group_list[listidx].phase = PHASE_MIDGROUP;
        set_timeout(listidx);
        free(group_list[listidx].fileinfo.naklist);
        free(group_list[listidx].fileinfo.section_done);
        group_list[listidx].fileinfo.naklist = NULL;
        group_list[listidx].fileinfo.section_done = NULL;
    }
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
    header->destaddr = group_list[listidx].srcaddr.s_addr;
}

/**
 * Sets the timeout time for a given group list member
 */
void set_timeout(int listidx)
{
    gettimeofday(&group_list[listidx].timeout_time, NULL);
    switch (group_list[listidx].phase) {
    case PHASE_REGISTERED:
        group_list[listidx].timeout_time.tv_usec +=
                group_list[listidx].register_int * 1000;
        break;
    case PHASE_RECEIVING:
    case PHASE_MIDGROUP:
        group_list[listidx].timeout_time.tv_sec +=
                group_list[listidx].status_time;
        break;
    case PHASE_COMPLETE:
        group_list[listidx].timeout_time.tv_usec +=
                group_list[listidx].done_int * 1000;
        break;
    }
    while (group_list[listidx].timeout_time.tv_usec >= 1000000) {
        group_list[listidx].timeout_time.tv_usec -= 1000000;
        group_list[listidx].timeout_time.tv_sec++;
    }
}

/**
 * Sends an ABORT message to a server
 */
void send_abort(int listidx, const char *message)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct abort_h *abort;
    struct uftp2_h *v2_header;
    char *v2_message;
    int payloadlen;

    buf = calloc(group_list[listidx].mtu, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    if (group_list[listidx].version == UFTP_V2_VER) {
        v2_header = (struct uftp2_h *)buf;
        v2_message = (char *)v2_header + sizeof(struct uftp2_h);

        v2_header->uftp_id = htonl(V2_UFTP_ID);
        v2_header->func = htonl(V2_ABORT);
        v2_header->tx_id = htonl(group_list[listidx].group_id);
        v2_header->blsize = htonl(strlen(message));
        payloadlen = sizeof(struct uftp2_h) + strlen(message);
        strncpy(v2_message, message, V2_BLOCKSIZE - 1);
        encrypted = NULL;
        outpacket = buf;
    } else {
        header = (struct uftp_h *)buf;
        abort = (struct abort_h *)(buf + sizeof(struct uftp_h));

        set_uftp_header(header, ABORT, listidx);
        abort->func = ABORT;
        abort->host = 0;
        strncpy(abort->message, message, sizeof(abort->message) - 1);

        payloadlen = sizeof(struct abort_h);
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
        payloadlen += sizeof(struct uftp_h);
    }

    if (nb_sendto(listener, outpacket, payloadlen, 0,
               (struct sockaddr *)&group_list[listidx].replyaddr,
               sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(group_list[listidx].group_id, group_list[listidx].file_id,
                "Error sending ABORT");
    }

    file_cleanup(listidx, 1);
    free(buf);
    free(encrypted);
}

/**
 * Handles an ABORT message from a server
 */
void handle_abort(int listidx, const unsigned char *message, int meslen)
{
    struct abort_h *abort;
    struct uftp2_h *v2_header;
    const char *v2_message;
    int found, i;

    if (group_list[listidx].version == UFTP_V2_VER) {
        v2_header = (struct uftp2_h *)message;
        v2_message = (const char *)message + sizeof(struct uftp2_h);
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Transfer aborted by server: %s", v2_message);
        file_cleanup(listidx, 1);
        return;
    }

    abort = (struct abort_h *)message;
    if (meslen != sizeof(struct abort_h)) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Rejecting ABORT from server: invalid message size");
    }

    for (i = 0, found = 0; (i < interface_count) && !found; i++) {
        if (abort->host == m_interface[i].addr.s_addr) {
            found = 1;
        }
    }

    if ((abort->host == 0) || found) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Transfer aborted by server: %s", abort->message);
        file_cleanup(listidx, 1);
    }
}

/**
 * Sends a KEY_REQ message to the proxy specified as the reply proxy
 */
void send_key_req()
{
    unsigned char *packet;
    struct uftp_h *header;
    struct key_req_h *keyreq;
    struct sockaddr_in proxyaddr;
    int meslen;

    packet = calloc(sizeof(struct uftp_h) + sizeof(struct key_req_h), 1);
    if (packet == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)packet;
    keyreq = (struct key_req_h *)(packet + sizeof(struct uftp_h));
    header->uftp_id = UFTP_VER_NUM;
    header->func = KEY_REQ;
    keyreq->func = KEY_REQ;

    meslen = sizeof(struct key_req_h);
    header->blsize = htons(meslen);
    meslen += sizeof(struct uftp_h);
    proxyaddr.sin_family = AF_INET;
    proxyaddr.sin_addr = proxy_info.addr;
    proxyaddr.sin_port = htons(port);
    if (nb_sendto(listener, packet, meslen, 0, 
                  (struct sockaddr *)&proxyaddr,
                  sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error sending KEY_REQ");
    } else {
        log(0, 0, "Sent KEY_REQ to %s:%d", inet_ntoa(proxy_info.addr), port);
    }

    free(packet);
    gettimeofday(&next_keyreq_time, NULL);
    next_keyreq_time.tv_sec += KEY_REQ_INT;
}

/**
 * Process a PROXY_KEY message
 */
void handle_proxy_key(const struct sockaddr_in *src,
                      const unsigned char *message)
{
    struct uftp_h *header;
    struct proxy_key_h *proxykey;
    unsigned char *keymod, *sig;
    struct hostent *hp;
    RSA_key_t key;
    unsigned char *verifydata, fingerprint[HMAC_LEN];
    unsigned int verifylen, fplen, keylen, siglen;

    header = (struct uftp_h *)message;
    proxykey = (struct proxy_key_h *)(message + sizeof(struct uftp_h));

    if (!noname && (hp = gethostbyaddr((char *)&src->sin_addr,
                                       sizeof(struct in_addr), AF_INET))) {
        log(0, 0, "Received PROXY_KEY from %s (%s)",
                  hp->h_name, inet_ntoa(src->sin_addr));
    } else {
        log(0, 0, "Received PROXY_KEY from %s", inet_ntoa(src->sin_addr));
    }
    if (!has_proxy) {
        log(0, 0, "No reply proxy specified");
        return;
    }
    if ((src->sin_addr.s_addr != proxy_info.addr.s_addr) ||
            (src->sin_port != htons(port))) {
        log(0, 0, "PROXY_KEY not from specified reply proxy");
        return;
    }

    keymod = (unsigned char *)proxykey + sizeof(struct proxy_key_h);
    keylen = ntohs(proxykey->keylen);
    sig = keymod + keylen;
    siglen = ntohs(proxykey->siglen);

    // First check key fingerprint
    if (proxy_info.has_fingerprint) {
        verifylen = 0;
        verifydata = calloc(sizeof(proxykey->keyexp) + keylen, 1);
        if (verifydata == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        memcpy(verifydata, &proxykey->keyexp, sizeof(proxykey->keyexp));
        verifylen += sizeof(proxykey->keyexp);
        memcpy(verifydata + verifylen, keymod, keylen);
        verifylen += keylen;
        hash(HASH_SHA1, verifydata, verifylen, fingerprint, &fplen);
        if (memcmp(proxy_info.fingerprint, fingerprint, fplen)) {
            log(0, 0, "Failed to verify PROXY_KEY fingerprint");
            free(verifydata);
            return;
        }
        free(verifydata);
    }

    // Then check signature
    if (!import_RSA_key(&key, ntohl(proxykey->keyexp), keymod, keylen)) {
        log(0, 0, "Failed to import public key from PROXY_KEY");
        return;
    } 

    if (!verify_RSA_sig(key, HASH_SHA1, (unsigned char *)&proxykey->nonce,
            sizeof(proxykey->nonce), sig, siglen)) {
        log(0, 0, "Failed to verify PROXY_KEY signature");
        return;
    }

    // Load key
    if (!import_RSA_key(&proxy_key, ntohl(proxykey->keyexp), keymod, keylen)) {
        log(0, 0, "Failed to import public key from PROXY_KEY");
        return;
    } 
}

/**
 * Removes a full path from disk
 */
void clear_path(const char *path, int listidx)
{
    stat_struct statbuf;
    char filename[MAXPATHNAME];
    int len;

    if (lstat_func(path, &statbuf) == -1) {
        if (errno != ENOENT) {
            syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                     "Error getting file status for %s", path);
        }
        return;
    }
    if (!S_ISDIR(statbuf.st_mode)) {
        unlink(path);
    } else {
#ifdef WINDOWS
        intptr_t ffhandle;
        struct _finddatai64_t finfo;
        char dirglob[MAXPATHNAME];

        snprintf(dirglob, sizeof(dirglob), "%s%c*", path,
                 PATH_SEP, group_list[listidx].group_id, PATH_SEP);
        if ((ffhandle = _findfirsti64(dirglob, &finfo)) == -1) {
            syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                     "Failed to open directory %s", path);
            return;
        }
        do {
            len = snprintf(filename, sizeof(filename), "%s%c%s", path,
                           PATH_SEP, finfo.name);
            if ((len >= sizeof(filename)) || (len == -1)) {
                log(group_list[listidx].group_id, group_list[listidx].file_id,
                        "Max pathname length exceeded: %s%c%s",
                        filename, PATH_SEP, finfo.name);
                continue;
            }
            if (strcmp(finfo.name, ".") && strcmp(finfo.name, "..")) {
                clear_path(filename, listidx);
            }
        } while (_findnexti64(ffhandle, &finfo) == 0);
        _findclose(ffhandle);
#else
        DIR *dir;
        struct dirent *de;

        if ((dir = opendir(path)) == NULL) {
            syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                     "Failed to open directory %s", path);
            return;
        }
        // errno needs to be set to 0 before calling readdir, otherwise
        // we'll report a false error when we exhaust the directory
        while ((errno = 0, de = readdir(dir)) != NULL) {
            len = snprintf(filename, sizeof(filename), "%s%c%s", path, PATH_SEP,
                           de->d_name);
            if ((len >= sizeof(filename)) || (len == -1)) {
                log(group_list[listidx].group_id, group_list[listidx].file_id,
                        "Max pathname length exceeded: %s%c%s", path,
                        PATH_SEP, de->d_name);
                continue;
            }
            if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
                clear_path(filename, listidx);
            }
        }
        if (errno && (errno != ENOENT)) {
            syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                     "Failed to read directory %s", path);
        }
        closedir(dir);
#endif
        if (rmdir(path) == -1) {
            syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                     "Failed remove directory %s", path);
        }
    }
}

/**
 * Creates all directories in the given file's path, removing existing files.
 * Returns 1 on success, 0 on failure
 */
int create_path_to_file(int listidx, const char *filename)
{
    char *dir, *base;
    stat_struct statbuf;
    int rval;

    split_path(filename, &dir, &base);
    if (!dir) {
        log(group_list[listidx].group_id, group_list[listidx].file_id,
                "Invalid path element %s", filename);
        rval = 0;
        goto end;
    }
#ifdef WINDOWS
    if ((base == NULL) || ((strlen(dir) == 2) && (dir[1] == ':'))) {
#else
    if ((!strcmp(dir, ".")) || (!strcmp(dir, "/"))) {
#endif
        // At top level directory, so stop recursion
        rval = 1;
        goto end;
    }

    if (lstat_func(dir, &statbuf) != -1) {
        if (!S_ISDIR(statbuf.st_mode)) {
            if (unlink(dir) == -1) {
                syserror(group_list[listidx].group_id,
                         group_list[listidx].file_id,
                         "Failed to delete path element %s", dir);
                rval = 0;
                goto end;
            }
            if (mkdir(dir, 0755) == -1) {
                syserror(group_list[listidx].group_id,
                         group_list[listidx].file_id,
                         "Failed to create path element %s", dir);
                rval = 0;
                goto end;
            }
        }
    } else {
        // If the file's directory does not exist, recurse first to make sure
        // all parent directories exist
        if (!create_path_to_file(listidx, dir)) {
            rval = 0;
            goto end;
        }
        if (mkdir(dir, 0755) == -1) {
            syserror(group_list[listidx].group_id, group_list[listidx].file_id,
                     "Failed to create path element %s", dir);
            rval = 0;
            goto end;
        }
    }

    rval = 1;

end:
    free(dir);
    free(base);
    return rval;
}

