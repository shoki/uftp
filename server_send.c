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
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#ifdef WINDOWS

#include <io.h>

#else  // if WINDOWS

#include <unistd.h>
#include <dirent.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif

#include "server.h"
#include "server_send.h"
#include "server_phase.h"
#include "server_common.h"

/**
 * Checks to see if a file/directory is in the exclude list
 */
int file_excluded(const char *filename)
{
    int found, i;

    for (found = 0, i = 0; (i < excludecount) && !found; i++) {
        if (!strcmp(filename, exclude[i])) {
            found = 1;
        }
    }

    return found;
}

/**
 * Performs the send for a particular file/directory.  If a directory is
 * specified, get the list of files and call recursively for each.
 * Returns 0 if a file was sent and none received it, 1 otherwise
 */
int send_file(const char *basedir, const char *filename,
              const char *n_destfname, uint32_t group_id)
{
    static uint16_t file_id = 1;
    struct finfo_t finfo;
    stat_struct statbuf;
    char path[MAXPATHNAME], destpath[MAXPATHNAME];
    int len, rval, fd, emptydir;

    log(0, 0, "----- %s -----", filename);
    len = snprintf(path, sizeof(path), "%s%c%s", basedir, PATH_SEP, filename);
    if ((len >= sizeof(path)) || (len == -1)) {
        log(0, 0, "Max pathname length exceeded: %s%c%s",
                   basedir, PATH_SEP, filename);
        return 1;
    }
    if (follow_links) {
        rval = stat_func(path, &statbuf);
    } else {
        rval = lstat_func(path, &statbuf);
    }
    if (rval == -1) {
        syserror(0, 0, "Error getting file status for %s", filename);
        return 1;
    }
    if (file_excluded(filename)) {
        log(0, 0, "Skipping %s", filename);
        return 1;
    }
    rval = 1;
    if (S_ISREG(statbuf.st_mode)) {
        if ((fd = open(path, OPENREAD, 0)) == -1) {
            syserror(0, 0, "Error reading file %s", filename);
            return 1;
        }
        close(fd);
        memset(&finfo, 0, sizeof(struct finfo_t));
        finfo.ftype = FTYPE_REG;
        finfo.basedir = basedir;
        finfo.filename = filename;
        finfo.destfname = n_destfname;
        finfo.group_id = group_id;
        finfo.file_id = file_id++;
        if (file_id == 0) {
            file_id = 1;
        }
        finfo.size = statbuf.st_size;
        finfo.blocks = (int32_t)((finfo.size / blocksize) +
                (finfo.size % blocksize ? 1 :0));
        finfo.sections = (finfo.blocks / (blocksize * 8)) +
                (finfo.blocks % (blocksize * 8) ? 1 : 0);
        finfo.naklist = calloc(finfo.blocks, 1);
        finfo.deststate = calloc(destcount ? destcount : MAXDEST,
                sizeof(struct deststate_t));
        if ((finfo.naklist == NULL) || (finfo.deststate == NULL)) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        finfo.partial = 1;
        rval = announce_phase(&finfo);
        if (rval) {
            rval = transfer_phase(&finfo);
        }
        free(finfo.deststate);
        free(finfo.naklist);
#ifndef WINDOWS
    } else if (S_ISLNK(statbuf.st_mode)) {
        char linkname[MAXPATHNAME];

        memset(linkname, 0, sizeof(linkname));
        if (readlink(path, linkname, sizeof(linkname)-1) == -1) {
            syserror(0, 0, "Failed to read symbolic link %s", path);
            return 1;
        }
        // Both the file name and the link have to fit into a fileinfo_h.name
        if (strlen(linkname) + strlen(filename) + 2 > MAXPATHNAME) {
            log(0, 0, "Combined file name %s and link %s too long",
                      filename, linkname);
            return 1;
        }
        memset(&finfo, 0, sizeof(struct finfo_t));
        finfo.ftype = FTYPE_LINK;
        finfo.basedir = basedir;
        finfo.filename = filename;
        finfo.destfname = n_destfname;
        finfo.linkname = linkname;
        finfo.group_id = group_id;
        finfo.file_id = file_id++;
        if (file_id == 0) {
            file_id = 1;
        }
        finfo.deststate = calloc(destcount ? destcount : MAXDEST,
                sizeof(struct deststate_t));
        if (finfo.deststate == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        finfo.partial = 1;
        rval = announce_phase(&finfo);
        if (rval) {
            rval = transfer_phase(&finfo);
        }
#endif
    } else if (S_ISDIR(statbuf.st_mode)) {
        // read directory and do recursive send
#ifdef WINDOWS
        intptr_t ffhandle;
        struct _finddatai64_t ffinfo;
        char dirglob[MAXPATHNAME];

        snprintf(dirglob, sizeof(dirglob), "%s%c%s%c*", basedir, PATH_SEP,
                                                        filename, PATH_SEP);
        if ((ffhandle = _findfirsti64(dirglob, &ffinfo)) == -1) {
            syserror(0, 0, "Failed to open directory %s%c%s", basedir, PATH_SEP,
                                                              filename);
            return 1;
        }
        emptydir = 1;
        do {
            len = snprintf(path, sizeof(path), "%s/%s", filename, ffinfo.name);
            if ((len >= sizeof(path)) || (len == -1)) {
                log(0, 0, "Max pathname length exceeded: %s/%s",
                           filename, ffinfo.name);
                continue;
            }
            len = snprintf(destpath, sizeof(destpath), "%s/%s",
                           n_destfname, ffinfo.name);
            if ((len >= sizeof(destpath)) || (len == -1)) {
                log(0, 0, "Max pathname length exceeded: %s/%s",
                           n_destfname, ffinfo.name);
                continue;
            }
            if (strcmp(ffinfo.name, ".") && strcmp(ffinfo.name, "..")) {
                emptydir = 0;
                if (!send_file(basedir, path, destpath, group_id)) {
                    rval = 0;
                    break;
                }
            }
        } while (_findnexti64(ffhandle, &ffinfo) == 0);
        _findclose(ffhandle);
#else
        DIR *dir;
        struct dirent *de;
        char dirname[MAXPATHNAME];

        snprintf(dirname, sizeof(dirname), "%s%c%s", basedir,PATH_SEP,filename);
        if ((dir = opendir(dirname)) == NULL) {
            syserror(0, 0, "Failed to open directory %s", dirname);
            return 1;
        }
        // errno needs to be set to 0 before calling readdir, otherwise
        // we'll report a false error when we exhaust the directory
        emptydir = 1;
        while ((errno = 0, de = readdir(dir)) != NULL) {
            len = snprintf(path, sizeof(path), "%s/%s", filename, de->d_name);
            if ((len >= sizeof(path)) || (len == -1)) {
                log(0, 0, "Max pathname length exceeded: %s/%s",
                           filename, de->d_name);
                continue;
            }
            len = snprintf(destpath, sizeof(destpath), "%s/%s",
                           n_destfname, de->d_name);
            if ((len >= sizeof(destpath)) || (len == -1)) {
                log(0, 0, "Max pathname length exceeded: %s/%s",
                           n_destfname, de->d_name);
                continue;
            }
            if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
                emptydir = 0;
                if (!send_file(basedir, path, destpath, group_id)) {
                    rval = 0;
                    break;
                }
            }
        }
        if (errno && (errno != ENOENT)) {
            syserror(0, 0, "Failed to read directory %s", filename);
        }
        closedir(dir);
#endif
        if (emptydir) {
            memset(&finfo, 0, sizeof(struct finfo_t));
            finfo.ftype = FTYPE_DIR;
            finfo.basedir = basedir;
            finfo.filename = filename;
            finfo.destfname = n_destfname;
            finfo.group_id = group_id;
            finfo.file_id = file_id++;
            if (file_id == 0) {
                file_id = 1;
            }
            finfo.deststate = calloc(destcount ? destcount : MAXDEST,
                    sizeof(struct deststate_t));
            if (finfo.deststate == NULL) {
                syserror(0, 0, "calloc failed!");
                exit(1);
            }
            finfo.partial = 1;
            rval = announce_phase(&finfo);
            if (rval) {
                rval = transfer_phase(&finfo);
            }
        }
    } else {
        log(0, 0, "Skipping special file %s", filename);
    }
    return rval;
}

/**
 * Write a restart file entry for a particular client.
 * Returns 1 on success, o on fail.
 */
int write_restart_host(int fd, int i)
{
    struct server_restart_host_t host;

    memset(&host, 0, sizeof(host));
    strcpy(host.name, destlist[i].name);
    host.addr = destlist[i].addr;
    if (destlist[i].has_fingerprint) {
        host.has_fingerprint = 1;
        memcpy(host.keyfingerprint, destlist[i].keyfingerprint,
               HMAC_LEN);
    }
    host.is_proxy = (destlist[i].clientcnt != -1);
    if (file_write(fd, &host, sizeof(host)) == -1) {
        log(0, 0, "Failed to write host for restart file");
        return 0;
    }
    return 1;
}

/**
 * Save the state of a failed transfer so it can restarted later.
 */
void write_restart_file(uint32_t group_id)
{
    struct server_restart_t header;
    char restart_name[MAXFILENAME];
    char proxy_listed[MAXPROXYDEST];
    int fd, opened, i, j, proxycnt, found;

    memset(proxy_listed, 0, sizeof(proxy_listed));
    opened = 0;
    proxycnt = 0;
    for (i = 0; i < destcount; i++) {
        if ((destlist[i].clientcnt == -1) && client_error(i)) {
            if (!opened) {
                snprintf(restart_name, sizeof(restart_name),
                         "_group_%08X_restart", group_id);
                if ((fd = open(restart_name, OPENWRITE | O_CREAT | O_TRUNC,
                               0644)) == -1) {
                    syserror(0, 0, "Failed to create restart file");
                    return;
                }

                // Write header
                header.group_id = group_id;
                header.filecount = filecount;
                if (file_write(fd, &header, sizeof(header)) == -1) {
                    log(0, 0, "Failed to write header for restart file");
                    goto errexit;
                }

                // Write file list
                for (j = 0; j < filecount; j++) {
                    if (file_write(fd, filelist[j],sizeof(filelist[j])) == -1) {
                        log(0, 0, "Failed to write filename for restart file");
                        goto errexit;
                    }
                }
                opened = 1;
            }
            if (!write_restart_host(fd, i)) {
                goto errexit;
            }
            if (destlist[i].proxyidx != -1) {
                for (j = 0, found = 0; (j < proxycnt) && !found; j++) {
                    if (proxy_listed[j] == destlist[i].proxyidx) {
                        found = 1;
                    }
                }
                if (!found) {
                    if (!write_restart_host(fd, destlist[i].proxyidx)) {
                        goto errexit;
                    }
                    proxy_listed[proxycnt++] = destlist[i].proxyidx;
                }
            }
        }
    }

    if (opened) {
        close(fd);
    }
    return;

errexit:
    close(fd);
    unlink(restart_name);
}

/**
 * The main sending function.  Goes through all files/diectories specified on
 * the command line and initializes the group for multiple files.
 */
int send_files()
{
    int i, rval, len;
    struct finfo_t group_info;
    char *dir, *base;
    time_t t;
    char path[MAXPATHNAME];

    t = time(NULL);
    if (!showtime) fprintf(applog, "\n");
    log(0, 0, "%s", VERSIONSTR);
    if (!showtime) clog(0, 0, "Starting at %s", ctime(&t));
    if (privkey) {
        log(0, 0, "Loaded %d bit key with fingerprint %s",
                  RSA_keylen(privkey) * 8, print_key_fingerprint(privkey));
    }
    if (rate == -1) {
        log(0, 0, "Transfer rate: full interface speed");
    } else {
        log(0, 0, "Transfer rate: %d Kbps (%d KB/s)", rate, rate / 8);
        log(0, 0, "Wait between packets: %d us", packet_wait);
    }

    memset(&group_info, 0, sizeof(struct finfo_t));
    if (restart_groupid) {
        group_info.group_id = restart_groupid;
    } else {
        group_info.group_id = rand() & 0xFFFF;
        group_info.group_id |= (rand() & 0xFFFF) << 16;
    }
    group_info.deststate = calloc(destcount ? destcount : MAXDEST,
                                  sizeof(struct deststate_t));
    if (group_info.deststate == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    log(0, 0, "Using private multicast address %s  Group ID: %08X",
               inet_ntoa(receive_dest.sin_addr), group_info.group_id);
    rval = announce_phase(&group_info);
    if (rval) {
        rval = 0;
        for (i = 0; i < filecount; i++) {
            split_path(filelist[i], &dir, &base);
            if (strcmp(destfname, "")) {
                if (filecount > 1) {
                    len = snprintf(path, sizeof(path), "%s/%s", destfname,base);
                    if ((len >= sizeof(path)) || (len == -1)) {
                        log(0, 0, "Max pathname length exceeded: %s/%s",
                                   destfname, base);
                        free(dir);
                        free(base);
                        continue;
                    }
                    rval = send_file(dir, base, path, group_info.group_id);
                } else {
                    rval = send_file(dir, base, destfname, group_info.group_id);
                }
            } else {
                rval = send_file(dir, base, base, group_info.group_id);
            }
            free(dir);
            free(base);
            if (!rval) {
                break;
            }
        }
        if (rval) {
            log(0, 0, "-----------------------------");
            transfer_phase(&group_info);
        }
    }
    if (save_fail) {
        write_restart_file(group_info.group_id);
    }
    free(group_info.deststate);

    t = time(NULL);
    if (!showtime) clog(0, 0, "uftp: Finishing at %s", ctime(&t));
    return rval;
}

