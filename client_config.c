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
#include <errno.h>

#ifdef WINDOWS

#include "win_func.h"

#else  // if WINDOWS

#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

#endif

#include "client.h"
#include "client_config.h"

/**
 * Global command line values and sockets
 */
SOCKET listener;
char tempdir[MAXDIRNAME], destdir[MAXDIRNAME];
char logfile[MAXPATHNAME], pidfile[MAXPATHNAME];
char keyfile[MAXLIST][MAXPATHNAME];
int verbose, noname, debug, newkeylen, encrypted_only, dscp;
int interface_count, pub_multi_count, keyfile_count, buffer;
uint16_t port;
uint32_t uid;
struct iflist m_interface[MAX_INTERFACES];
struct in_addr pub_multi[MAX_INTERFACES];
struct group_list_t group_list[MAXLIST];
struct fp_list_t server_keys[MAXLIST];
struct iflist ifl[MAX_INTERFACES];
struct timeval next_keyreq_time;
int ifl_len, server_count, key_count, has_proxy, sys_keys;
RSA_key_t privkey[MAXLIST];
struct fp_list_t proxy_info;
RSA_key_t proxy_key;

extern char *optarg;
extern int optind;

/**
 * Adds a server and its fingerprint to the list of approved servers
 */
void add_server_by_name(const char *server, const char *fingerprint)
{
    struct hostent *hp;
    struct in_addr *addr;

    if (inet_addr(server) == INADDR_NONE) {
        if ((hp = gethostbyname(server)) == NULL) {
            fprintf(stderr, "Invalid host name: %s\n", server);
            exit(1);
        } else {
            addr = (struct in_addr *)hp->h_addr_list[0];
            server_keys[server_count].addr = *addr;
            server_keys[server_count].has_fingerprint =
                    parse_fingerprint(server_keys[server_count].fingerprint,
                                      fingerprint);
            server_count++;
        }
    } else {
        server_keys[server_count].addr.s_addr = inet_addr(server);
        server_keys[server_count].has_fingerprint =
                parse_fingerprint(server_keys[server_count].fingerprint,
                                  fingerprint);
        server_count++;
    }
}

/**
 * Set defaults for all command line arguments
 */
void set_defaults()
{
    debug = 0;
    verbose = 0;
    noname = 0;
    encrypted_only = 0;
    uid = 0;
    dscp = DEF_DSCP;
    strncpy(logfile, DEF_LOGFILE, sizeof(logfile)-1);
    logfile[sizeof(logfile)-1] = '\x0';
    memset(pidfile, 0, sizeof(pidfile));
    interface_count = 0;
    port = DEF_PORT;
    strncpy(tempdir, DEF_TEMPDIR, sizeof(tempdir)-1);
    tempdir[sizeof(tempdir)-1] = '\x0';
    strncpy(destdir, DEF_DESTDIR, sizeof(destdir)-1);
    destdir[sizeof(destdir)-1] = '\x0';
    pub_multi_count = 0;
    key_count = 0;
    keyfile_count = 0;
    memset(keyfile[0], 0, sizeof(keyfile[0]));
    buffer = 0;
    server_count = 0;
    newkeylen = 0;
    has_proxy = 0;
    sys_keys = 0;
}

/**
 * Set argument defaults, read and validate command line options
 */
void process_args(int argc, char *argv[])
{
    int c, i, listidx;
    long tmpval;
    struct hostent *hp;
    struct in_addr addr, *paddr;
    char line[1000], *servername, *fingerprint, *p;
    FILE *serverfile;
    const char opts[] = "dv:nL:P:I:p:T:D:M:B:Q:EU:S:R:k:K:m";

    set_defaults();

    // read lettered arguments
    while ((c = getopt(argc, argv, opts)) != EOF) {
        switch (c) {
        case 'd':
            debug = 1;
            break;
        case 'n':
            noname = 1;
            break;
        case 'v':
            verbose = atoi(optarg);
            break;
        case 'L':
            strncpy(logfile, optarg, sizeof(logfile)-1);
            logfile[sizeof(logfile)-1] = '\x0';
            break;
        case 'P':
            strncpy(pidfile, optarg, sizeof(pidfile)-1);
            pidfile[sizeof(pidfile)-1] = '\x0';
            break;
        case 'I':
            p = strtok(optarg, ",");
            while (p != NULL) {
                if ((listidx = getifbyname(p, ifl, ifl_len)) != -1) {
                    m_interface[interface_count++] = ifl[listidx];
                    p = strtok(NULL, ",");
                    continue;
                }
                if (inet_addr(p) == INADDR_NONE) {
                    if ((hp = gethostbyname(p)) == NULL) {
                        fprintf(stderr, "Invalid host name: %s\n", p);
                        exit(1);
                    } else {
                        paddr = (struct in_addr *)hp->h_addr_list[0];
                    }
                } else {
                    addr.s_addr = inet_addr(p);
                    paddr = &addr;
                }
                if ((listidx = getifbyaddr(*paddr, ifl, ifl_len)) != -1) {
                    m_interface[interface_count++] = ifl[listidx];
                } else {
                    fprintf(stderr, "Interface %s not found\n", p);
                    exit(1);
                }
                p = strtok(NULL, ",");
            }
            break;
        case 'p':
            port = atoi(optarg);
            if (port == 0) {
                fprintf(stderr, "Invalid port\n");
                exit(1);
            }
            break;
        case 'T':
            strncpy(tempdir, optarg, sizeof(tempdir)-1);
            tempdir[sizeof(tempdir)-1] = '\x0';
            break;
        case 'D':
            strncpy(destdir, optarg, sizeof(destdir)-1);
            destdir[sizeof(destdir)-1] = '\x0';
            break;
        case 'M':
            p = strtok(optarg, ",");
            while (p != NULL) {
                pub_multi[pub_multi_count].s_addr = inet_addr(p);
                if ((pub_multi[pub_multi_count].s_addr == INADDR_NONE) ||
                        (!is_multicast(pub_multi[pub_multi_count], 0))) {
                    fprintf(stderr, "Invalid multicast address: %s\n", p);
                    exit(1);
                }
                pub_multi_count++;
                p = strtok(NULL, ",");
            }
            break;
        case 'B':
            buffer = atoi(optarg);
            if ((buffer < 65536) || (buffer > 104857600)) {
                fprintf(stderr, "Invalid buffer size\n");
                exit(1);
            }
            break;
        case 'Q':
            tmpval = strtol(optarg, NULL, 0);
            if ((tmpval < 0) || (tmpval > 63)) {
                fprintf(stderr, "Invalid dscp\n");
                exit(1);
            }
            dscp = (tmpval & 0xFF) << 2;
            break;
        case 'E':
            encrypted_only = 1;
            break;
        case 'U':
            if ((uid = inet_addr(optarg)) != 0) {
                if (ntohl(uid) > 0xffffff) {
                    fprintf(stderr, "Invalid UID\n");
                    exit(1);
                }
            } else {
                uid = strtol(optarg, NULL, 16);
                if ((uid > 0xffffff) || (uid <= 0)) {
                    fprintf(stderr, "Invalid UID\n");
                    exit(1);
                }
                uid = htonl(uid);
            }
            break;
        case 'S':
            if ((serverfile = fopen(optarg, "r")) == NULL) {
                fprintf(stderr, "Couldn't open server list %s: %s\n",
                        optarg, strerror(errno));
                exit(1);
            }
            while (fgets(line, sizeof(line), serverfile)) {
                while (line[strlen(line)-1] == '\r' ||
                       line[strlen(line)-1] == '\n') {
                    line[strlen(line)-1] = '\x0';
                }
                servername = strtok(line, " \t");
                if (!servername) continue;
                if (servername[0] == '#') continue;
                if (strlen(servername) > DESTNAME_LEN) {
                    fprintf(stderr, "Server list: name too long\n");
                    exit(1);
                }
                fingerprint = strtok(NULL, " \t");
                add_server_by_name(servername, fingerprint);
            }
            if (!feof(serverfile) && ferror(serverfile)) {
                perror("Failed to read from server list file");
                exit(1);
            }
            fclose(serverfile);
            break;
        case 'R':
            strncpy(line, optarg, sizeof(line));
            line[sizeof(line)-1] = '\x0';
            servername = strtok(line, "/");
            if (!servername) {
                fprintf(stderr, "Invalid host name\n");
                exit(1);
            }
            fingerprint = strtok(NULL, "/");
            if (inet_addr(servername) == INADDR_NONE) {
                if ((hp = gethostbyname(servername)) == NULL) {
                    fprintf(stderr, "Invalid host name: %s\n", servername);
                    exit(1);
                } else {
                    paddr = (struct in_addr *)hp->h_addr_list[0];
                    proxy_info.addr = *paddr;
                    proxy_info.has_fingerprint =
                            parse_fingerprint(proxy_info.fingerprint,
                                              fingerprint);
                    has_proxy = 1;
                }
            } else {
                proxy_info.addr.s_addr = inet_addr(servername);
                proxy_info.has_fingerprint =
                        parse_fingerprint(proxy_info.fingerprint, fingerprint);
                has_proxy = 1;
            }
            break;
        case 'k':
            p = strtok(optarg, ",");
            while (p != NULL) {
                strncpy(keyfile[keyfile_count], p, sizeof(keyfile[0])-1);
                keyfile[keyfile_count][sizeof(keyfile[0])-1] = '\x0';
                keyfile_count++;
                p = strtok(NULL, ",");
            }
            break;
        case 'K':
            newkeylen = atoi(optarg);
            if ((newkeylen < 512) || (newkeylen > 2048)) {
                fprintf(stderr, "Invalid new key length\n");
                exit(1);
            }
            break;
        case 'm':
            sys_keys = 1;
            break;
        case '?':
            fprintf(stderr, USAGE);
            exit(1);
        }
    }
    if (server_count) {
        for (i = 0; i < pub_multi_count; i++) {
            if (!is_multicast(pub_multi[i], 1)) {
                fprintf(stderr, "Invalid source specific "
                        "multicast address: %s\n", inet_ntoa(pub_multi[i]));
                exit(1);
            }
        }
        if (pub_multi_count == 0) {
            fprintf(stderr, "Default multicast address %s invalid "
                    "for source specific multicast\n", DEF_PUB_MULTI);
            exit(1);
        }
    }
}

