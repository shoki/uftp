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
#include <time.h>
#include <errno.h>

#ifdef WINDOWS

#include <process.h>
#include "win_func.h"

#else  // if WINDOWS

#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#endif

#include "proxy.h"
#include "proxy_config.h"

/**
 * Global command line values and sockets
 */
SOCKET listener;
char logfile[MAXPATHNAME], pidfile[MAXPATHNAME];
char keyfile[MAXLIST][MAXPATHNAME];
int proxy_type, verbose, noname, debug, buffer, newkeylen, dscp;
int hb_interval, proxy_int;
unsigned char ttl;
uint16_t port, out_port;
struct sockaddr_in down_addr;
int have_down_fingerprint;
uint8_t down_fingerprint[HMAC_LEN];
uint32_t down_nonce, uid;
struct sockaddr_in hb_hosts[MAXLIST];
struct in_addr pub_multi[MAX_INTERFACES];
struct fp_list_t server_fp[MAXLIST], client_fp[MAXPROXYDEST];
struct iflist ifl[MAX_INTERFACES], m_interface[MAX_INTERFACES];
struct timeval next_hb_time, last_key_req;
int ifl_len, hbhost_count, server_fp_count, client_fp_count;
int keyfile_count, key_count, pub_multi_count, interface_count, sys_keys;
struct in_addr out_addr;
RSA_key_t privkey[MAXLIST];
struct pr_group_list_t group_list[MAXLIST];

extern char *optarg;
extern int optind;

/**
 * Adds a host and its fingerprint to the given list
 */
void add_hosts_by_name(struct fp_list_t *list, int *list_count,
                       const char *filename)
{
    char line[1000], *hostname, *fingerprint;
    FILE *hostfile;
    struct hostent *hp;
    struct in_addr *addr;

    if ((hostfile = fopen(filename, "r")) == NULL) {
        fprintf(stderr,"Couldn't open server/client list %s: %s\n",
                filename, strerror(errno));
        exit(1);
    }
    while (fgets(line, sizeof(line), hostfile)) {
        while (line[strlen(line)-1] == '\r' ||
               line[strlen(line)-1] == '\n') {
            line[strlen(line)-1] = '\x0';
        }
        hostname = strtok(line, " \t");
        if (!hostname) continue;
        if (hostname[0] == '#') continue;
        if (strlen(hostname) > DESTNAME_LEN) {
            fprintf(stderr, "Server/Client list %s: name too long\n", filename);
            exit(1);
        }
        fingerprint = strtok(NULL, " \t");

        if (inet_addr(hostname) == INADDR_NONE) {
            if ((hp = gethostbyname(hostname)) == NULL) {
                fprintf(stderr, "Invalid host name: %s\n", hostname);
                exit(1);
            } else {
                addr = (struct in_addr *)hp->h_addr_list[0];
                list[*list_count].addr = *addr;
                list[*list_count].has_fingerprint =
                    parse_fingerprint(list[*list_count].fingerprint,
                                      fingerprint);
                (*list_count)++;
            }
        } else {
            list[*list_count].addr.s_addr = inet_addr(hostname);
            list[*list_count].has_fingerprint =
                parse_fingerprint(list[*list_count].fingerprint, fingerprint);
            (*list_count)++;
        }
    }
    if (!feof(hostfile) && ferror(hostfile)) {
        perror("Failed to read from server/client list file");
        exit(1);
    }
    fclose(hostfile);
}

/**
 * Set defaults for all command line arguments
 */
void set_defaults()
{
    proxy_type = UNDEF_PROXY;
    proxy_int = DEF_PROXY_INT;
    hbhost_count =  0;
    memset(hb_hosts, 0, sizeof(hb_hosts));
    hb_interval = DEF_HB_INT;
    debug = 0;
    noname = 0;
    verbose = 0;
    port = DEF_PORT;
    out_addr.s_addr = INADDR_NONE;
    ttl = DEF_TTL;
    dscp = DEF_DSCP;
    out_port = DEF_PORT;
    uid = 0;
    buffer = 0;
    strncpy(logfile, DEF_LOGFILE, sizeof(logfile)-1);
    logfile[sizeof(logfile)-1] = '\x0';
    memset(pidfile, 0, sizeof(pidfile));
    server_fp_count = 0;
    client_fp_count = 0;
    key_count = 0;
    keyfile_count = 0;
    newkeylen = 0;
    interface_count = 0;
    pub_multi_count = 0;
    sys_keys = 0;
}

/**
 * Set argument defaults, read and validate command line options
 */
void process_args(int argc, char *argv[])
{
    int c, i, listidx, hbport;
    long tmpval;
    struct hostent *hp;
    struct in_addr *paddr, addr;
    char *p, *p2, *hoststr, *portstr;
    const char opts[] = "s:crdv:np:t:Q:O:U:q:T:mh:H:B:L:P:C:S:k:K:I:M:";

    set_defaults();

    // read lettered arguments
    while ((c = getopt(argc, argv, opts)) != EOF) {
        switch (c) {
        case 's':
            if (proxy_type != UNDEF_PROXY) {
                fprintf(stderr, "Only one of -s, -c, -r may be specified\n");
                exit(1);
            }
            proxy_type = SERVER_PROXY;
            memset(&down_addr, 0, sizeof(down_addr));
            if (!strncmp(optarg, "fp=", 3)) {
                have_down_fingerprint =
                        parse_fingerprint(down_fingerprint, optarg + 3);
                if (!have_down_fingerprint) {
                    fprintf(stderr, "Failed to parse downstream fingerprint\n");
                    exit(1);
                }
                srand((unsigned int)time(NULL) ^ getpid());
                down_nonce = rand();
            } else {
                have_down_fingerprint = 0;
                down_addr.sin_family = AF_INET;
                if (inet_addr(optarg) == INADDR_NONE) {
                    if ((hp = gethostbyname(optarg)) == NULL) {
                        fprintf(stderr, "Invalid host name: %s\n", optarg);
                        exit(1);
                    } else {
                        paddr = (struct in_addr *)hp->h_addr_list[0];
                        down_addr.sin_addr.s_addr = paddr->s_addr;
                    }
                } else {
                    down_addr.sin_addr.s_addr = inet_addr(optarg);
                }
            }
            break;
        case 'c':
            if (proxy_type != UNDEF_PROXY) {
                fprintf(stderr, "Only one of -s, -c, -r may be specified\n");
                exit(1);
            }
            proxy_type = CLIENT_PROXY;
            break;
        case 'r':
            if (proxy_type != UNDEF_PROXY) {
                fprintf(stderr, "Only one of -s, -c, -r may be specified\n");
                exit(1);
            }
            proxy_type = RESPONSE_PROXY;
            break;
        case 'd':
            debug = 1;
            break;
        case 'n':
            noname = 1;
            break;
        case 'v':
            verbose = atoi(optarg);
            break;
        case 'p':
            port = atoi(optarg);
            if (port == 0) {
                fprintf(stderr, "Invalid port\n");
                exit(1);
            }
            break;
        case 't':
            tmpval = atoi(optarg);
            if ((tmpval <= 0) || (tmpval > 255)) {
                fprintf(stderr, "Invalid ttl\n");
                exit(1);
            }
            ttl = (char)tmpval;
            break;
        case 'Q':
            tmpval = strtol(optarg, NULL, 0);
            if ((tmpval < 0) || (tmpval > 63)) {
                fprintf(stderr, "Invalid dscp\n");
                exit(1);
            }
            dscp = (tmpval & 0xFF) << 2;
            break;
        case 'O':
            if ((listidx = getifbyname(optarg, ifl, ifl_len)) != -1) {
                out_addr = ifl[listidx].addr;
                break;
            }
            if (inet_addr(optarg) == INADDR_NONE) {
                if ((hp = gethostbyname(optarg)) == NULL) {
                    fprintf(stderr, "Invalid host name: %s\n", optarg);
                    exit(1);
                } else {
                    paddr = (struct in_addr *)hp->h_addr_list[0];
                }
            } else {
                addr.s_addr = inet_addr(optarg);
                paddr = &addr;
            }
            if ((listidx = getifbyaddr(*paddr, ifl, ifl_len)) != -1) {
                out_addr = ifl[listidx].addr;
            } else {
                fprintf(stderr, "Interface %s not found\n", optarg);
                exit(1);
            }
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
        case 'q':
            out_port = atoi(optarg);
            if (out_port == 0) {
                fprintf(stderr, "Invalid outgoing port\n");
                exit(1);
            }
            break;
        case 'T':
            proxy_int = atoi(optarg);
            if ((proxy_int < 10) || (proxy_int >= 100)) {
                fprintf(stderr, "Invalid interval percentage\n");
                exit(1);
            }
            break;
        case 'm':
            sys_keys = 1;
            break;
        case 'H':
            p = strtok(optarg, ",");
            while (p != NULL) {
                p2 = strchr(p, ':');
                if (p2) {
                    hoststr = strdup(p);
                    hoststr[p2 - p] = '\x0';
                    portstr = p2 + 1;
                } else {
                    hoststr = p;
                    portstr = NULL;
                }
                hb_hosts[hbhost_count].sin_family = AF_INET;
                if (inet_addr(hoststr) == INADDR_NONE) {
                    if ((hp = gethostbyname(hoststr)) == NULL) {
                        fprintf(stderr, "Invalid host name: %s\n", hoststr);
                        exit(1);
                    } else {
                        paddr = (struct in_addr *)hp->h_addr_list[0];
                        hb_hosts[hbhost_count].sin_addr.s_addr = paddr->s_addr;
                    }
                } else {
                    hb_hosts[hbhost_count].sin_addr.s_addr = inet_addr(hoststr);
                }
                if (portstr) {
                    free(hoststr);
                    hbport = atoi(portstr);
                    if ((hbport <= 0) || (hbport > 65535)) {
                        hbport = DEF_PORT;
                    }
                } else {
                    hbport = DEF_PORT;
                }
                hb_hosts[hbhost_count++].sin_port = htons(hbport);
                p = strtok(NULL, ",");
            }
            break;
        case 'h':
            hb_interval = atoi(optarg);
            if ((hb_interval <= 0) || (hb_interval > 3600)) {
                fprintf(stderr, "Invalid hearbeat interval\n");
                exit(1);
            }
            break;
        case 'B':
            buffer = atoi(optarg);
            if ((buffer < 65536) || (buffer > 104857600)) {
                fprintf(stderr, "Invalid buffer size\n");
                exit(1);
            }
            break;
        case 'L':
            strncpy(logfile, optarg, sizeof(logfile)-1);
            logfile[sizeof(logfile)-1] = '\x0';
            break;
        case 'P':
            strncpy(pidfile, optarg, sizeof(pidfile)-1);
            pidfile[sizeof(pidfile)-1] = '\x0';
            break;
        case 'C':
            add_hosts_by_name(client_fp, &client_fp_count, optarg);
            break;
        case 'S':
            add_hosts_by_name(server_fp, &server_fp_count, optarg);
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
        case '?':
            fprintf(stderr, USAGE);
            exit(1);
        }
    }

    if (proxy_type == UNDEF_PROXY) {
        fprintf(stderr, "Either -s, -c, or -r must be specified\n");
        fprintf(stderr, USAGE);
        exit(1);
    }
    if (proxy_type != CLIENT_PROXY) {
        down_addr.sin_port = htons(out_port);
        if (server_fp_count) {
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
    if (proxy_type == RESPONSE_PROXY) {
        out_port = port;
    }
}

