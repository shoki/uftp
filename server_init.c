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

#include <process.h>
#include <ws2tcpip.h>
#include <io.h>

#else  // if WINDOWS

#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#endif

#include "server.h"
#include "server_config.h"
#include "server_init.h"

/**
 * Cleanup routine set up by atexit
 */
void cleanup(void)
{
    int i, j;

    closesocket(sock);
    if (keytype != KEY_NONE) {
        for (i = 0; i < destcount; i++) {
            if (destlist[i].pubkey) {
                free_RSA_key(destlist[i].pubkey);
            }
            free(destlist[i].last_status);
            for (j = 0; j < destlist[i].last_prstatus_cnt; j++) {
                free(destlist[i].last_prstatus[j]);
            }
        }
        free_RSA_key(privkey);
    }
    crypto_cleanup();

#ifdef WINDOWS
    WSACleanup();
#endif
}

/**
 * Do initial setup before parsing arguments, including getting interface list
 */
void pre_initialize()
{
#ifdef WINDOWS
    struct WSAData data;

    if (WSAStartup(2, &data)) {
        fprintf(stderr, "Error in WSAStartup: %d\n", WSAGetLastError());
        exit(1);
    }
#endif
    applog = stderr;
    ifl_len = sizeof(ifl) / sizeof(struct iflist);
    getiflist(ifl, &ifl_len);
    srand((unsigned int)time(NULL) ^ getpid());
    crypto_init(0);
}

/**
 * Do all socket creation and initialization
 */
void create_sockets()
{
    struct sockaddr_in sin;
    char *p, tmp_multi[IPSTR_LEN];
    int found_if, fdflag, i;

    // Create and bind socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        sockerror(0, 0, "Error creating socket");
        exit(1);
    }
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = 0;
    if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error binding socket");
        exit(1);
    }

    // Set send/receive buffer size, ttl, and multicast interface
    if (rcvbuf) {
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, 
                       sizeof(rcvbuf)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error setting receive buffer size");
            exit(1);
        }
        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&rcvbuf, 
                       sizeof(rcvbuf)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error setting send buffer size");
            exit(1);
        }
    } else {
        rcvbuf = DEF_RCVBUF;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, 
                       sizeof(rcvbuf)) == SOCKET_ERROR) {
            rcvbuf = DEF_BSD_RCVBUF;
            if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, 
                           sizeof(rcvbuf)) == SOCKET_ERROR) {
                sockerror(0, 0, "Error setting receive buffer size");
                exit(1);
            }
        }
        rcvbuf = DEF_RCVBUF;
        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&rcvbuf, 
                       sizeof(rcvbuf)) == SOCKET_ERROR) {
            rcvbuf = DEF_BSD_RCVBUF;
            if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&rcvbuf, 
                           sizeof(rcvbuf)) == SOCKET_ERROR) {
                sockerror(0, 0, "Error setting send buffer size");
                exit(1);
            }
        }
    }
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl, 
                   sizeof(ttl)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error setting ttl");
        closesocket(sock);
        exit(1);
    }
    if (setsockopt(sock, IPPROTO_IP, IP_TOS, (char *)&dscp, 
                   sizeof(dscp)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error setting dscp");
        closesocket(sock);
        exit(1);
    }
    if (out_addr.s_addr == INADDR_NONE) {
        for (i = 0, found_if = 0; (i < ifl_len) && !found_if; i++) {
            if (!ifl[i].isloopback) {
                found_if = 1;
                out_addr = ifl[i].addr;
            }
        }
        if (!found_if) {
            if (ifl_len > 0) {
                out_addr = ifl[0].addr;
            } else {
                fprintf(stderr, "ERROR: no network interfaces found!\n");
                exit(1);
            }
        }
    }
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char *)&out_addr, 
                   sizeof(out_addr)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error setting outgoing interface");
        closesocket(sock);
        exit(1);
    }
    // Make socket non-blocking
#ifndef BLOCKING
#ifdef WINDOWS
    fdflag = 1;
    if (ioctlsocket(sock, FIONBIO, &fdflag) == SOCKET_ERROR) {
        sockerror(0, 0, "Error setting non-blocking option");
        closesocket(sock);
        exit(1);
    }
#else
    if ((fdflag = fcntl(sock, F_GETFL)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error getting socket descriptor flags");
        closesocket(sock);
        exit(1);
    }
    fdflag |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, fdflag) == SOCKET_ERROR) {
        sockerror(0, 0, "Error setting non-blocking option");
        closesocket(sock);
        exit(1);
    }
#endif
#endif  // BLOCKING

    // Set up global sockaddr_in structs for public and private addresses
    // Perform octet substitution on private multicast address
    listen_dest.sin_family = AF_INET;
    listen_dest.sin_addr.s_addr = inet_addr(pub_multi);
    listen_dest.sin_port = htons(port);
    while ((p = strchr(priv_multi,'x')) != NULL) {
        memset(tmp_multi, 0, sizeof(tmp_multi));
        snprintf(tmp_multi, sizeof(tmp_multi), "%.*s%d%s",
                 (int)(p - priv_multi), priv_multi, rand() & 0xFF, p + 1);
        strcpy(priv_multi, tmp_multi);
    }
    receive_dest.sin_family = AF_INET;
    receive_dest.sin_addr.s_addr = inet_addr(priv_multi);
    receive_dest.sin_port = htons(port);
    if (unicast) {
        listen_dest.sin_addr = destlist[0].addr;
        receive_dest.sin_addr = destlist[0].addr;
    }
    if (listen_dest.sin_addr.s_addr == INADDR_NONE) {
        log(0, 0, "Invalid public address\n");
        exit(1);
    }
    if (receive_dest.sin_addr.s_addr == INADDR_NONE) {
        log(0, 0, "Invalid private address\n");
        exit(1);
    }
}

/**
 * Initialize crypto library, generate keys
 */
void key_init()
{
    unsigned char *prf_buf;
    time_t t;
    uint32_t t2;
    int explen, len;

    if (keytype == KEY_NONE) {
        return;
    }

    set_sys_keys(sys_keys);
    get_key_info(keytype, &keylen, &ivlen);
    hmaclen = get_hash_len(hashtype);

    memset(groupkey, 0, sizeof(groupkey));
    memset(groupsalt, 0, sizeof(groupsalt));
    memset(grouphmackey, 0, sizeof(grouphmackey));

    if (!get_random_bytes(groupmaster, sizeof(groupmaster))) {
        log(0, 0, "Failed to generate group master");
        exit(1);
    }
    groupmaster[0] = UFTP_VER_NUM;
    if (!get_random_bytes(rand1, sizeof(rand1))) {
        log(0, 0, "Failed to generate rand1");
        exit(1);
    }
    // Sets the first 4 bytes of rand1 to the current time
    t = time(NULL);
    t2 = (uint32_t)(t & 0xFFFFFFFF);
    *(uint32_t *)rand1 = t2;

    explen = hmaclen + keylen + ivlen;
    prf_buf = calloc(explen + hmaclen, 1);
    if (prf_buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    PRF(hashtype, explen, groupmaster, sizeof(groupmaster), "key expansion",
            rand1, sizeof(rand1), prf_buf, &len);
    memcpy(grouphmackey, prf_buf, hmaclen);
    memcpy(groupkey, prf_buf + hmaclen, keylen);
    memcpy(groupsalt, prf_buf + hmaclen + keylen, ivlen);
    free(prf_buf);

    if ((!strcmp(keyfile, "")) || (newkeylen != 0)) {
        privkey = gen_RSA_key(newkeylen, RSA_EXP, keyfile);
    } else {
        privkey = read_RSA_key(keyfile);
    }
    if (!privkey) {
        log(0, 0, "Failed to read/generate private key");
        exit(1);
    }

    rsalen = RSA_keylen(privkey);
}

/**
 * Initialization based on command line args
 */
void initialize()
{
    atexit(cleanup);

    if (strcmp(logfile, "")) {
        int fd;
        if ((fd = open(logfile, O_WRONLY | O_APPEND | O_CREAT, 0644)) == -1) {
            perror("Can't open log file");
            exit(1);
        }
        dup2(fd, 2);
        close(fd);
        showtime = 1;
    }
    applog = stderr;

    key_init();
    create_sockets();

    // Size of non-data packets including message specific header.
    // sizeof(ip) + sizeof(udp) = 20 + 8 = 28
    payloadsize = mtu - 28 - sizeof(struct uftp_h);

    // Size of encrypted packets
    // Leaves room for expansion due to symmetric key block size
    encpayloadsize = payloadsize - sizeof(struct encrypted_h) - KEYBLSIZE -
                     ((sigtype == SIG_RSA) ? rsalen : hmaclen );

    // Size of data block
    blocksize = ((keytype != KEY_NONE) ? encpayloadsize : payloadsize) -
                sizeof(struct fileseg_h);

    // Never ask for a client key with no encryption,
    // and always ask with RSA signatures
    if (keytype == KEY_NONE) {
        client_auth = 0;
    } else if (sigtype == SIG_RSA) {
        client_auth = 1;
    }

    if (rate == -1) {
        packet_wait = 0;
    } else {
        packet_wait = (int32_t)(1000000.0 * mtu / ((float)rate * 1024 / 8));
    }
}

