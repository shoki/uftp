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
#include <signal.h>
#include <time.h>
#include <errno.h>

#ifdef WINDOWS

#include <process.h>
#include <ws2tcpip.h>
#include <io.h>

#else // WINDOWS

#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#endif

#include "proxy.h"
#include "proxy_init.h"
#include "proxy_config.h"
#include "proxy_common.h"

static int parent;  // is this the parent process that exits after a fork?

/**
 * Cleanup routine set up by atexit
 */
void cleanup(void)
{
    int i;

    for (i = 0; i < MAXLIST; i++) {
        if (group_list[i].group_id != 0) {
            group_cleanup(i);
        }
    }
    if (!parent) {
        for (i = 0; i < pub_multi_count; i++) {
            multicast_leave(listener, 0, &pub_multi[i], m_interface,
                            interface_count, server_fp, server_fp_count);
        }
    }
    closesocket(listener);

    for (i = 0; i < key_count; i++) {
        free_RSA_key(privkey[i]);
    }
    crypto_cleanup();

#ifdef WINDOWS
    WSACleanup();
#endif
    fclose(stderr);
}

/**
 * Generic signal handler, exits on signal
 */
void gotsig(int sig)
{
    log(0, 0, "Exiting on signal %d", sig);
    exit(0);
}

/**
 * Signal handler for SIGPIPE
 */
void gotpipe(int sig)
{
    log(0, 0, "Got SIGPIPE");
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
}

/**
 * Set up log file and run in the backgroud
 */
void daemonize()
{
#ifdef WINDOWS
    if (!debug) {
        int fd;
        FILE *pidfh;

        if ((fd = open(logfile, O_WRONLY | O_APPEND | O_CREAT, 0644)) == -1) {
            perror("Can't open log file");
            exit(1);
        }
        if (strcmp(pidfile, "")) {
            // Write out the pid file, before we redirect STDERR to the log.
            if ((pidfh = fopen(pidfile, "w")) == NULL) {
                perror("Can't open pid file for writing");
                exit(1);
            }
            fprintf(pidfh, "%d\n", GetCurrentProcessId());
            fclose(pidfh);
        }
        dup2(fd, 2);
        close(fd);
        applog = stderr;
    }
#else  // WINDOWS
    if (!debug) {
        int pid, fd;
        FILE *pidfh;

        if ((fd = open(logfile, O_WRONLY | O_APPEND | O_CREAT, 0644)) == -1) {
            perror("Can't open log file");
            exit(1);
        }
        if ((pid = fork()) == -1) {
            perror("Couldn't fork");
            exit(1);
        } else if (pid > 0) {
            parent = 1;
            exit(0);
        }
        if (strcmp(pidfile, "")) {
            // Write out the pid file, before we redirect STDERR to the log.
            if ((pidfh = fopen(pidfile, "w")) == NULL) {
                perror("Can't open pid file for writing");
                exit(1);
            }
            fprintf(pidfh, "%d\n", getpid());
            fclose(pidfh);
        }
        setsid();
        dup2(fd, 2);
        close(fd);
        for (fd = 0; fd < 30; fd++) {
            if ((fd != 2) && (fd != listener)) {
                close(fd);
            }
        }
#ifdef VMS
        chdir("SYS$LOGIN");
#else
        chdir("/");
#endif
        umask(0);
        applog = stderr;
    }

    nice(-20);
    {
        struct sigaction act;

        sigfillset(&act.sa_mask);
        act.sa_flags = SA_NOCLDSTOP | SA_NOCLDWAIT | SA_RESTART;

        act.sa_handler = gotsig;
        sigaction(SIGINT, &act, NULL);
        sigaction(SIGTERM, &act, NULL);
        act.sa_handler = gotpipe;
        sigaction(SIGPIPE, &act, NULL);
        act.sa_handler = SIG_IGN;
        sigaction(SIGCHLD, &act, NULL);
    }
#endif  // WINDOWS
}

/**
 * Initialize crypto library, generate keys
 */
void key_init()
{
#ifndef NO_ENCRYPTION
    int i;

    crypto_init(sys_keys);

    if ((keyfile_count == 0) || (newkeylen != 0)) {
        privkey[0] = gen_RSA_key(newkeylen, RSA_EXP, keyfile[0]);
        if (!privkey[0]) {
            exit(1);
        }
        key_count = 1;
    } else {
        for (i = 0; i < keyfile_count; i++) {
            privkey[key_count] = read_RSA_key(keyfile[i]);
            if (!privkey[key_count]) {
                exit(1);
            }
            key_count++;
        }
    }
#endif
}

/**
 * Do all socket creation and initialization
 */
void create_sockets()
{
    struct sockaddr_in sin;
    int fdflag, found_if, i;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(port);
    if ((listener = socket(AF_INET,SOCK_DGRAM,0)) == INVALID_SOCKET) {
        sockerror(0, 0, "Error creating socket for listener");
        exit(1);
    }
    if (bind(listener, (struct sockaddr *)&sin, sizeof(sin)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error binding socket for listener");
        exit(1);
    }
#ifndef BLOCKING
#ifdef WINDOWS
    fdflag = 1;
    if (ioctlsocket(listener, FIONBIO, &fdflag) == SOCKET_ERROR) {
        sockerror(0, 0, "Error setting non-blocking option");
        closesocket(listener);
        exit(1);
    }
#else
    if ((fdflag = fcntl(listener, F_GETFL)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error getting socket descriptor flags");
        closesocket(listener);
        exit(1);
    }
    fdflag |= O_NONBLOCK;
    if (fcntl(listener, F_SETFL, fdflag) == SOCKET_ERROR) {
        sockerror(0, 0, "Error setting non-blocking option");
        closesocket(listener);
        exit(1);
    }
#endif
#endif  // BLOCKING
    if (setsockopt(listener, IPPROTO_IP, IP_TOS, (char *)&dscp,
                   sizeof(dscp)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error setting dscp");
        closesocket(listener);
        exit(1);
    }
    if (buffer) {
        if (setsockopt(listener, SOL_SOCKET, SO_RCVBUF,
                       (char *)&buffer, sizeof(buffer)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error setting receive buffer size");
            exit(1);
        }
        if (setsockopt(listener, SOL_SOCKET, SO_SNDBUF,
                       (char *)&buffer, sizeof(buffer)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error setting send buffer size");
            exit(1);
        }
    } else {
        buffer = DEF_RCVBUF;
        if (setsockopt(listener, SOL_SOCKET, SO_RCVBUF,
                       (char *)&buffer, sizeof(buffer)) == SOCKET_ERROR) {
            buffer = DEF_BSD_RCVBUF;
            if (setsockopt(listener, SOL_SOCKET, SO_RCVBUF,
                           (char *)&buffer, sizeof(buffer)) == SOCKET_ERROR) {
                sockerror(0, 0, "Error setting receive buffer size");
                exit(1);
            }
        }
        buffer = DEF_RCVBUF;
        if (setsockopt(listener, SOL_SOCKET, SO_SNDBUF,
                       (char *)&buffer, sizeof(buffer)) == SOCKET_ERROR) {
            buffer = DEF_BSD_RCVBUF;
            if (setsockopt(listener, SOL_SOCKET, SO_SNDBUF,
                           (char *)&buffer, sizeof(buffer)) == SOCKET_ERROR) {
                sockerror(0, 0, "Error setting send buffer size");
                exit(1);
            }
        }
    }
    if (setsockopt(listener, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
                   sizeof(ttl)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error setting ttl");
        closesocket(listener);
        exit(1);
    }
    if (out_addr.s_addr == INADDR_NONE) {
        for (i = 0, found_if = 0; (i < ifl_len) && !found_if; i++) {
            if (!ifl[i].isloopback) {
                found_if = 1;
                out_addr.s_addr = ifl[i].addr.s_addr;
            }
        }
        if (!found_if) {
            if (ifl_len > 0) {
                out_addr.s_addr = ifl[0].addr.s_addr;
            } else {
                fprintf(stderr, "ERROR: no network interfaces found!\n");
                exit(1);
            }
        }
    }
    if (setsockopt(listener, IPPROTO_IP, IP_MULTICAST_IF, (char *)&out_addr,
                   sizeof(out_addr)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error setting outgoing interface");
        closesocket(listener);
        exit(1);
    }

    for (i = 0; i < pub_multi_count; i++) {
        if (!multicast_join(listener, 0, &pub_multi[i], m_interface,
                            interface_count, server_fp, server_fp_count)) {
            exit(1);
        }
    }
}

/**
 * Initialization based on command line args
 */
void initialize()
{
    char hostname[256];
    struct hostent *hp;
    struct in_addr *addr;
    int i;

    parent = 0;

    // Load list of multicast interfaces
    if (interface_count == 0) {
        for (i = 0; i < ifl_len; i++) {
            if (!ifl[i].isloopback) {
                m_interface[interface_count++] = ifl[i];
            }
        }
    }
    // No non-loopback interfaces, so just use the hostname's interface
    if (interface_count == 0) {
        gethostname(hostname, sizeof(hostname));
        if ((hp = gethostbyname(hostname)) == NULL) {
            fprintf(stderr, "Can't get host name\n");
            exit(1);
        } else {
            addr = (struct in_addr *)hp->h_addr_list[0];
            m_interface[interface_count].addr = *addr;
            m_interface[interface_count++].ismulti = 1;
            m_interface[interface_count++].isloopback = 0;
        }
    }
    if (uid) {
        m_interface[interface_count].addr.s_addr = uid;
        m_interface[interface_count++].ismulti = 0;
        m_interface[interface_count++].isloopback = 0;
    }

    if (proxy_type == CLIENT_PROXY) {
        pub_multi_count = 0;
    } else if (!pub_multi_count) {
        pub_multi[0].s_addr = inet_addr(DEF_PUB_MULTI);
        pub_multi_count = 1;
    }

    for (i = 0; i < MAXLIST; i++) {
        group_list[i].group_id = 0;
    }
    next_hb_time.tv_sec = 0;
    next_hb_time.tv_usec = 0;
    last_key_req.tv_sec = 0;
    last_key_req.tv_usec = 0;

    atexit(cleanup);
    key_init();
    create_sockets();

    daemonize();
    showtime = 1;
}

