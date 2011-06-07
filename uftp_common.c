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
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#ifdef WINDOWS

#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "uftp.h"
#include "uftp2.h"
#include "uftp_common.h"
#include "encryption.h"
#include "win_func.h"

void getiflist(struct iflist *list, int *len)
{
    SOCKET s;
    int rval, rsize, count, i;
    INTERFACE_INFO *iflist;

    if (*len <= 0) return;
    count = *len;
    iflist = malloc(sizeof(INTERFACE_INFO) * count);
    if (iflist == NULL) {
        syserror(0, 0, "malloc failed!");
        exit(1);
    }
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        sockerror(0, 0, "Error creating socket for interface list");
        free(iflist);
        *len = 0;
        return;
    }
    if ((rval = WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0, iflist,
            sizeof(INTERFACE_INFO) * count, &rsize, NULL, NULL)) ==
                SOCKET_ERROR) {
        sockerror(0, 0, "Error getting interface list");
        closesocket(s);
        free(iflist);
        *len = 0;
        return;
    }
    count = rsize / sizeof(INTERFACE_INFO);
    for (i = 0, *len = 0; i < count; i++) {
        if ((iflist[i].iiFlags & IFF_UP) != 0) {
            memset(&list[*len], 0, sizeof(struct iflist));
            strcpy(list[*len].name, "");
            list[*len].addr.s_addr =
                    iflist[i].iiAddress.AddressIn.sin_addr.s_addr;
            list[*len].isloopback = (iflist[i].iiFlags&IFF_LOOPBACK) != 0;
            list[*len].ismulti = (iflist[i].iiFlags&IFF_MULTICAST) != 0;
            (*len)++;
        }
    }
    free(iflist);
    closesocket(s);
}

#else  /*if WINDOWS*/

#include <libgen.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

#include "uftp.h"
#include "uftp2.h"
#include "uftp_common.h"
#include "encryption.h"

#ifdef HAS_GETIFADDRS

#include <ifaddrs.h>

void getiflist(struct iflist *list, int *len)
{
    struct ifaddrs *ifa, *ifa_tmp;
    struct sockaddr_in *in;
    int count;

    if (getifaddrs(&ifa) == -1) {
        syserror(0, 0, "getifaddrs failed");
        *len = 0;
        return;
    }
    ifa_tmp = ifa;
    count = *len;
    *len = 0;
    while (ifa_tmp && (*len < count)) {
        in = (struct sockaddr_in *)ifa_tmp->ifa_addr;
        if (in && (in->sin_family == AF_INET) &&
                    ((ifa_tmp->ifa_flags & IFF_UP) != 0)) {
            memset(&list[*len], 0, sizeof(struct iflist));
            strncpy(list[*len].name, ifa_tmp->ifa_name,
                    sizeof(list[*len].name) - 1);
            list[*len].addr.s_addr = in->sin_addr.s_addr;
            list[*len].isloopback = (ifa_tmp->ifa_flags & IFF_LOOPBACK) != 0;
            list[*len].ismulti = (ifa_tmp->ifa_flags & IFF_MULTICAST) != 0;
            (*len)++;
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }
    freeifaddrs(ifa);
}

#else

void getiflist(struct iflist *list, int *len)
{
    int s, i, count;
    struct ifconf ifc;
    struct ifreq *ifr;
    struct ifreq ifr_tmp;
    struct sockaddr_in *in;

    if (*len <= 0) return;
    count = *len;
    ifr = malloc(sizeof(struct ifreq) * count);
    if (ifr == NULL) {
        syserror(0, 0, "malloc failed!");
        exit(1);
    }
    ifc.ifc_len = sizeof(struct ifreq) * count;
    ifc.ifc_req = ifr;

    if ((s = socket(AF_INET,SOCK_DGRAM, 0)) == -1) {
        sockerror(0, 0, "Error creating socket for interface list");
        free(ifr);
        *len = 0;
        return;
    }
    if (ioctl(s, SIOCGIFCONF, &ifc) == -1) {
        syserror(0, 0, "Error getting interface list");
        free(ifr);
        close(s);
        *len = 0;
        return;
    }
    count = ifc.ifc_len / sizeof(struct ifreq);
    for (i = 0, *len = 0; i < count; i++) {
        in = (struct sockaddr_in *)&ifr[i].ifr_addr;
        strcpy(ifr_tmp.ifr_name, ifr[i].ifr_name);
        if (ioctl(s, SIOCGIFFLAGS, &ifr_tmp) == -1) {
            continue;
        }
        if (in && (in->sin_family == AF_INET) &&
                    ((ifr_tmp.ifr_flags & IFF_UP) != 0)) {
            memset(&list[*len], 0, sizeof(struct iflist));
            strncpy(list[*len].name, ifr[i].ifr_name, sizeof(list[i].name) - 1);
            list[*len].addr.s_addr = in->sin_addr.s_addr;
            list[*len].isloopback = (ifr_tmp.ifr_flags & IFF_LOOPBACK) != 0;
            list[*len].ismulti = (ifr_tmp.ifr_flags & IFF_MULTICAST) != 0;
            (*len)++;
        }
    }
    free(ifr);
    close(s);
}

#endif /*if Sun*/

#ifdef VMS
pid_t GENERIC_SETSID(void) { return(0); }
#endif

#endif /*if WINDOWS*/

const char *printll(int64_t n)
{
    static char str[50];

#ifdef WINDOWS
    snprintf(str, sizeof(str) - 1, "%I64d", n);
#else
    snprintf(str, sizeof(str) - 1, "%lld", (long long)n);
#endif
    str[sizeof(str) - 1] = '\x0';
    return &str[0];
}


int32_t diff_sec(struct timeval t2, struct timeval t1)
{
    return t2.tv_sec - t1.tv_sec;
}

int64_t diff_usec(struct timeval t2, struct timeval t1)
{
    return (t2.tv_usec - t1.tv_usec) +
            (int64_t)1000000 * (t2.tv_sec - t1.tv_sec);
}

int cmptimestamp(struct timeval t1, struct timeval t2)
{
    if (t1.tv_sec > t2.tv_sec) {
        return 1;
    } else if (t1.tv_sec < t2.tv_sec) {
        return -1;
    } else if (t1.tv_usec > t2.tv_usec) {
        return 1;
    } else if (t1.tv_usec < t2.tv_usec) {
        return -1;
    } else {
        return 0;
    }
}

const char *func_name(int func)
{
    switch (func) {
    case ANNOUNCE:
        return "ANNOUNCE";
    case REGISTER:
        return "REGISTER";
    case CLIENT_KEY:
        return "CLIENT_KEY";
    case REG_CONF:
        return "REG_CONF";
    case KEYINFO:
        return "KEYINFO";
    case FILEINFO:
        return "FILEINFO";
    case INFO_ACK:
        return "INFO_ACK";
    case FILESEG:
        return "FILESEG";
    case DONE:
        return "DONE";
    case PRSTATUS:
        return "PRSTATUS";
    case STATUS:
        return "STATUS";
    case COMPLETE:
        return "COMPLETE";
    case DONE_CONF:
        return "DONE_CONF";
    case HB_REQ:
        return "HB_REQ";
    case HB_RESP:
        return "HB_RESP";
    case KEY_REQ:
        return "KEY_REQ";
    case PROXY_KEY:
        return "PROXY_KEY";
    case ENCRYPTED:
        return "ENCRYPTED";
    case ABORT:
        return "ABORT";
    default:
        return "UNKNOWN";
  }
}

const char *v2_func_name(int func)
{
    switch (func) {
    case V2_ANNOUNCE:
        return "ANNOUNCE";
    case V2_REGISTER:
        return "REGISTER";
    case V2_REG_CONF:
        return "REG_CONF";
    case V2_FILESEG:
        return "FILESEG";
    case V2_DONE:
        return "DONE";
    case V2_STATUS:
        return "STATUS";
    case V2_DONE_CONF:
        return "DONE_CONF";
    case V2_ABORT:
        return "ABORT";
    default:
        return "UNKNOWN";
  }
}

int showtime;
FILE *applog;

void logfunc(uint32_t group_id, uint16_t file_id, int _showtime,
             int newline, int err, int sockerr, const char *str, ...)
{
    struct tm *timeval;
    struct timeval tv;
    time_t t;
    va_list args;
 
    if (_showtime) {
        gettimeofday(&tv, NULL);
        // In Windows, tv.tv_sec is long, not time_t
        t = tv.tv_sec;
        timeval = localtime(&t);
        fprintf(applog, "%04d/%02d/%02d %02d:%02d:%02d.%06d: ",
                timeval->tm_year + 1900, timeval->tm_mon + 1, timeval->tm_mday,
                timeval->tm_hour, timeval->tm_min, timeval->tm_sec,
                (int)tv.tv_usec);
    }
    if (group_id && file_id) {
        fprintf(applog, "[%08X:%04X]: ", group_id, file_id);
    } else if (group_id && !file_id) {
        fprintf(applog, "[%08X:0]: ", group_id);
    } else if (!group_id && file_id) {
        fprintf(applog, "[%04X]: ", file_id);
    }
    va_start(args, str);
    vfprintf(applog, str, args);
    va_end(args);
    if (sockerr) {
#ifdef WINDOWS
        char errbuf[300];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, WSAGetLastError(),
                      0, errbuf, sizeof(errbuf), NULL);
        fprintf(applog, ": (%d) %s", WSAGetLastError(), errbuf);
        newline = 0;
#else
        fprintf(applog, ": %s", strerror(err));
#endif
    } else if (err) {
        fprintf(applog, ": %s", strerror(err));
    } 
    if (newline) {
        fprintf(applog, "\n");
    }
    fflush(applog);
}

/**
 * Takes a pathname and splits it into a directory part and file part.
 * The caller is expected to clean up *dir and *file.
 */
void split_path(const char *path, char **dir, char **file)
{
#ifdef WINDOWS
    char *result, *filename;
    DWORD len, len2;

    if (strlen(path) == 0) {
        *dir = NULL;
        *file = NULL;
        return;
    }

    // GetFullPathNameA doens't handle trailing slashes well, so disallow
    if ((path[strlen(path)-1] == '/') || (path[strlen(path)-1] == '\\')) {
        log(0, 0, "bad path, trailing / or \\ not allowed");
        *dir = NULL;
        *file = NULL;
        return;
    }

    len = GetFullPathNameA(path, 0, NULL, &filename);

    *dir = NULL;
    *file = NULL;
    result = malloc(len);
    if (!result) {
        syserror(0, 0, "malloc failed!");
        exit(1);
    }
    if ((len2 = GetFullPathNameA(path, len, result, &filename)) <= len) {
        *dir = strdup(result);
        *file = strdup(filename);
        if (!*dir || (filename && !*file)) {
            syserror(0, 0, "strdup failed!");
            exit(1);
        }
        (*dir)[strlen(*dir) - strlen(*file) - 1] = '\x0';
    }
    free(result);
#else
    char *dirc, *filec;

    dirc = strdup(path);
    filec = strdup(path);
    if (!dirc || !filec) {
        syserror(0, 0, "strdup failed!");
        exit(1);
    }
    *dir = strdup(dirname(dirc));
    *file = strdup(basename(filec));
    if (!*dir || !*file) {
        syserror(0, 0, "strdup failed!");
        exit(1);
    }
    free(dirc);
    free(filec);
#endif
}

/**
 * Parses a key fingerprint string and saves it to the specified buffer
 * Returns 1 on success, 0 on fail
 */
int parse_fingerprint(unsigned char *fingerprint, const char *fingerprint_str)
{
    char *p, *tmp;
    int num, len;

    if (fingerprint_str == NULL) {
        return 0;
    }
    tmp = strdup(fingerprint_str);
    len = 0;
    p = strtok(tmp, ":");
    if (p == NULL) {
        log(0, 0, "Invalid fingerprint %s", fingerprint_str);
        return 0;
    }
    do {
        if (len >= HMAC_LEN) {
            log(0, 0, "Key fingerprint %s too long", fingerprint_str);
            free(tmp);
            return 0;
        }
        errno = 0;
        num = strtol(p, NULL, 16);
        if (errno) {
            syserror(0, 0, "Parse of host key fingerprint %s failed",
                           fingerprint_str);
            free(tmp);
            return 0;
        } else if ((num > 255) || (num < 0)) {
            log(0, 0, "Parse of host key fingerprint %s failed",
                      fingerprint_str);
            free(tmp);
            return 0;
        }
        fingerprint[len++] = (uint8_t)num;
        p = strtok(NULL, ":");
    } while (p);
    free(tmp);
    return 1;
}

/**
 * Tests a struct in_addr to see if it's a valid multicast address
 */
int is_multicast(struct in_addr addr, int ssm)
{
    int val;

    val = ntohl(addr.s_addr) >> 24;
    if (ssm && (val != 232)) {
        return 0;
    } else if ((val >= 224) && (val < 240)) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * Returns a struct in_addr based on the given 32-bit value
 */
struct in_addr to_addr(uint32_t addr)
{
    struct in_addr inaddr;

    inaddr.s_addr = addr;
    return inaddr;
}

/**
 * Returns whether the last socket operation would have blocked
 */
int would_block_err()
{
#ifdef WINDOWS
    return (WSAGetLastError() == WSAEWOULDBLOCK);
#else
    return (errno == EAGAIN);
#endif
}

/**
 * Calls sendto, retrying if the send would block.
 * The calling function should check for and log any other errors.
 */
int nb_sendto(SOCKET s, const void *msg, int len, int flags,
              const struct sockaddr *to, int tolen)
{
    int retry, sentlen;

    retry = 1;
    while (retry) {
        if ((sentlen = sendto(s, msg, len, flags, to, tolen)) == SOCKET_ERROR) {
            if (!would_block_err()) {
                return -1;
            }
        } else {
            retry = 0;
        }
    }
    return sentlen;
}

/**
 * Reads a packet off the network with a possible timeout.
 * The socket must be non-blocking.
 * Returns 1 on success, 0 on timeout, -1 on fail.
 */
int read_packet(SOCKET sock, struct sockaddr_in *sin, unsigned char *buffer,
                int *len, int bsize, const struct timeval *timeout)
{
    fd_set fdin;
    struct timeval tv;
    int rval;
    socklen_t addr_len;

#ifdef BLOCKING
    FD_ZERO(&fdin);
    FD_SET(sock,&fdin);
    if (timeout) tv = *timeout;
    if ((rval = select(FD_SETSIZE-1, &fdin, NULL, NULL,
                       (timeout ? &tv : NULL))) == SOCKET_ERROR) {
        sockerror(0, 0, "Select failed");
        return -1;
    }
    if (rval == 0) {
        return 0;
    } else if (FD_ISSET(sock, &fdin)) {
        addr_len = sizeof(struct sockaddr_in);
        if ((*len = recvfrom(sock, buffer, bsize, 0, (struct sockaddr *)sin,
                             &addr_len)) == SOCKET_ERROR) {
#ifdef WINDOWS
            if (WSAGetLastError() != WSAECONNRESET) {
#else
            if (errno != ECONNRESET) {
#endif
                sockerror(0, 0, "Error receiving");
            }
            return -1;
        }
        return 1;
    } else {
        log(0, 0, "Unknown select error");
        return -1;
    }
#else  // BLOCKING
    while (1) {
        addr_len = sizeof(struct sockaddr_in);
        if ((*len = recvfrom(sock, buffer, bsize, 0, (struct sockaddr *)sin,
                             &addr_len)) == SOCKET_ERROR) {
            if (!would_block_err()) {
#ifdef WINDOWS
                if (WSAGetLastError() != WSAECONNRESET) {
#else
                if (errno != ECONNRESET) {
#endif
                    sockerror(0, 0, "Error receiving");
                }
                return -1;
            }
        } else {
            return 1;
        }

        FD_ZERO(&fdin);
        FD_SET(sock,&fdin);
        if (timeout) tv = *timeout;
        if ((rval = select(FD_SETSIZE-1, &fdin, NULL, NULL,
                           (timeout ? &tv : NULL))) == SOCKET_ERROR) {
            sockerror(0, 0, "Select failed");
            return -1;
        }
        if (rval == 0) {
            return 0;
        } else if (!FD_ISSET(sock, &fdin)) {
            log(0, 0, "Unknown select error");
            return -1;
        }
    }
#endif  // BLOCKING
}

/**
 * Performs an XOR between p1 and p2, storing the result in p1
 */
void memxor(void *p1, const void *p2, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        ((unsigned char *)p1)[i] ^= ((unsigned char *)p2)[i];
    }
}

/**
 * Constructs an initialization vector (IV) from a salt value
 * and encrypted packet as follows:
 * For a 128-bit IV:  IV = S XOR (group_ID + IP + T)
 * For a 64-bit IV:   IV = S XOR (group_ID + IP) XOR T
 * All values should be in network byte order.
 */
void build_iv(uint8_t *iv, const uint8_t *salt, int saltlen, uint32_t group_id,
              uint32_t addr, uint32_t time_sec, uint32_t time_usec)
{
    char tmp[16], tmp2[8];
    int tmplen, tmp2len;

    memcpy(tmp, &group_id, sizeof(uint32_t));
    tmplen = sizeof(uint32_t);
    memcpy(tmp + tmplen, &addr, sizeof(uint32_t));
    tmplen += sizeof(uint32_t);
    if (saltlen == 8) {
        memcpy(tmp2, &time_sec, sizeof(uint32_t));
        tmp2len = sizeof(uint32_t);
        memcpy(tmp2 + tmp2len, &time_usec, sizeof(uint32_t));
        tmp2len += sizeof(uint32_t);
        memxor(tmp, tmp2, tmp2len);
    } else {
        memcpy(tmp + tmplen, &time_sec, sizeof(uint32_t));
        tmplen = sizeof(uint32_t);
        memcpy(tmp + tmplen, &time_usec, sizeof(uint32_t));
        tmplen += sizeof(uint32_t);
    }
    memcpy(iv, salt, saltlen);
    memxor(iv, tmp, tmplen);
}

/**
 * Outputs data buffers to log in hex.
 * Used only for debugging
 */
void printhex(const char *name, const unsigned char *data, int len)
{
    int i;

    sclog("%s:", name);
    for (i = 0; i < len; i++) {
        sclog(" %02X", data[i]);
        if (i % 16 == 15) sclog("\n");
    }
    sclog("\n");
}

/**
 * Verify the signature of an encrypted message and decrypt.
 * The decrypted message is returned without a uftp_h header.
 * Returns 1 on success, 0 on fail
 */
int validate_and_decrypt(const unsigned char *encpacket,
                         unsigned char **decpacket, unsigned int *declen,
                         int mtu, int keytype, const uint8_t *key,
                         const uint8_t *salt, int ivlen, int hashtype,
                         const uint8_t *hmackey, uint8_t hmaclen, int sigtype,
                         RSA_key_t rsakey, int rsalen)
{
    struct uftp_h *header;
    struct encrypted_h *encrypted;
    unsigned char *payload, *sig, *sigcopy, *sigtest, *iv;
    unsigned int hsiglen, siglen, len, rval, allocdec;

    if (sigtype == SIG_HMAC) {
        siglen = hmaclen;
    } else if (sigtype == SIG_RSA) {
        siglen = rsalen;
    } else {
        log(0, 0, "Invalid signature type");
        return 0;
    }

    header = (struct uftp_h *)encpacket;
    encrypted = (struct encrypted_h *)(encpacket + sizeof(struct uftp_h));
    hsiglen = ntohs(encrypted->sig_len);
    sig = (unsigned char *)encrypted + sizeof(struct encrypted_h);
    payload = sig + hsiglen;

    if (header->func != ENCRYPTED) {
        log(0, 0, "Attempt to decrypt non-encrypted message");
        return 0;
    }
    if (ntohs(header->blsize) != (sizeof(struct encrypted_h) +
            hsiglen + ntohs(encrypted->payload_len))) {
        log(0, 0, "Invalid signature and/or encrypted payload length");
        return 0;
    }
    if (hsiglen != siglen) {
        log(0, 0, "Signature length incorrect: got %d, expected %d",
                  hsiglen, siglen);
        return 0;
    }

    sigcopy = calloc(siglen, 1);
    sigtest = calloc(siglen, 1);
    iv = calloc(ivlen, 1);
    if ((sigcopy == NULL) || (sigtest == NULL) || (iv == NULL)) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    memcpy(sigcopy, sig, hsiglen);
    memset(sig, 0, hsiglen);
    if (sigtype == SIG_HMAC) {
        if (!create_hmac(hashtype, hmackey, hsiglen, encpacket,
                         sizeof(struct uftp_h) + ntohs(header->blsize),
                         sigtest, &len)) {
            log(0, 0, "HMAC creation failed");
            rval = 0;
            goto end;
        }
        if (memcmp(sigtest, sigcopy, len)) {
            log(0, 0, "HMAC verification failed");
            rval = 0;
            goto end;
        }
    } else {
        if (!verify_RSA_sig(rsakey, hashtype, encpacket,
                            sizeof(struct uftp_h) + ntohs(header->blsize),
                            sigcopy, ntohs(encrypted->sig_len))) {
            log(0, 0, "RSA signature verification failed");
            rval = 0;
            goto end;
        }
    }

    allocdec = 0;
    if (*decpacket == NULL) {
        allocdec = 1;
        *decpacket = calloc(mtu + KEYBLSIZE, 1);
        if (*decpacket == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
    }
    build_iv(iv, salt, ivlen, header->group_id, header->srcaddr,
             encrypted->tstamp_sec, encrypted->tstamp_usec);
    if (!decrypt_block(keytype, iv, key, payload,
            ntohs(encrypted->payload_len), *decpacket, declen)) {
        log(0, 0, "Decrypt failed");
        if (allocdec) {
            free(*decpacket);
            *decpacket = NULL;
        }
        rval = 0;
        goto end;
    }

    rval = 1;

end:
    free(sigcopy);
    free(sigtest);
    free(iv);
    return rval;
}

/**
 * Encrypts a message and attaches a signature to the encrypted message.
 * The incoming message should include a uftp_h header.
 * Returns 1 on success, 0 on fail
 */
int encrypt_and_sign(const unsigned char *decpacket, unsigned char **encpacket,
                     int declen, int mtu, int keytype, uint8_t *key,
                     const uint8_t *salt, int ivlen,
                     int hashtype, uint8_t *hmackey, uint8_t hmaclen,
                     int sigtype, RSA_key_t rsakey, int rsalen)
{
    struct uftp_h *header;
    struct encrypted_h *encrypted;
    const unsigned char *mheader;
    unsigned char *payload, *sig, *sigcopy, *iv;
    unsigned int enclen, siglen, len, allocenc;
    struct timeval tv;

    if (sigtype == SIG_HMAC) {
        siglen = hmaclen;
    } else if (sigtype == SIG_RSA) {
        siglen = rsalen;
    } else {
        log(0, 0, "Invalid signature type");
        return 0;
    }

    allocenc = 0;
    if (*encpacket == NULL) {
        allocenc = 1;
        *encpacket = calloc(mtu + KEYBLSIZE, 1);
        if (*encpacket == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
    }
    iv = calloc(ivlen, 1);
    if (iv == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    mheader = decpacket + sizeof(struct uftp_h);
    header = (struct uftp_h *)*encpacket;
    encrypted = (struct encrypted_h *)(*encpacket + sizeof(struct uftp_h));
    sig = (unsigned char *)encrypted + sizeof(struct encrypted_h);
    payload = sig + siglen;

    memcpy(*encpacket, decpacket, sizeof(struct uftp_h));
    gettimeofday(&tv, NULL);
    build_iv(iv, salt, ivlen, header->group_id, header->srcaddr,
             htonl(tv.tv_sec), htonl(tv.tv_usec));
    if (!encrypt_block(keytype, iv, key, mheader, declen, payload, &enclen)) {
        // Called function should log
        free(iv);
        if (allocenc) {
            free(*encpacket);
            *encpacket = NULL;
        }
        return 0;
    }
    header->func = ENCRYPTED;
    header->blsize = htons(sizeof(struct encrypted_h) + enclen + siglen);
    encrypted->tstamp_sec = htonl(tv.tv_sec);
    encrypted->tstamp_usec = htonl(tv.tv_usec);
    encrypted->sig_len = htons(siglen);
    encrypted->payload_len = htons(enclen);

    sigcopy = calloc(siglen, 1);
    if (sigcopy == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    memset(sig, 0, siglen);
    if (sigtype == SIG_HMAC) {
        if (!create_hmac(hashtype, hmackey, siglen, *encpacket,
                         sizeof(struct uftp_h) + ntohs(header->blsize),
                         sigcopy, &len)) {
            log(0, 0, "HMAC creation failed");
            free(iv);
            free(sigcopy);
            if (allocenc) {
                free(*encpacket);
                *encpacket = NULL;
            }
            return 0;
        }
    } else {
        if (!create_RSA_sig(rsakey, hashtype, *encpacket,
                            sizeof(struct uftp_h) + ntohs(header->blsize),
                            sigcopy, &len)) {
            // Called function should log
            free(iv);
            free(sigcopy);
            if (allocenc) {
                free(*encpacket);
                *encpacket = NULL;
            }
            return 0;
        }
    }
    memcpy(sig, sigcopy, len);

    free(iv);
    free(sigcopy);
    return 1;
}

/**
 * Psedo-random function for an individual hashing algorithm
 * as defined in RFC 4346 and RFC 5246
 */
static void P_hash(int hash, int bytes, 
                   const unsigned char *secret, int secret_len, 
                   const char *label, const unsigned char *seed, int seed_len,
                   unsigned char *outbuf, int *outbuf_len)
{
    unsigned char *newseed, *inbuf, *tmpbuf;
    unsigned newseed_len, inbuf_len;
    unsigned int tmpbuf_len, outbuf_len_new;

    newseed = calloc(strlen(label) + seed_len, 1);
    inbuf = calloc(get_hash_len(hash) + strlen(label) + seed_len, 1);
    tmpbuf = calloc(get_hash_len(hash) + strlen(label) + seed_len, 1);
    if ((newseed == NULL) || (inbuf == NULL) || (tmpbuf == NULL)) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    *outbuf_len = 0;
    newseed_len = 0;
    memcpy(newseed, label, strlen(label));
    newseed_len += strlen(label);
    memcpy(newseed + newseed_len, seed, seed_len);
    newseed_len += seed_len;

    memcpy(inbuf, newseed, newseed_len);
    inbuf_len = newseed_len;
    while (*outbuf_len < bytes)
    {
        // TODO: create_hmac can fail under CrypoAPI.
        // Figure out how to handle this.
        create_hmac(hash, secret, secret_len, inbuf, inbuf_len,
                    tmpbuf, &tmpbuf_len);
        memcpy(tmpbuf + tmpbuf_len, newseed, newseed_len);
        tmpbuf_len += newseed_len;
        create_hmac(hash, secret, secret_len, tmpbuf, tmpbuf_len, 
                    outbuf + *outbuf_len, &outbuf_len_new);
        *outbuf_len += outbuf_len_new;
        memcpy(inbuf,tmpbuf,tmpbuf_len);
        inbuf_len = tmpbuf_len;
    }

    free(newseed);
    free(inbuf);
    free(tmpbuf);
}

/**
 * Psedo-random function
 * as defined in RFC 4346 and RFC 5246
 */
void PRF(int hash, int bytes, const unsigned char *secret, int secret_len, 
         const char *label, const unsigned char *seed, int seed_len,
         unsigned char *outbuf, int *outbuf_len)
{
    int i, s_len, sha_buf_len, md5_buf_len;
    unsigned char *sha_buf, *md5_buf;

    if (hash == HASH_SHA256) {
        P_hash(HASH_SHA256, bytes, secret, secret_len, label,
               seed, seed_len, outbuf, outbuf_len);
    } else if (hash == HASH_SHA1) {
        // TLS 1.1 MD5/SHA1 combination
        md5_buf = calloc(bytes + get_hash_len(HASH_MD5), 1);
        sha_buf = calloc(bytes + get_hash_len(HASH_SHA1), 1);
        if ((md5_buf == NULL) || (sha_buf == NULL)) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        // if secret_len is even integer division truncates the result
        // if secret_len is odd, the + 1 effectively rounds up
        s_len = (secret_len + 1) / 2;
        P_hash(HASH_MD5, bytes, secret, s_len, label,
               seed, seed_len, md5_buf, &md5_buf_len);
        P_hash(HASH_SHA1, bytes, secret + (secret_len - s_len), s_len, label,
               seed, seed_len, sha_buf, &sha_buf_len);
        for (i = 0; i < bytes; i++) {
            outbuf[i] = md5_buf[i] ^ sha_buf[i];
        }
        *outbuf_len = bytes;
        free(md5_buf);
        free(sha_buf);
    } else {
        *outbuf_len = 0;
    }
}

/**
 * Outputs a key's fingerprint
 */
const char *print_key_fingerprint(const RSA_key_t key)
{
    static char fpstr[100];
    char *p;
    unsigned char keymod[PUBKEY_LEN], fingerprint[HMAC_LEN], *keydata;
    uint32_t exponent;
    uint16_t modlen;
    unsigned int keylen, fplen, i, cnt;

    if (!export_RSA_key(key, &exponent, keymod, &modlen)) {
        return NULL;
    }
    exponent = htonl(exponent);

    keylen = 0;
    keydata = calloc(sizeof(exponent) + modlen, 1);
    if (keydata == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    memcpy(keydata, &exponent, sizeof(exponent));
    keylen += sizeof(exponent);
    memcpy(keydata + keylen, keymod, modlen);
    keylen += modlen;
    hash(HASH_SHA1, keydata, keylen, fingerprint, &fplen);

    for (i = 0, p = fpstr; i < fplen; i++) {
        if (i != 0) {
            *p = ':';
            p++;
        }
        cnt = sprintf(p, "%02X", fingerprint[i]);
        p += cnt;
    }

    free(keydata);
    return fpstr;
}

/**
 * Join the specified multicast group on the specified list of interfaces.
 * If source specific multicast is supported and we're given a list of servers,
 * join source specific multicast groups for those servers.
 * Returns 1 on success, 0 on fail
 */
int multicast_join(SOCKET s, uint32_t group_id, const struct in_addr *multi,
                   const struct iflist *addrlist, int addrlen,
                   const struct fp_list_t *fplist, int fplist_len)
{
    struct ip_mreq mreq;
    int i;

    for (i = 0; i < addrlen; i++) {
        if (!addrlist[i].ismulti) {
            continue;
        }
#ifdef IP_ADD_SOURCE_MEMBERSHIP
        if (fplist_len != 0) {
            int j;
            for (j = 0; j < fplist_len; j++) {
                struct ip_mreq_source srcmreq;
                srcmreq.imr_multiaddr = *multi;
                srcmreq.imr_sourceaddr = fplist[j].addr;
                srcmreq.imr_interface = addrlist[i].addr;
                if (setsockopt(s, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP,
                        (char *)&srcmreq, sizeof(srcmreq)) == SOCKET_ERROR) {
                    sockerror(group_id, 0, "Error joining multicast group"); 
                    return 0;
                }
            }
        } else {
            mreq.imr_multiaddr = *multi;
            mreq.imr_interface = addrlist[i].addr;
            if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                           (char *)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
                sockerror(group_id, 0, "Error joining multicast group");
                return 0;
            }
        }
#else
        mreq.imr_multiaddr = *multi;
        mreq.imr_interface = addrlist[i].addr;
        if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                       (char *)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
            sockerror(group_id, 0, "Error joining multicast group");
            return 0;
        }
#endif
    }
    return 1;
}

/**
 * Leave the specified multicast group on the specified list of interfaces.
 * If source specific multicast is supported and we're given a list of servers,
 * leave source specific multicast groups for those servers.
 */
void multicast_leave(SOCKET s, uint32_t group_id, const struct in_addr *multi,
                     const struct iflist *addrlist, int addrlen,
                     const struct fp_list_t *fplist, int fplist_len)
{
    struct ip_mreq mreq;
    int i;

    for (i = 0; i < addrlen; i++) {
        if (!addrlist[i].ismulti) {
            continue;
        }
#ifdef IP_DROP_SOURCE_MEMBERSHIP
        if (fplist_len != 0) {
            int j;
            for (j = 0; j < fplist_len; j++) {
                struct ip_mreq_source srcmreq;
                srcmreq.imr_multiaddr = *multi;
                srcmreq.imr_sourceaddr = fplist[j].addr;
                srcmreq.imr_interface = addrlist[i].addr;
                if (setsockopt(s, IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP,
                        (char *)&srcmreq, sizeof(srcmreq)) == SOCKET_ERROR) {
                    sockerror(group_id, 0, "Error leaving multicast group"); 
                }
            }
        } else {
            mreq.imr_multiaddr = *multi;
            mreq.imr_interface = addrlist[i].addr;
            if (setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                           (char *)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
                sockerror(group_id, 0, "Error leaving multicast group");
            }
        }
#else
        mreq.imr_multiaddr = *multi;
        mreq.imr_interface = addrlist[i].addr;
        if (setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                       (char *)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
            sockerror(group_id, 0, "Error leaving multicast group");
        }
#endif
    }
}

/**
 * Search for a network interface in a list with the matching name.
 * Returns the index in the list if found, -1 if not found.
 */
int getifbyname(const char *name, const struct iflist *list, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (!strcmp(name, list[i].name)) {
            return i;
        }
    }
    return -1;
}

/**
 * Search for a network interface in a list with the matching IP address.
 * Returns the index in the list if found, -1 if not found.
 */
int getifbyaddr(struct in_addr addr, const struct iflist *list, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (addr.s_addr == list[i].addr.s_addr) {
            return i;
        }
    }
    return -1;
}

/**
 * Reads buflen bytes into buf from the given file descriptor.
 * If buflen bytes are read, returns buflen.
 * If 0 bytes are read, returns 0 if allow_eof is true, otherwise returns -1.
 * If less that buflen bytes are read, or on error, returns -1.
 */
int file_read(int fd, void *buf, int buflen, int allow_eof)
{
    int read_len;

    if ((read_len = read(fd, buf, buflen)) == -1) {
        syserror(0, 0, "Read failed");
        return -1;
    }
    if ((read_len != buflen) && (!allow_eof || (read_len != 0))) {
        log(0, 0, "Read error: read %d bytes, expected %d", read_len, buflen);
        return -1;
    }
    return read_len;
}
/**
 * Writes buflen bytes from buf to the given file descriptor.
 * If buflen bytes are written, returns buflen.
 * If less that buflen bytes are written, or on error, returns -1.
 */
int file_write(int fd, const void *buf, int buflen)
{
    int write_len;

    if ((write_len = write(fd, buf, buflen)) == -1) {
        syserror(0, 0, "Write failed");
        return -1;
    }
    if (write_len != buflen) {
        log(0, 0, "Write error: wrote %d bytes, expected %d", write_len,buflen);
        return -1;
    }
    return write_len;
}

