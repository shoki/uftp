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

#ifndef _UFTP_COMMON_H
#define _UFTP_COMMON_H

#include <stdio.h>

#include "uftp.h"
#include "encryption.h"

extern int showtime;
extern FILE *applog;

void logfunc(uint32_t group_id, uint16_t file_id, int _showtime,
             int newline, int err, int sockerr, const char *str, ...);

#define clog(group_id, file_id, ...) \
    logfunc(group_id, file_id, showtime, 0, 0, 0, __VA_ARGS__)
#define log(group_id, file_id, ...) \
    logfunc(group_id, file_id, showtime, 1, 0, 0, __VA_ARGS__)
#define sclog(...) \
    logfunc(0, 0, 0, 0, 0, 0, __VA_ARGS__)
#define slog(...) \
    logfunc(0, 0, 0, 1, 0, 0, __VA_ARGS__)
#define syserror(group_id, file_id, ...) \
    logfunc(group_id, file_id, showtime, 1, errno, 0, __VA_ARGS__)
#define sockerror(group_id, file_id, ...) \
    logfunc(group_id, file_id, showtime, 1, errno, 1, __VA_ARGS__)

const char *func_name(int func);
int32_t diff_sec(struct timeval t2, struct timeval t1);
int64_t diff_usec(struct timeval t2, struct timeval t1);
int cmptimestamp(struct timeval t1, struct timeval t2);
const char *printll(int64_t n);
void getiflist(struct iflist *list, int *len);
void split_path(const char *path, char **dir, char **file);
int parse_fingerprint(unsigned char *fingerprint, const char *fingerprint_str);
int is_multicast(struct in_addr addr, int ssm);
struct in_addr to_addr(uint32_t addr);

int would_block_err();
int nb_sendto(SOCKET s, const void *msg, int len, int flags,
              const struct sockaddr *to, int tolen);
int read_packet(SOCKET sock, struct sockaddr_in *sin, unsigned char *buffer,
                int *len, int bsize, const struct timeval *timeout);
void build_iv(uint8_t *iv, const uint8_t *salt, int saltlen, uint32_t group_id,
              uint32_t addr, uint32_t time_sec, uint32_t time_usec);
void printhex(const char *name, const unsigned char *data, int len);
int encrypt_and_sign(const unsigned char *decpacket, unsigned char **encpacket,
                     int declen, int mtu, int keytype, uint8_t *key,
                     const uint8_t *salt, int ivlen,
                     int hashtype, uint8_t *hmackey, uint8_t hmaclen,
                     int sigtype, RSA_key_t rsakey, int rsalen);
int validate_and_decrypt(const unsigned char *encpacket,
                         unsigned char **decpacket, unsigned int *declen,
                         int mtu, int keytype, const uint8_t *key,
                         const uint8_t *salt, int ivlen, int hashtype,
                         const uint8_t *hmackey, uint8_t hmaclen, int sigtype,
                         RSA_key_t rsakey, int rsalen);
void PRF(int hash, int bytes, const unsigned char *secret, int secret_len,
         const char *label, const unsigned char *seed, int seed_len,
         unsigned char *outbuf, int *outbuf_len);
const char *print_key_fingerprint(const RSA_key_t key);

/**
 * Key fingerprint for an allowed server or client
 */
struct fp_list_t {
    struct in_addr addr;
    int has_fingerprint;
    uint8_t fingerprint[HMAC_LEN];
};

int multicast_join(SOCKET s, uint32_t group_id, const struct in_addr *multi,
                   const struct iflist *addrlist, int addrlen,
                   const struct fp_list_t *fplist, int fplist_len);
void multicast_leave(SOCKET s, uint32_t group_id, const struct in_addr *multi,
                     const struct iflist *addrlist, int addrlen,
                     const struct fp_list_t *fplist, int fplist_len);

int getifbyname(const char *name, const struct iflist *list, int len);
int getifbyaddr(struct in_addr addr, const struct iflist *list, int len);

int file_read(int fd, void *buf, int buflen, int allow_eof);
int file_write(int fd, const void *buf, int buflen);

#endif  // _UFTP_COMMON_H

