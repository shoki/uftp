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

#ifndef _UFTP_H
#define _UFTP_H

#ifdef WINDOWS

#include <winsock2.h>

typedef unsigned __int8 uint8_t;
typedef __int8 int8_t;
typedef unsigned __int16 uint16_t;
typedef __int16 int16_t;
typedef unsigned __int32 uint32_t;
typedef __int32 int32_t;
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;

#define open(name, ...) _open(name, __VA_ARGS__)
#define read(fd, buf, count) _read(fd, buf, count)
#define close(fd) _close(fd)
#define write(fd, buf, count) _write(fd, buf, count)
#define dup2(fd1, fd2) _dup2(fd1, fd2)
#define unlink(file) _unlink(file)
#define rmdir(dir) _rmdir(dir)
#define getpid() _getpid()
#define mkdir(dir, mode) _mkdir(dir)
#define usleep(t) Sleep((t)/1000)
#define sleep(t) Sleep((t)*1000)
#define strdup(p) _strdup(p)
#define isfullpath(str) (((str[1] == ':') && (str[2] == '\\')) || \
                         ((str[0] == '\\') && (str[1] == '\\')))
#define PATH_SEP '\\'

typedef int64_t f_offset_t;
typedef struct __stat64 stat_struct;
#define stat_func(name, buf) _stat64(name, buf)
#define lstat_func(name, buf) _stat64(name, buf)
#define S_ISCHR(mode)   (((mode) & S_IFMT) == S_IFCHR)
#define S_ISDIR(mode)   (((mode) & S_IFMT) == S_IFDIR)
#define S_ISREG(mode)   (((mode) & S_IFMT) == S_IFREG)
#define lseek_func(fd, offset, whence) _lseeki64(fd, offset, whence)
#define snprintf(buf, cnt, ...) _snprintf(buf, cnt, __VA_ARGS__)


typedef int socklen_t;
#define OPENREAD (O_RDONLY | O_BINARY)
#define OPENWRITE (O_WRONLY | O_BINARY)

#else  // if WINDOWS

#include <netinet/in.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <sys/time.h>

#define closesocket(s) close(s)

#ifdef VMS
pid_t GENERIC_SETSID(void);
#define setsid GENERIC_SETSID
#define fork vfork
typedef unsigned int socklen_t;
#define isfullpath(str) (1)
#define PATH_SEP ':'
#define open(name, flag, mode) open(name, flag, mode, "ctx=stm")
#else
#define isfullpath(str) (str[0] == '/')
#define PATH_SEP '/'
#endif

typedef int64_t f_offset_t;
typedef struct stat stat_struct;
#define stat_func(name, buf) stat(name, buf)
#define lstat_func(name, buf) lstat(name, buf)
#define lseek_func(fd, offset, whence) lseek(fd, offset, whence)

typedef int SOCKET;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif
#define OPENREAD (O_RDONLY)
#define OPENWRITE (O_WRONLY)

#endif // if WINDOWS

#define VERSIONSTR "UFTP version 3.4.3  Copyright (C) 2001-2011  Dennis A. Bush"
#define UFTP_VER_NUM 0x30

#define ANNOUNCE    1
#define REGISTER    2
#define CLIENT_KEY  3
#define REG_CONF    4
#define FILEINFO    5
#define KEYINFO     6
#define INFO_ACK    7
#define FILESEG     8
#define DONE        9
#define STATUS     10
#define PRSTATUS   11
#define COMPLETE   12
#define DONE_CONF  13
#define HB_REQ     14
#define HB_RESP    15
#define KEY_REQ    16
#define PROXY_KEY  17
#define ENCRYPTED  80
#define ABORT      99 

#define MAXDEST 10000
#define MAXFILENAME 100
#define MAXDIRNAME 200
#define MAXPATHNAME 300
#define MAXPROXYDEST 1000

#define DESTNAME_LEN 100
#define MAXFILES 500
#define IFNAME_LEN 25
#define MAX_INTERFACES 20
#define IPSTR_LEN 16

#define FTYPE_REG 0
#define FTYPE_DIR 1
#define FTYPE_LINK 2

#define KEY_NONE 0x00
#define KEY_DES 0x01
#define KEY_DES_EDE3 0x02
#define KEY_AES128 0x03
#define KEY_AES256 0x04

#define HASH_NONE 0x00
#define HASH_MD5 0x01
#define HASH_SHA1 0x02
#define HASH_SHA256 0x03

#define SIG_NONE 0x00
#define SIG_HMAC 0x01
#define SIG_RSA 0x02

#define FLAG_RESTART 0x01

#define FLAG_PARTIAL 0x01

#define PUBKEY_LEN 256  // big enough for RSA-2048
#define RAND_LEN 32     // rfc 5246
#define HMAC_LEN 32     // big enough for SHA-256
#define VERIFY_LEN 12   // rfc 5246
#define MASTER_LEN 48   // rfc 5246
#define MAXIV 16        // big enough for AES256
#define MAXKEY 32       // big enough for AES256
#define KEYBLSIZE 16    // Maximum symetric key blocksize
#define DEF_RSA_LEN 512 // Default length of generated RSA keys
#define RSA_EXP 65537   // Public key exponent of generated RSA keys

struct uftp_h {
    uint8_t uftp_id;
    uint8_t func;
    uint16_t blsize;
    uint32_t group_id;
    uint32_t srcaddr;       // local IP of sender
    uint32_t destaddr;      // IP of receiver (multicast for server)
};  // sizeof = 16

struct encrypted_h {
    uint32_t tstamp_sec;
    uint32_t tstamp_usec;
    uint16_t sig_len;
    uint16_t payload_len;
};  // sizeof = 12 + sig_len + payload_len

struct announce_h {
    uint8_t func;  // always ANNOUNCE
    uint8_t flags;
    uint16_t destcount;
    uint16_t announce_int;
    uint16_t status_int;
    uint16_t register_int;
    uint16_t done_int;
    uint8_t announce_time;
    uint8_t status_time;
    uint16_t mtu;
    uint32_t privatemcast;
    uint8_t client_auth;
    uint8_t sigtype;
    uint8_t hashtype;
    uint8_t keytype;
    uint16_t keylen;
    uint16_t reserved;
    uint32_t keyexp;
    uint8_t rand1[RAND_LEN];
    //uint8_t keymod[PUBKEY_LEN];
};  // sizeof = 64 + keylen + sizeof(uint32_t)*destcount

struct client_key_h {
    uint8_t func;  // always CLIENT_KEY
    uint8_t reserved1;
    uint16_t reserved2;
    uint16_t keylen;
    uint16_t verifylen;
    uint32_t keyexp;
    //uint8_t keymod[PUBKEY_LEN];
    //uint8_t verify[PUBKEY_LEN];
};  // sizeof = 12 + (2 * keylen)

struct register_h {
    uint8_t func;  // always REGISTER
    uint8_t reserved1;
    uint16_t reserved2;
    uint16_t destcount;
    uint16_t premaster_len;
    uint8_t rand2[RAND_LEN];
    //uint8_t premaster[PUBKEY_LEN];     // RSA encrypted, 48 byte per rfc5246
};  // sizeof = 40 + server_key_len + sizeof(uint32_t)*destcount

struct regconf_h {
    uint8_t func;  // always REG_CONF
    uint8_t reserved;
    uint16_t destcount;
};  // sizeof = 4 + sizeof(uint32_t)*destcount

struct fileinfo_h {
    uint8_t func;  // always FILEINFO
    uint8_t ftype;
    uint16_t file_id;
    uint32_t block_total;
    uint16_t section_total;
    uint16_t destcount;
    uint32_t hifsize, lofsize;
    char name[MAXPATHNAME];
};  // sizeof = 320 + sizeof(uint32_t)*destcount

struct keyinfo_h {
    uint8_t func;  // always KEYINFO
    uint8_t reserved;
    uint8_t destcount;
    uint8_t groupmaster_len;
    uint32_t tstamp_sec;
    uint32_t tstamp_usec;
};  // sizeof = 12 + sizeof(destkey)*destcount

struct destkey {
    uint32_t destaddr;
    uint8_t groupmaster[MASTER_LEN];      // based on 16 byte blocksize
};  // sizeof = 52 */

struct infoack_h {
    uint8_t func;  // always INFO_ACK
    uint8_t flags;
    uint16_t file_id;
    uint16_t destcount;
    uint16_t reserved;
    uint8_t verify_data[VERIFY_LEN];
};  // sizeof = 20 + sizeof(uint32_t)*destcount */

struct fileseg_h {
    uint8_t func;  // always FILESEG
    uint8_t reserved1;
    uint16_t file_id;
    uint8_t pass;
    uint8_t reserved2;
    uint16_t section;
    uint32_t seq_num;
};  // sizeof = 12

struct done_h {
    uint8_t func;  // always DONE
    uint8_t pass;
    uint16_t section;
    uint16_t file_id;
    uint16_t destcount;
};  // sizeof = 8 + sizeof(uint32_t)*destcount

struct status_h {
    uint8_t func;  // always STATUS
    uint8_t reserved;
    uint16_t file_id;
    uint8_t pass;
    uint8_t seq;
    uint16_t section;
    int32_t nak_count;
};  // sizeof = 12

struct prstatus_h {
    uint8_t func;  // always PRSTATUS
    uint8_t reserved1;
    uint16_t file_id;
    uint8_t pass;
    uint8_t seq;
    uint16_t section;
    uint16_t destcount;
    uint16_t reserved2;
};  // sizeof = 12 + sizeof(uint32_t)*destcount

struct complete_h {
    uint8_t func;  // always COMPLETE
    uint8_t reserved1;
    uint16_t file_id;
    uint16_t destcount;
    uint16_t reserved2;
};  // sizeof = 8 + sizeof(uint32_t)*destcount

struct doneconf_h {
    uint8_t func;  // always DONE_CONF
    uint8_t reserved1;
    uint16_t file_id;
    uint16_t destcount;
    uint16_t reserved2;
};  // sizeof = 8 + sizeof(uint32_t)*destcount

struct abort_h {
    uint8_t func;  // always ABORT
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t host;
    char message[300];
};  // sizeof = 308

struct hb_req_h {
    uint8_t func;  // always HB_REQ
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t nonce;
    uint16_t keylen;
    uint16_t siglen;
    uint32_t keyexp;
    //uint8_t keymod[PUBKEY_LEN];
    //uint8_t verify[PUBKEY_LEN];
};  // sizeof = 16 + (2 * keylen)

struct hb_resp_h {
    uint8_t func;  // always HB_RESP
    uint8_t authenticated;
    uint16_t reserved;
    uint32_t nonce;
};  // sizeof = 8

struct key_req_h {
    uint8_t func;  // always KEY_REQ
    uint8_t reserved1;
    uint16_t reserved2;
};  // sizeof = 4

struct proxy_key_h {
    uint8_t func;  // always PROXY_KEY
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t nonce;
    uint16_t keylen;
    uint16_t siglen;
    uint32_t keyexp;
    //uint8_t keymod[PUBKEY_LEN];
    //uint8_t verify[PUBKEY_LEN];
};  // sizeof = 16 + (2 * keylen)

struct iflist {
    char name[IFNAME_LEN];
    struct in_addr addr;
    int isloopback;
    int ismulti;
};

#endif  // _UFTP_H
