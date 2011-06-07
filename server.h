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

#ifndef _SERVER_H
#define _SERVER_H

#include "uftp_common.h"
#include "encryption.h"

/**
 * Values for deststate_t.status
 */ 
enum client_status {
    DEST_MUTE = -4,         /// Expected client that hasn't registered
    DEST_LOST = -3,         /// Client that timed out responding to a DONE
    DEST_ABORT = -2,        /// An ABORT was either sent to or received from
    DEST_REGISTERED = -1,   /// Registered but haven't received INFO_ACK
    DEST_ACTIVE = 0,        /// Ready to receive data
    DEST_STATUS = 1,        /// Active but not yet received STATUS or COMPLETE
    DEST_DONE = 2           /// Client finished successfully, sent COMPLETE
};

/**
 * Destination state for a particular destination and file
 */
struct deststate_t {
    int conf_sent;          /// False if REG_CONF or DONE_CONF needs to be sent
    struct timeval time;    /// Time that this client finished
    int naks;               /// Total NAKS for this client
};

/**
 * File info struct
 */
struct finfo_t {
    int ftype;              /// File type (regular, directory, symlink)
    const char *basedir;    /// Base pathname of file in filesystem
    const char *filename;   /// Local name of file (may include path)
    const char *linkname;   /// For symbolic links, the text of the link
    const char *destfname;  /// Transmitted name of file (may include path)
    f_offset_t size;        /// File size in bytes
    uint32_t blocks;        /// Total blocks in file
    uint32_t sections;      /// Total sections in file
    uint32_t group_id;      /// Group ID
    uint16_t file_id;       /// File ID
    char *naklist;          /// Aggregate NAK list
    int partial;            /// True if all clients partially received last run
    struct deststate_t *deststate;  /// Status array for each client
};

#define PRSTATUS_CNT 10

/**
 * Destination info
 */
struct destinfo_t {
    char name[DESTNAME_LEN];        /// Hostname of client
    struct in_addr addr;            /// IP address of client
    int proxyidx;                   /// Index of the proxy serving this client
    int clientcnt;                  /// The number of clients a proxy serves
    uint16_t clients[MAXPROXYDEST]; /// Indexes of clients served by this proxy
    RSA_key_t pubkey;               /// The client's RSA public key
    int pubkeylen;                  /// The client's RSA key length in bytes
    uint8_t verifydata[PUBKEY_LEN]; /// The verify data from a CLIENT_KEY
    uint16_t verifylen;             /// The length of verifydata in bytes
    int status;                     /// Specified by a client_status value
    int registered;                 /// True if we received a REGISTER
    int verified;                   /// True if we have a verified CLIENT_KEY
    int has_fingerprint;            /// True if we have client's key fingerprint
    uint8_t keyfingerprint[HMAC_LEN];       /// Fingerprint of RSA key
    uint8_t rand2[RAND_LEN];        /// Client's random number
    uint8_t premaster[MASTER_LEN];  /// Premaster secret sent by client
    uint8_t master[MASTER_LEN];     /// Master key for client
    uint8_t hmackey[HMAC_LEN];      /// HMAC key for client
    uint8_t key[MAXKEY];            /// Symmetric encryption key for client
    uint8_t salt[MAXIV];            /// Salt for block cypher IV for client
    uint8_t *last_status;           /// For proxies, last STATUS message
    uint8_t *last_prstatus[PRSTATUS_CNT];   /// For proxies, last PRSTATUS msg
    int last_prstatus_cnt;          /// Number of messages in last_prstatus
};

/**
 * Header of server restart file.
 * Followed in the file by filecount file names of MAXPATHNAME length,
 * followed by an arbitrary number of server_restart_host_t entries.
 */
struct server_restart_t {
    uint32_t group_id;              /// Group ID of failed transfer
    int filecount;                  /// Number of files specified on cmdline
};

/**
 * Server restart file entry for a particular host.
 */
struct server_restart_host_t {
    char name[DESTNAME_LEN];        /// Hostname of client
    struct in_addr addr;            /// IP address of client
    int has_fingerprint;            /// True if we have client's key fingerprint
    uint8_t keyfingerprint[HMAC_LEN];       /// Fingerprint of RSA key
    int is_proxy;                   /// True if this is a proxy
};

/**
 * Global command line values and sockets
 */
extern SOCKET sock;
extern struct sockaddr_in listen_dest, receive_dest;
extern int weight, min_time, rate, port, rcvbuf, packet_wait, follow_links;
extern int noname, unicast, verbose, client_auth, quit_on_error, dscp;
extern int save_fail, restart_groupid;
extern int announce_time, status_time;
extern int announce_int, status_int, register_int, done_int;
extern unsigned char ttl;
extern char pub_multi[IPSTR_LEN], priv_multi[IPSTR_LEN], destfname[MAXPATHNAME];
extern char logfile[MAXPATHNAME], keyfile[MAXPATHNAME];
extern char filelist[MAXFILES][MAXPATHNAME], exclude[MAXFILES][MAXPATHNAME];
extern struct iflist ifl[MAX_INTERFACES];
extern int keytype, hashtype, sigtype, newkeylen;
extern int mtu, blocksize, encpayloadsize, payloadsize;
extern int ifl_len, destcount, filecount, excludecount;
extern struct in_addr out_addr;
extern struct destinfo_t destlist[MAXDEST];

/**
 * Encryption variables
 */
extern RSA_key_t privkey;
extern unsigned char rand1[RAND_LEN], groupmaster[MASTER_LEN];
extern uint8_t groupsalt[MAXIV], groupkey[MAXKEY], grouphmackey[HMAC_LEN];
extern int ivlen, keylen, hmaclen, rsalen, sys_keys;

#endif  // _SERVER_H

