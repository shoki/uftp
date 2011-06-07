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

#ifndef _CLIENT_H
#define _CLIENT_H

#include "uftp_common.h"
#include "uftp2.h"
#include "encryption.h"

/**
 * Current state of client for a given group
 */
enum client_phase {
    PHASE_REGISTERED = 1,       /// Registered and awaiting KEYINFO or REG_CONF
    PHASE_RECEIVING = 2,        /// Currently receiving a file
    PHASE_COMPLETE = 3,         /// Completed group and awaiting DONE_CONF
    PHASE_MIDGROUP = 4          /// Registered awaiting next file or group end
};

/**
 * Info pertaining to current file
 */
struct file_t {
    uint32_t blocks;            // Total blocks
    uint32_t sections;          // Total sections
    int ftype;                  // File type (regular, directory, symlink)
    f_offset_t size;            // Size in bytes
    char name[MAXPATHNAME];     // Path name
    char linkname[MAXPATHNAME]; // Link name (symlinks only)
    uint8_t *naklist;           // NAK list
    uint8_t *section_done;      // Array of done flags for each section
    int fd;                     // File descriptor for file
    int wait;                   // True if only last block in section is missing
    int last_block;             // Block number of last block received
    f_offset_t curr_offset;     // Current file pointer offset in fd
    int restart;                // True if restarting a prior session
};

/**
 * Header of client save state file.
 * Followed in the file by the NAK list and section_done list.
 * The naklist and section_done fields are left blank when the struct is
 * written to a file.  When read back in, memory is allocated and the
 * NAK list and section_done list are written to them.
 */
struct client_restart_t {
    uint32_t blocks;            // Total blocks
    uint32_t sections;          // Total sections
    f_offset_t size;            // Size in bytes
    char name[MAXPATHNAME];     // Path name
    uint8_t *naklist;           // NAK list
    uint8_t *section_done;      // Array of done flags for each section
};

/**
 * Info for a particular group
 */
struct group_list_t {
    uint32_t group_id;              /// Group ID
    uint16_t file_id;               /// File ID of current file
    uint8_t version;                /// Protocol version number of server
    struct in_addr multi;           /// Private multicast address
    int multi_join;                 /// True if we're listening on private addr
    int announce_time, register_int, status_time, done_int;
    struct in_addr srcaddr, destaddr;
    struct sockaddr_in replyaddr;
    int phase;                      /// Current client_phase of the group
    int client_auth, restart;       /// Flags from the server's ANNOUNCE
    struct client_restart_t *restartinfo; /// Restart file header
    unsigned int mtu, payloadsize, encpayloadsize, blocksize;
    struct timeval timeout_time, expire_time;
    int keytype, hashtype, sigtype; /// Key, hash, and sig types from server
    RSA_key_t serverkey;            /// Server's RSA public key
    RSA_key_t clientkey;            /// Client's RSA private key for this group
    unsigned int server_keylen;     /// Length in bytes of server key
    unsigned int client_keylen;     /// Length in bytes of client key
    uint8_t rand1[RAND_LEN];        /// Server's random number
    uint8_t rand2[RAND_LEN];        /// Client's random number
    uint8_t premaster[MASTER_LEN];  /// Premaster secret sent by client
    uint8_t master[MASTER_LEN];     /// Master key for client
    uint8_t hmackey[HMAC_LEN];      /// HMAC key for client
    uint8_t key[MAXKEY];            /// Symmetric encryption key for client
    uint8_t salt[MAXIV];            /// Salt for block cypher IV for client
    uint8_t groupmaster[MASTER_LEN];/// Master key for server
    uint8_t grouphmackey[HMAC_LEN]; /// HMAC key for server
    uint8_t groupkey[MAXKEY];       /// Symmetric encryption key for server
    uint8_t groupsalt[MAXIV];       /// Salt for block cypher IV for server
    int ivlen, keylen, hmaclen;     /// Length of HMAC key, symmetric key and iv
    struct file_t fileinfo;         /// Info pertaining to current file
};

#define MAXLIST 100
#define KEY_REQ_INT 5

/**
 * Global command line values and sockets
 */
extern SOCKET listener;
extern char tempdir[MAXDIRNAME], destdir[MAXDIRNAME];
extern char logfile[MAXPATHNAME], pidfile[MAXPATHNAME];
extern char keyfile[MAXLIST][MAXPATHNAME];
extern int verbose, noname, debug, newkeylen, encrypted_only, dscp;
extern int interface_count, pub_multi_count, keyfile_count, buffer;
extern uint16_t port;
extern uint32_t uid;
extern struct iflist m_interface[MAX_INTERFACES];
extern struct in_addr pub_multi[MAX_INTERFACES];
extern struct group_list_t group_list[MAXLIST];
extern struct fp_list_t server_keys[MAXLIST];
extern struct iflist ifl[MAX_INTERFACES];
extern struct timeval next_keyreq_time;
extern int ifl_len, server_count, key_count, has_proxy, sys_keys;
extern RSA_key_t privkey[MAXLIST];
extern struct fp_list_t proxy_info;
extern RSA_key_t proxy_key;

#endif  // _CLIENT_H

