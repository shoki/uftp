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

#ifndef _PROXY_H
#define _PROXY_H

#include "uftp_common.h"
#include "encryption.h"

/**
 * Type of proxy
 */
enum proxy_type {
    UNDEF_PROXY = 0,            /// Not specified, indicates an error
    SERVER_PROXY = 1,           /// Server proxy: forwards to a specific place
    CLIENT_PROXY = 2,           /// Client proxy: sends to specified destaddr
    RESPONSE_PROXY = 3,         /// Response proxy: response aggregation only
};

/**
 * The state of the given group
 */
enum proxy_phase {
    PR_PHASE_REGISTERED = 1,    /// Currently setting up group
    PR_PHASE_READY = 2,         /// Still in setup, but received KEYINFO
    PR_PHASE_RECEIVING = 3,     /// Group setup complete
    PR_PHASE_DONE = 4,          /// All clients send COMPLETE for group
};

/**
 * The state of a given client when encryption is enabled
 */
enum proxy_client_state {
    PR_CLIENT_MUTE = 0,         /// Got nothing yet
    PR_CLIENT_REGISTERED = 1,   /// Got REGISTER (and CLIENT_KEY if required)
    PR_CLIENT_CONF = 2,         /// Got REG_CONF from server
    PR_CLIENT_READY = 3,        /// Got INFO_ACK in response to KEYINFO 
    PR_CLIENT_DONE = 4,         /// Sent COMPLETE for group
};

enum hb_auth {
    HB_AUTH_FAILED = 0,         /// Heartbeat authorization failed
    HB_AUTH_OK = 1,             /// Successfully authorized heartbeat
    HB_AUTH_CHALLENGE = 2,      /// Authorized heartbeat required
};

/**
 * Info for a particular client for the given group
 */
struct pr_destinfo_t {
    char name[DESTNAME_LEN];        /// Hostname of client
    struct in_addr addr;            /// IP address of client
    RSA_key_t pubkey;               /// The client's RSA public key
    int pubkeylen;                  /// The length of client's RSA key in bytes
    uint8_t verifydata[PUBKEY_LEN]; /// The verify data from a CLIENT_KEY
    uint16_t verifylen;             /// The length of verifydata in bytes
    int registered;                 /// True if we received a REGISTER
    int verified;                   /// True if we have a verified CLIENT_KEY
    int state;                      /// State as specified by proxy_client_state
    int pending;                    /// Index of pending message
    uint8_t rand2[RAND_LEN];        /// Client's random number
    uint8_t premaster[MASTER_LEN];  /// Premaster secret sent by client
    uint8_t master[MASTER_LEN];     /// Master key for client
    uint8_t hmackey[HMAC_LEN];      /// HMAC key for client
    uint8_t key[MAXKEY];            /// Symmetric encryption key for client
    uint8_t salt[MAXIV];            /// Salt for block cypher IV for client
};

/**
 * Info for a message pending to go upstream
 */
struct pr_pending_info_t {
    int msg, count;                 /// Type and number of pending responses
    int file_id;                    /// File ID from last client message
    int pass;                       /// Pass number from last status
    int section;                    /// Section number from last status
    uint8_t seq;                    /// Last sequence number used in STATUS
    uint8_t *naklist;               /// NAK list from last status
    int partial;                    /// PARTIAL flag from last INFO_ACK
};

#define MAX_PEND 3

/**
 * Info for a particular group
 */
struct pr_group_list_t {
    uint32_t group_id;              /// Group ID
    struct in_addr multi, srcaddr, destaddr;
    int multi_join;                 /// True if we're listening on private addr
    int foundaddr;                  /// True if our addr found in an ANNOUNCE
    int announce_int, status_int, register_int, done_int;
    int announce_time, status_time;
    unsigned int mtu, payloadsize, encpayloadsize, blocksize;
    struct sockaddr_in up_addr;     /// Upstream addr to send responses back to
    struct timeval phase_expire_time, phase_timeout_time, timeout_time;
    int phase, client_auth;
    int keyinfo_cnt;
    struct pr_pending_info_t pending[MAX_PEND];   /// Pending messages to send
    uint8_t last_seq;               /// Last sequence number used in STATUS
    int keytype, hashtype, sigtype; /// Key, hash, and sig types from server
    RSA_key_t serverkey;            /// Server's RSA public key
    RSA_key_t proxykey;             /// Proxy's RSA private key for this group
    unsigned int server_keylen;     /// Length in bytes of server key
    unsigned int proxy_keylen;      /// Length in bytes of client key
    uint8_t rand1[RAND_LEN];        /// Server's random number
    uint8_t rand2[RAND_LEN];        /// Proxy's random number
    uint8_t premaster[MASTER_LEN];  /// Premaster secret sent by proxy
    uint8_t master[MASTER_LEN];     /// Master key for proxy
    uint8_t hmackey[HMAC_LEN];      /// HMAC key for proxy
    uint8_t key[MAXKEY];            /// Symmetric encryption key for proxy
    uint8_t salt[MAXIV];            /// Salt for block cypher IV for proxy
    uint8_t groupmaster[MASTER_LEN];/// Master key for server
    uint8_t grouphmackey[HMAC_LEN]; /// HMAC key for server
    uint8_t groupkey[MAXKEY];       /// Symmetric encryption key for server
    uint8_t groupsalt[MAXIV];       /// Salt for block cypher IV for server
    int ivlen, keylen, hmaclen;     /// Length of HMAC key, symmetric key and iv
    struct pr_destinfo_t destinfo[MAXPROXYDEST];    /// List of clients
    int destcount;                  /// Number of clients served by this proxy
};

#define MAXLIST 100
#define KEY_REQ_LIMIT 5

/**
 * Global command line values and sockets
 */
extern SOCKET listener;
extern char logfile[MAXPATHNAME], pidfile[MAXPATHNAME];
extern char keyfile[MAXLIST][MAXPATHNAME];
extern int proxy_type, verbose, noname, debug, buffer, newkeylen, dscp;
extern int hb_interval, proxy_int;
extern unsigned char ttl;
extern uint16_t port, out_port;
extern struct sockaddr_in down_addr;
extern int have_down_fingerprint;
extern uint8_t down_fingerprint[HMAC_LEN];
extern uint32_t down_nonce, uid;
extern struct sockaddr_in hb_hosts[MAXLIST];
extern struct in_addr pub_multi[MAX_INTERFACES];
extern struct fp_list_t server_fp[MAXLIST], client_fp[MAXPROXYDEST];
extern struct iflist ifl[MAX_INTERFACES], m_interface[MAX_INTERFACES];
extern struct timeval next_hb_time, last_key_req;
extern int ifl_len, hbhost_count, server_fp_count, client_fp_count;
extern int keyfile_count, key_count, pub_multi_count, interface_count, sys_keys;
extern struct in_addr out_addr;
extern RSA_key_t privkey[MAXLIST];
extern struct pr_group_list_t group_list[MAXLIST];

#endif  // _PROXY_H

