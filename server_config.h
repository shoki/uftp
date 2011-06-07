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

#ifndef _SERVER_CONFIG_H
#define _SERVER_CONFIG_H

#include "uftp.h"

/**
 * Default command line values
 */
#define DEF_RATE                1000
#define DEF_WEIGHT              300
#define DEF_MIN_TIME            10
#define DEF_PORT                1044
#define DEF_PUB_MULTI           "230.4.4.1"
#define DEF_PRIV_MULTI          "230.5.5.x"
#define DEF_ANNOUNCE_TIME       10
#define DEF_STATUS_TIME         12
#define DEF_ANNOUNCE_INTERVAL   2500
#define DEF_STATUS_INTERVAL     4000
#define DEF_REGISTER_INTERVAL   4000
#define DEF_DONE_INTERVAL       4000
#define DEF_VERBOSE             0
#define DEF_NONAME              0
#define DEF_UNICAST             0
#define DEF_TTL                 1
#define DEF_DSCP                0
#define DEF_RCVBUF              262144
#define DEF_BSD_RCVBUF          233016
#define DEF_MTU                 1500
#define DEF_KEYTYPE             KEY_NONE
#define DEF_HASHTYPE            HASH_SHA1
#define DEF_SIGTYPE             SIG_HMAC

#define USAGE "uftp [ -U ] [ -R txrate ] [ -W txweight ] [ -m min_time ]\n\
    [ -n ] [ -L logfile ] [ -B udp_buf_size ] [ -Y keytype ] [ -h hashtype ]\n\
    [ -w sigtype ] [ -c ] [ -k key_file ] [ -K new_key_length ] [ -l ] [ -T ]\n\
    [ -A announce_time ] [ -S status_time ] [ -a announce_interval ]\n\
    [ -s status_interval ] [ -r register_interval ] [ -d done_interval ]\n\
    [ -b mtu ] [ -t ttl ] [ -Q dscp ] [ -I interface ]\n\
    [ -p port ] [ -j proxylist_file ] [ -q ] [ -f ] [ -y ]\n\
    [ -H host[,host...] | -H @hostlist_file | -F restart_file ]\n\
    [ -X exclude_file ] [ -M pub_multicast_addr ] [ -P priv_multicast_addr ]\n\
    [ -D dest_name ] { -i list_file | file [ file... ] }\n"

void process_args(int argc, char *argv[]);

#endif  // _SERVER_CONFIG_H

