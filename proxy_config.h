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

#ifndef _PROXY_CONFIG_H
#define _PROXY_CONFIG_H

#define DEF_PROXY_INT   50
#define DEF_HB_INT      20
#define DEF_PORT        1044
#define DEF_PUB_MULTI   "230.4.4.1"
#define DEF_RCVBUF      262144
#define DEF_BSD_RCVBUF  233016
#define DEF_TTL         1
#define DEF_DSCP        0

#ifdef WINDOWS

#define DEF_LOGFILE     "C:\\uftpproxyd_log.txt"

#elif defined VMS

#define DEF_LOGFILE     "SYS$SCRATCH:uftpproxyd_log.txt"

#else

#define DEF_LOGFILE     "/tmp/uftpproxyd.log"

#endif

#define USAGE \
"uftpproxyd { -s { dest | fp=fingerprint } | -c | -r } [ -d ] [ -n ]\n\
    [ -p port ] [ -t ttl ] [ -Q dscp ] [ -O out_multi_interface ]\n\
    [ -U UID ] [ -q dest_port ] [ -T interval_pct ] [ -m ]\n\
    [ -H hb_server[:port][,hb_server[:port]...] ] [ -h hb_interval ]\n\
    [ -B udp_buf_size ] [ -L logfile ] [ -P pidfile ] [ -C clientlist_file ]\n\
    [ -S serverlist_file ] [ -k keyfile[,keyfile...] ] [ -K new_key_length ]\n\
    [ -I interface[,interface...] ] [ -M pub_mcast_addr[,pub_mcast_addr...] ]\n"


void process_args(int argc, char *argv[]);

#endif  // _PROXY_CONFIG_H
