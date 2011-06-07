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

#define UFTP_V2_VER     0x20
#define V2_UFTP_ID      0x69
#define V2_ANNOUNCE     1
#define V2_REGISTER     2
#define V2_REG_CONF     3
#define V2_FILESEG      4
#define V2_DONE         5
#define V2_STATUS       6
#define V2_DONE_CONF    7
#define V2_ABORT        99

#define V2_BLOCKSIZE    1400
#define V2_PACKETSIZE   (V2_BLOCKSIZE + sizeof(struct uftp2_h))
#define V2_MAXDEST      100
#define V2_MAXINFODEST  300
#define V2_MAXPATHNAME  300

struct uftp2_h {
  int32_t uftp_id;
  int32_t func;
  uint32_t tx_id;
  int32_t seq_num;
  int32_t section_num;
  int32_t nak_count;
  int32_t blsize;
  int32_t pass;
};

struct fileinfo2 {
  uint32_t fsize;
  int32_t block_total;
  int32_t section_total;
  int32_t open;
  uint32_t mcast;
  uint32_t addr_list[V2_MAXDEST];
  char name[V2_MAXPATHNAME];
  uint16_t rxlatency1;
  uint16_t rxlatency2;
  uint32_t hilargefsize,lolargefsize;
  uint8_t minimal_resp;
};

struct statusinfo2 {
  uint32_t unused1;
  int32_t unused2;
  int32_t unused3;
  int32_t unused4;
  uint32_t unused5;
  uint32_t addr_list[V2_MAXINFODEST];
};

const char *v2_func_name(int func);
