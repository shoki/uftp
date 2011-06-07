#
#  UFTP - UDP based FTP with multicast
#
#  Copyright (C) 2001-2010   Dennis A. Bush, Jr.   bush@tcnj.edu
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#  Additional permission under GNU GPL version 3 section 7
#
#  If you modify this program, or any covered work, by linking or
#  combining it with the OpenSSL project's OpenSSL library (or a
#  modified version of that library), containing parts covered by the
#  terms of the OpenSSL or SSLeay licenses, the copyright holder
#  grants you additional permission to convey the resulting work.
#  Corresponding Source for a non-source form of such a combination
#  shall include the source code for the parts of OpenSSL used as well
#  as that of the covered work.
#

UNAME_S:=$(shell uname -s)

ifdef NO_ENCRYPTION
ENC_OPTS=-DNO_ENCRYPTION
CRYPT_LIB=
else
ENC_OPTS=
CRYPT_LIB=-lcrypto
endif

# defaults
CC = gcc
OPTIONS=-g -Wall $(ENC_OPTS)
LDLIBS=-lc -lm $(CRYPT_LIB)
CFLAGS+=

# FreeBSD
ifeq ("FreeBSD", "$(UNAME_S)")
OPTIONS=-g -Wall -DHAS_GETIFADDRS $(ENC_OPTS)
endif

# OSX, aka Darwin
ifeq ("Darwin", "$(UNAME_S)")
OPTIONS=-g -Wall -DHAS_GETIFADDRS $(ENC_OPTS)
endif

# Sun
ifeq ("SunOS", "$(UNAME_S)")
CC = cc
OPTIONS=-g -DBSD_COMP $(ENC_OPTS)
LDLIBS=-lnsl -lsocket -lm $(CRYPT_LIB)
CFLAGS=`getconf LFS_CFLAGS`
OPENSSL=/usr/sfw
endif

# Linux
ifeq ("Linux", "$(UNAME_S)")
OPTIONS=-g -Wall -DHAS_GETIFADDRS $(ENC_OPTS)
LDLIBS=-lm $(CRYPT_LIB)
CFLAGS+=`getconf LFS_CFLAGS`
endif

ifdef OPENSSL
INCLUDE=-I $(OPENSSL)/include
LIB=-L $(OPENSSL)/lib
endif

all: uftp uftpd uftpproxyd uftp_keymgt

test: testclient_multi

testclient_multi.o: testclient_multi.c uftp.h uftp_common.h encryption.h

testclient_multi: testclient_multi.o encrypt_openssl.o uftp_common.o
	$(CC) $(OPTIONS) $(LIB) -o $@ $^ $(LDLIBS)

clean:
	rm -f testclient_multi uftp uftpd uftpproxyd uftp_keymgt *.o

client_announce.o: client_announce.c client.h uftp_common.h uftp.h \
  encryption.h uftp2.h client_common.h client_announce.h
client_common.o: client_common.c client.h uftp_common.h uftp.h \
  encryption.h uftp2.h client_common.h
client_config.o: client_config.c client.h uftp_common.h uftp.h \
  encryption.h uftp2.h client_config.h
client_init.o: client_init.c client.h uftp_common.h uftp.h encryption.h \
  uftp2.h client_init.h client_config.h client_common.h
client_loop.o: client_loop.c client.h uftp_common.h uftp.h encryption.h \
  uftp2.h client_common.h client_loop.h client_announce.h \
  client_transfer.h
client_main.o: client_main.c client_config.h client_init.h client_loop.h
client_transfer.o: client_transfer.c client.h uftp_common.h uftp.h \
  encryption.h uftp2.h client_common.h client_transfer.h

server_announce.o: server_announce.c server.h uftp_common.h uftp.h \
  encryption.h server_common.h server_announce.h
server_common.o: server_common.c server.h uftp_common.h uftp.h \
  encryption.h server_common.h
server_config.o: server_config.c server.h uftp_common.h uftp.h \
  encryption.h server_config.h
server_init.o: server_init.c server.h uftp_common.h uftp.h encryption.h \
  server_config.h server_init.h
server_main.o: server_main.c server_config.h uftp.h server_init.h \
  server_send.h
server_phase.o: server_phase.c server.h uftp_common.h uftp.h encryption.h \
  server_common.h server_announce.h server_transfer.h
server_send.o: server_send.c server.h uftp_common.h uftp.h encryption.h \
  server_send.h server_phase.h
server_transfer.o: server_transfer.c server.h uftp_common.h uftp.h \
  encryption.h server_common.h server_transfer.h

proxy_common.o: proxy_common.c proxy.h uftp_common.h uftp.h encryption.h \
  proxy_common.h proxy_upstream.h
proxy_config.o: proxy_config.c proxy.h uftp_common.h uftp.h encryption.h \
  proxy_config.h
proxy_downstream.o: proxy_downstream.c proxy.h uftp_common.h uftp.h \
  encryption.h proxy_common.h proxy_downstream.h
proxy_init.o: proxy_init.c proxy.h uftp_common.h uftp.h encryption.h \
  proxy_init.h proxy_config.h proxy_common.h
proxy_loop.o: proxy_loop.c proxy.h uftp_common.h uftp.h encryption.h \
  proxy_common.h proxy_loop.h proxy_upstream.h proxy_downstream.h
proxy_main.o: proxy_main.c proxy_config.h proxy_init.h proxy_loop.h
proxy_upstream.o: proxy_upstream.c proxy.h uftp_common.h uftp.h \
  encryption.h proxy_common.h proxy_upstream.h proxy_downstream.h

uftp_keymgt.o: uftp_keymgt.c uftp_common.h uftp.h encryption.h
encrypt_openssl.o: encrypt_openssl.c uftp_common.h uftp.h encryption.h
encrypt_none.o: encrypt_none.c encryption.h
uftp_common.o: uftp_common.c uftp.h uftp2.h uftp_common.h encryption.h

ifdef NO_ENCRYPTION

UFTP_OBJS=uftp_common.o encrypt_none.o \
	server_announce.o server_transfer.o server_send.o server_phase.o \
	server_common.o server_config.o server_init.o server_main.o 

UFTPD_OBJS=uftp_common.o encrypt_none.o \
	client_loop.o client_announce.o client_transfer.o \
	client_common.o client_config.o client_init.o client_main.o 

UFTPPROXYD_OBJS=uftp_common.o encrypt_none.o \
	proxy_loop.o proxy_upstream.o proxy_downstream.o \
	proxy_common.o proxy_config.o proxy_init.o proxy_main.o \

UFTP_KEYMGT_OBJS=uftp_keymgt.o uftp_common.o encrypt_none.o

else

UFTP_OBJS=uftp_common.o encrypt_openssl.o \
	server_announce.o server_transfer.o server_send.o server_phase.o \
	server_common.o server_config.o server_init.o server_main.o 

UFTPD_OBJS=uftp_common.o encrypt_openssl.o \
	client_loop.o client_announce.o client_transfer.o \
	client_common.o client_config.o client_init.o client_main.o 

UFTPPROXYD_OBJS=uftp_common.o encrypt_openssl.o \
	proxy_loop.o proxy_upstream.o proxy_downstream.o \
	proxy_common.o proxy_config.o proxy_init.o proxy_main.o \

UFTP_KEYMGT_OBJS=uftp_keymgt.o uftp_common.o encrypt_openssl.o

endif

uftp: $(UFTP_OBJS)
	$(CC) $(OPTIONS) $(LIB) -o $@ $^ $(LDLIBS)

uftpd: $(UFTPD_OBJS)
	$(CC) $(OPTIONS) $(LIB) -o $@ $^ $(LDLIBS)

uftpproxyd: $(UFTPPROXYD_OBJS)
	$(CC) $(OPTIONS) $(LIB) -o $@ $^ $(LDLIBS)

uftp_keymgt: $(UFTP_KEYMGT_OBJS)
	$(CC) $(OPTIONS) $(LIB) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(OPTIONS) $(INCLUDE) $(CFLAGS) -c $<

install:
	install -m 755 -d $(DESTDIR)/bin
	install -m 755 -d $(DESTDIR)/usr/sbin
	install -m 755 -d $(DESTDIR)/usr/share/man/man1
	/bin/cp -p uftp $(DESTDIR)/bin
	/bin/cp -p uftpd $(DESTDIR)/usr/sbin
	/bin/cp -p uftpproxyd $(DESTDIR)/usr/sbin
	/bin/cp -p uftp_keymgt $(DESTDIR)/bin
	/bin/cp -p uftp.1 uftpd.1 uftpproxyd.1 uftp_keymgt.1 $(DESTDIR)/usr/share/man/man1

