#
#  UFTP - UDP based FTP with multicast
#
#  Copyright (C) 2001-2011   Dennis A. Bush, Jr.   bush@tcnj.edu
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

!IFDEF OPENSSL

CFLAGS=-Zi -W3 -nologo -Od /D WINDOWS /D _CRT_SECURE_NO_WARNINGS /D OPENSSL /MD
LDLIBS = libeay32.lib ssleay32.lib ws2_32.lib
INCLUDE = $(INCLUDE);C:\OpenSSL\include
LIB = $(LIB);C:\OpenSSL\lib

!ELSE IFDEF NO_ENCRYPTION

CFLAGS=-Zi -W3 -nologo -Od /D WINDOWS /D _CRT_SECURE_NO_WARNINGS /D NO_ENCRYPTION
LDLIBS = ws2_32.lib

!ELSE

CFLAGS=-Zi -W3 -nologo -Od /D WINDOWS /D _CRT_SECURE_NO_WARNINGS
LDLIBS = advapi32.lib ws2_32.lib

!ENDIF

LDFLAGS=-debug -nologo -subsystem:console

CC = cl
LINK = link

all: uftp.exe uftpd.exe uftpproxyd.exe uftp_keymgt.exe

clean:
	-del /f uftp.exe uftpd.exe uftpproxyd.exe uftp_keymgt.exe *.obj *.pdb *.ilk

test: testclient_multi.exe

testclient_multi.obj: testclient_multi.c uftp.h uftp_common.h encryption.h

!IFDEF OPENSSL

testclient_multi.exe: testclient_multi.obj encrypt_openssl.obj uftp_common.obj win_func.obj
	$(LINK) $(LDFLAGS) -out:$@ $** $(LDLIBS)

!ELSE

testclient_multi.exe: testclient_multi.obj encrypt_cryptoapi.obj uftp_common.obj win_func.obj
	$(LINK) $(LDFLAGS) -out:$@ $** $(LDLIBS)

!ENDIF

client_announce.obj: client_announce.c client.h uftp_common.h uftp.h \
  encryption.h uftp2.h client_common.h client_announce.h
client_common.obj: client_common.c client.h uftp_common.h uftp.h \
  encryption.h uftp2.h client_common.h
client_config.obj: client_config.c client.h uftp_common.h uftp.h \
  encryption.h uftp2.h client_config.h
client_init.obj: client_init.c client.h uftp_common.h uftp.h encryption.h \
  uftp2.h client_init.h client_config.h client_common.h
client_loop.obj: client_loop.c client.h uftp_common.h uftp.h encryption.h \
  uftp2.h client_common.h client_loop.h client_announce.h \
  client_transfer.h
client_main.obj: client_main.c client_config.h client_init.h client_loop.h
client_transfer.obj: client_transfer.c client.h uftp_common.h uftp.h \
  encryption.h uftp2.h client_common.h client_transfer.h

server_announce.obj: server_announce.c server.h uftp_common.h uftp.h \
  encryption.h server_common.h server_announce.h
server_common.obj: server_common.c server.h uftp_common.h uftp.h \
  encryption.h server_common.h
server_config.obj: server_config.c server.h uftp_common.h uftp.h \
  encryption.h server_config.h
server_init.obj: server_init.c server.h uftp_common.h uftp.h encryption.h \
  server_config.h server_init.h
server_main.obj: server_main.c server_config.h uftp.h server_init.h \
  server_send.h
server_phase.obj: server_phase.c server.h uftp_common.h uftp.h encryption.h \
  server_common.h server_announce.h server_transfer.h
server_send.obj: server_send.c server.h uftp_common.h uftp.h encryption.h \
  server_send.h server_phase.h
server_transfer.obj: server_transfer.c server.h uftp_common.h uftp.h \
  encryption.h server_common.h server_transfer.h

proxy_common.obj: proxy_common.c proxy.h uftp_common.h uftp.h encryption.h \
  proxy_common.h proxy_upstream.h
proxy_config.obj: proxy_config.c proxy.h uftp_common.h uftp.h encryption.h \
  proxy_config.h
proxy_downstream.obj: proxy_downstream.c proxy.h uftp_common.h uftp.h \
  encryption.h proxy_common.h proxy_downstream.h
proxy_init.obj: proxy_init.c proxy.h uftp_common.h uftp.h encryption.h \
  proxy_init.h proxy_config.h proxy_common.h
proxy_loop.obj: proxy_loop.c proxy.h uftp_common.h uftp.h encryption.h \
  proxy_common.h proxy_loop.h proxy_upstream.h proxy_downstream.h
proxy_main.obj: proxy_main.c proxy_config.h proxy_init.h proxy_loop.h
proxy_upstream.obj: proxy_upstream.c proxy.h uftp_common.h uftp.h \
  encryption.h proxy_common.h proxy_upstream.h proxy_downstream.h

uftp_keymgt.obj: uftp_keymgt.c uftp_common.h uftp.h encryption.h
encrypt_cryptoapi.obj: encrypt_cryptoapi.c uftp_common.h uftp.h encryption.h
encrypt_openssl.obj: encrypt_openssl.c uftp_common.h uftp.h encryption.h
uftp_common.obj: uftp_common.c uftp.h uftp2.h uftp_common.h encryption.h
win_func.obj: win_func.c win_func.h

!IFDEF NO_ENCRYPTION

UFTP_OBJS=win_func.obj uftp_common.obj encrypt_none.obj \
	server_announce.obj server_transfer.obj \
	server_send.obj server_phase.obj \
	server_common.obj server_config.obj server_init.obj server_main.obj

UFTPD_OBJS=win_func.obj uftp_common.obj encrypt_none.obj \
	client_loop.obj client_announce.obj client_transfer.obj \
	client_common.obj client_config.obj client_init.obj client_main.obj

UFTPPROXYD_OBJS=win_func.obj uftp_common.obj encrypt_none.obj \
	proxy_loop.obj proxy_upstream.obj proxy_downstream.obj \
	proxy_common.obj proxy_config.obj proxy_init.obj proxy_main.obj \

UFTP_KEYMGT_OBJS=uftp_keymgt.obj win_func.obj uftp_common.obj encrypt_none.obj

!ELSE IFDEF OPENSSL

UFTP_OBJS=win_func.obj uftp_common.obj encrypt_openssl.obj \
	server_announce.obj server_transfer.obj \
	server_send.obj server_phase.obj \
	server_common.obj server_config.obj server_init.obj server_main.obj

UFTPD_OBJS=win_func.obj uftp_common.obj encrypt_openssl.obj \
	client_loop.obj client_announce.obj client_transfer.obj \
	client_common.obj client_config.obj client_init.obj client_main.obj

UFTPPROXYD_OBJS=win_func.obj uftp_common.obj encrypt_openssl.obj \
	proxy_loop.obj proxy_upstream.obj proxy_downstream.obj \
	proxy_common.obj proxy_config.obj proxy_init.obj proxy_main.obj \

UFTP_KEYMGT_OBJS=uftp_keymgt.obj win_func.obj uftp_common.obj encrypt_openssl.obj

!ELSE

UFTP_OBJS=win_func.obj uftp_common.obj encrypt_cryptoapi.obj \
	server_announce.obj server_transfer.obj \
	server_send.obj server_phase.obj \
	server_common.obj server_config.obj server_init.obj server_main.obj \

UFTPD_OBJS=win_func.obj uftp_common.obj encrypt_cryptoapi.obj \
	client_loop.obj client_announce.obj client_transfer.obj \
	client_common.obj client_config.obj client_init.obj client_main.obj

UFTPPROXYD_OBJS=win_func.obj uftp_common.obj encrypt_cryptoapi.obj \
	proxy_loop.obj proxy_upstream.obj proxy_downstream.obj \
	proxy_common.obj proxy_config.obj proxy_init.obj proxy_main.obj \

UFTP_KEYMGT_OBJS=uftp_keymgt.obj win_func.obj uftp_common.obj encrypt_cryptoapi.obj

!ENDIF

uftp.exe: $(UFTP_OBJS)
	$(LINK) $(LDFLAGS) -out:$@ $** $(LDLIBS)

uftpd.exe: $(UFTPD_OBJS)
	$(LINK) $(LDFLAGS) -out:$@ $** $(LDLIBS)

uftpproxyd.exe: $(UFTPPROXYD_OBJS)
	$(LINK) $(LDFLAGS) -out:$@ $** $(LDLIBS)

uftp_keymgt.exe: $(UFTP_KEYMGT_OBJS)
	$(LINK) $(LDFLAGS) -out:$@ $** $(LDLIBS)

.c.obj:
	$(CC) -c $(CFLAGS) $< 

uftp: uftp.exe
uftpd: uftpd.exe
uftpproxyd: uftpproxyd.exe
uftp_keymgt: uftp_keymgt.exe
testclient_multi: testclient_multi.exe
