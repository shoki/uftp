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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WINDOWS

#include "win_func.h"

#else  // if WINDOWS

#include <unistd.h>

#endif

#include "uftp_common.h"
#include "encryption.h"

void print_key(const char *name)
{
    RSA_key_t key;

    key = read_RSA_key(name);
    if (key) {
        fprintf(stderr, "%s: %d bits, fingerprint: %s\n", name,
                RSA_keylen(key) * 8, print_key_fingerprint(key));
        free_RSA_key(key);
    } else {
        fprintf(stderr, "%s: no such key\n", name);
    }
}

int main(int argc, char *argv[])
{
    RSA_key_t key;
    int i, c;
    int gen_key_len, del_key, sys_key;
    const char opts[] = "g:dm";
    
    applog = stderr;
    gen_key_len = 0;
    del_key = 0;
    sys_key = 0;
    while ((c = getopt(argc, argv, opts)) != EOF) {
        switch (c) {
        case 'g':
            gen_key_len = atoi(optarg);
            if ((gen_key_len < 512) || (gen_key_len > 2048)) {
                fprintf(stderr, "Invalid key size\n");
                exit(1);
            }
            break;
        case 'd':
            del_key = 1;
            break;
        case 'm':
            sys_key = 1;
            break;
        }
    }
    argc -= optind;
    argv += optind;

    if ((gen_key_len != 0) && (del_key != 0)) {
        fprintf(stderr, "Can't specify both -g and -d\n");
        exit(1);
    }
    crypto_init(sys_key);

    if (gen_key_len) {
        if (argc < 1) {
            fprintf(stderr, "No keyfile specified\n");
            exit(1);
        }
        key = gen_RSA_key(gen_key_len, RSA_EXP, argv[0]);
        if (key) {
            fprintf(stderr, "%s: %d bits, fingerprint: %s\n", argv[0],
                    RSA_keylen(key) * 8, print_key_fingerprint(key));
            free_RSA_key(key);
        } else {
            fprintf(stderr, "Error generating/storing key\n");
        }
    } else if (del_key) {
        if (argc < 1) {
            fprintf(stderr, "No keyfile specified\n");
            exit(1);
        }
        delete_container(argv[0]);
    } else {
        for (i = 0; i < argc; i++) {
            print_key(argv[i]);
        }
#if defined WINDOWS && !defined OPENSSL
        if (argc == 0) {
            const char *name;
            while ((name = get_next_container()) != NULL) {
                print_key(name);
            }
        }
#endif
    }
    crypto_cleanup();
    return 0;
}
