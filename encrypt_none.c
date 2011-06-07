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

#include <stdlib.h>

#ifdef WINDOWS
typedef unsigned __int8 uint8_t;
typedef __int8 int8_t;
typedef unsigned __int16 uint16_t;
typedef __int16 int16_t;
typedef unsigned __int32 uint32_t;
typedef __int32 int32_t;
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;
#else
#include <inttypes.h>
#endif

#include "encryption.h"

void crypto_init(int set_sys_key)
{
}

void crypto_cleanup()
{
}

/**
 * Returns whether a particular cipher is supported
 */
int cipher_supported(int keytype)
{
    return 0;
}

/**
 * Returns whether a particular hash is supported
 */
int hash_supported(int hashtype)
{
    return 0;
}

void get_key_info(int keytype, int *keylen, int *ivlen)
{
}

int get_hash_len(int hashtype)
{
    return 0;
}

int get_random_bytes(unsigned char *buf, int num)
{
    return 0;
}

int encrypt_block(int keytype, const unsigned char *IV,
                  const unsigned char *key,
                  const unsigned char *src, unsigned int srclen,
                  unsigned char *dest, unsigned int *destlen)
{
    return 0;
}

int decrypt_block(int keytype, const unsigned char *IV,
                  const unsigned char *key,
                  const unsigned char *src, unsigned int srclen,
                  unsigned char *dest, unsigned int *destlen)
{
    return 0;
}

int create_hmac(int hashtype, const unsigned char *key, unsigned int keylen,
                const unsigned char *src, unsigned int srclen,
                unsigned char *dest, unsigned int *destlen)
{
    return 0;
}

int hash(int hashtype, const unsigned char *src, unsigned int srclen,
         unsigned char *dest, unsigned int *destlen)
{
    return 0;
}

int RSA_keylen(const RSA_key_t rsa)
{
    return 0;
}

int RSA_encrypt(RSA_key_t rsa, const unsigned char *from, int fromlen,
                unsigned char *to, int *tolen)
{
    return 0;
}

int RSA_decrypt(RSA_key_t rsa, const unsigned char *from, int fromlen,
                unsigned char *to, int *tolen)
{
    return 0;
}

int create_RSA_sig(RSA_key_t rsa, int hashtype,
                   const unsigned char *mes, unsigned int meslen,
                   unsigned char *sig, unsigned int *siglen)
{
    return 0;
}

int verify_RSA_sig(RSA_key_t rsa, int hashtype,
                   const unsigned char *mes, unsigned int meslen,
                   unsigned char *sig, unsigned int siglen)
{
    return 0;
}

int import_RSA_key(RSA_key_t *rsa, uint32_t exponent,
                   const unsigned char *modulus, uint16_t modlen)
{
    return 0;
}

int export_RSA_key(const RSA_key_t rsa, uint32_t *exponent,
                   unsigned char *modulus, uint16_t *modlen)
{
    return 0;
}

RSA_key_t gen_RSA_key(int bits, int exponent, const char *filename)
{
    return NULL;
}

RSA_key_t read_RSA_key(const char *filename)
{
    return NULL;
}

void free_RSA_key(RSA_key_t rsa)
{
}

const char *get_next_container()
{
    return NULL;
}

void delete_container(const char *name)
{
}

void set_sys_keys(int set)
{
}
