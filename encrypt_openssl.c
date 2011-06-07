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

#ifdef WINDOWS

#include <winsock2.h>

#endif

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "uftp_common.h"
#include "encryption.h"

/**
 * Prints OpenSSL errors to log
 */
static void log_ssl_err(const char *mes)
{
    unsigned long err;
    char errstr[1000];

    while ((err = ERR_get_error())) {
        ERR_error_string(err, errstr);
        log(0, 0, "%s: %s", mes, errstr);
    }
}

static int init_done;

/**
 * Performs all necessary steps to initialize the crypto library
 */
void crypto_init(int set_sys_key)
{
    // TODO: include calls to RAND_add and the like?
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    init_done = 1;
}

/**
 * Performs all necessary steps to clean up the crypto library
 */
void crypto_cleanup()
{
    if (init_done) {
        ERR_free_strings();
        EVP_cleanup();
    }
}

/**
 * Gets the EVP_CIPHER associated with a given keytype
 */
static const EVP_CIPHER *get_cipher(int keytype)
{
    switch (keytype) {
    case KEY_DES:
        return EVP_get_cipherbyname("DES-CBC");
    case KEY_DES_EDE3:
        return EVP_get_cipherbyname("DES-EDE3-CBC");
    case KEY_AES128:
        return EVP_get_cipherbyname("AES-128-CBC");
    case KEY_AES256:
        return EVP_get_cipherbyname("AES-256-CBC");
    default:
        log(0, 0, "Unknown keytype: %d", keytype);
        exit(1);
    }
}

/**
 * Gets the EVP_MD associated with a given hashtype
 */
static const EVP_MD *get_hash(int hashtype)
{
    switch (hashtype) {
    case HASH_SHA256:
        return EVP_get_digestbyname("SHA256");
    case HASH_SHA1:
        return EVP_get_digestbyname("SHA1");
    case HASH_MD5:
        return EVP_get_digestbyname("MD5");
    default:
        log(0, 0, "Unknown hashtype: %d", hashtype);
        exit(1);
    }
}

/**
 * Returns whether a particular cipher is supported
 */
int cipher_supported(int keytype)
{
    return (get_cipher(keytype) != NULL);
}

/**
 * Returns whether a particular hash is supported
 */
int hash_supported(int hashtype)
{
    return (get_hash(hashtype) != NULL);
}

/**
 * Gets the key length and IV/block length of a given key
 */
void get_key_info(int keytype, int *keylen, int *ivlen)
{
    const EVP_CIPHER *cipher = get_cipher(keytype);

    *keylen = EVP_CIPHER_key_length(cipher);
    *ivlen = EVP_CIPHER_iv_length(cipher);
}

/**
 * Gets the length of the given hash
 */
int get_hash_len(int hashtype)
{
    const EVP_MD *hashptr = get_hash(hashtype);

    return EVP_MD_size(hashptr);
}

/**
 * Gets num cryptographically random bytes
 */
int get_random_bytes(unsigned char *buf, int num)
{
    int rval;

    if (!(rval = RAND_bytes(buf, num))) {
        log_ssl_err("Error getting random bytes");
    }
    return rval;
}

/**
 * Takes a block of data and encrypts it with a symmetric cypher.
 * The output buffer must be at least the size of source data + block size.
 */
int encrypt_block(int keytype, const unsigned char *IV,
                  const unsigned char *key,
                  const unsigned char *src, unsigned int srclen,
                  unsigned char *dest, unsigned int *destlen)
{
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher = get_cipher(keytype);
    int len;

    EVP_CIPHER_CTX_init(&ctx);
    if (!EVP_EncryptInit_ex(&ctx, cipher, NULL, key, IV)) {
        log_ssl_err("EncryptInit failed");
        return 0;
    }
    if (!EVP_EncryptUpdate(&ctx, dest, &len, src, srclen)) {
        log_ssl_err("EncryptUpdate failed");
        return 0;
    }
    *destlen = len;
    if (!EVP_EncryptFinal_ex(&ctx, dest + *destlen, &len)) {
        log_ssl_err("EncryptFinal failed");
        return 0;
    }
    *destlen += len;
    EVP_CIPHER_CTX_cleanup(&ctx);

    return 1;
}

/**
 * Takes a block of data encrypted with a symmetric cypher and decrypts it.
 * The output buffer must be at least the size of source data.
 */
int decrypt_block(int keytype, const unsigned char *IV,
                  const unsigned char *key,
                  const unsigned char *src, unsigned int srclen,
                  unsigned char *dest, unsigned int *destlen)
{
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher = get_cipher(keytype);
    int len;

    EVP_CIPHER_CTX_init(&ctx);
    if (!EVP_DecryptInit_ex(&ctx, cipher, NULL, key, IV)) {
        log_ssl_err("DecryptInit failed");
        return 0;
    }
    if (!EVP_DecryptUpdate(&ctx, dest, &len, src, srclen)) {
        log_ssl_err("DecryptUpdate failed");
        return 0;
    }
    *destlen = len;
    if (!EVP_DecryptFinal_ex(&ctx, dest + *destlen, &len)) {
        log_ssl_err("DecryptFinal failed");
        return 0;
    }
    *destlen += len;
    EVP_CIPHER_CTX_cleanup(&ctx);

    return 1;
}

/**
 * Calculates the HMAC of the given message, hashtype, and hashkey.
 * dest must be at least the hash length.
 */
int create_hmac(int hashtype, const unsigned char *key, unsigned int keylen,
                const unsigned char *src, unsigned int srclen,
                unsigned char *dest, unsigned int *destlen)
{
    const EVP_MD *hashptr = get_hash(hashtype);

    HMAC(hashptr, key, keylen, src, srclen, dest, destlen);
    return 1;
}

/**
 * Calculates the hash of the given message and hashtype
 */
int hash(int hashtype, const unsigned char *src, unsigned int srclen,
         unsigned char *dest, unsigned int *destlen)
{
    EVP_MD_CTX hashctx;
    const EVP_MD *hashptr = get_hash(hashtype);

    EVP_MD_CTX_init(&hashctx);
    if (!EVP_DigestInit_ex(&hashctx, hashptr, NULL)) {
        log_ssl_err("DigestInit failed");
        return 0;
    }
    if (!EVP_DigestUpdate(&hashctx, src, srclen)) {
        log_ssl_err("DigestUpdate failed");
        return 0;
    }
    if (!EVP_DigestFinal_ex(&hashctx, dest, (unsigned int *)destlen)) {
        log_ssl_err("DigestUpdate failed");
        return 0;
    }
    EVP_MD_CTX_cleanup(&hashctx);

    return 1;
}

/**
 * Returns the length in bytes of the modulus for the given RSA key
 */
int RSA_keylen(const RSA_key_t rsa)
{
    return RSA_size(rsa);
}

/**
 * Encrypts a small block of data with an RSA public key.
 * Output buffer must be at least the key size.
 */
int RSA_encrypt(RSA_key_t rsa, const unsigned char *from, int fromlen,
                unsigned char *to, int *tolen)
{
    int padding;

    if (RSA_size(rsa) * 8 < 768) {
        padding = RSA_PKCS1_PADDING;
    } else {
        padding = RSA_PKCS1_OAEP_PADDING;
    }

    if ((*tolen = RSA_public_encrypt(fromlen, from, to, rsa, padding)) == -1) {
        log_ssl_err("RSA_public_encrypt failed");
        return 0;
    }

    return 1;
}

/**
 * Decrypts a small block of data with an RSA private key.
 */
int RSA_decrypt(RSA_key_t rsa, const unsigned char *from, int fromlen,
                unsigned char *to, int *tolen)
{
    int padding;

    if (RSA_size(rsa) * 8 < 768) {
        padding = RSA_PKCS1_PADDING;
    } else {
        padding = RSA_PKCS1_OAEP_PADDING;
    }

    if ((*tolen = RSA_private_decrypt(fromlen, from, to, rsa, padding)) == -1) {
        log_ssl_err("RSA_private_decrypt failed");
        return 0;
    }

    return 1;
}

/**
 * Hashes a block of data and signs it with an RSA private key.
 * Output buffer must be at least the key size.
 */
int create_RSA_sig(RSA_key_t rsa, int hashtype,
                   const unsigned char *mes, unsigned int meslen,
                   unsigned char *sig, unsigned int *siglen)
{
    unsigned char meshash[HMAC_LEN];
    unsigned int meshashlen;
    const EVP_MD *hashptr;

    if (!hash(hashtype, mes, meslen, meshash, &meshashlen)) {
        return 0;
    }

    hashptr = get_hash(hashtype);
    if (!RSA_sign(EVP_MD_type(hashptr), meshash, meshashlen,
                  sig, siglen, rsa)) {
        log_ssl_err("RSA_sign failed");
        return 0;
    } else {
        return 1;
    }
}

/**
 * Hashes a block of data and verifies it against an RSA signature.
 */
int verify_RSA_sig(RSA_key_t rsa, int hashtype,
                   const unsigned char *mes, unsigned int meslen,
                   unsigned char *sig, unsigned int siglen)
{
    unsigned char meshash[HMAC_LEN];
    unsigned int meshashlen;
    const EVP_MD *hashptr;

    if (!hash(hashtype, mes, meslen, meshash, &meshashlen)) {
        return 0;
    }

    hashptr = get_hash(hashtype);
    if (!RSA_verify(EVP_MD_type(hashptr), meshash, meshashlen,
                    sig, siglen, rsa)) {
        log_ssl_err("RSA_verify failed");
        return 0;
    } else {
        return 1;
    }
}

/**
 * Creates an RSA public key with the given modulus and public exponent
 */
int import_RSA_key(RSA_key_t *rsa, uint32_t exponent,
                   const unsigned char *modulus, uint16_t modlen)
{
    unsigned char bin_exponent[4];

    *rsa = RSA_new();

    bin_exponent[0] = (exponent & 0xFF000000) >> 24;
    bin_exponent[1] = (exponent & 0x00FF0000) >> 16;
    bin_exponent[2] = (exponent & 0x0000FF00) >> 8;
    bin_exponent[3] = (exponent & 0x000000FF);

    if (((*rsa)->e = BN_bin2bn(bin_exponent, 4, NULL)) == NULL) {
        log_ssl_err("BN_bin2bn failed for e");
        return 0;
    }
    if (((*rsa)->n = BN_bin2bn(modulus, modlen, NULL)) == NULL) {
        log_ssl_err("BN_bin2bn failed for n");
        return 0;
    }

    return 1;
}

/**
 * Extracts the modulus and public exponent from an RSA public key
 */
int export_RSA_key(const RSA_key_t rsa, uint32_t *exponent,
                   unsigned char *modulus, uint16_t *modlen)
{
    unsigned char bin_exponent[4];
    int explen, l_modlen, i;

    if (BN_num_bytes(rsa->e) > sizeof(bin_exponent)) {
        log(0, 0, "exponent too big for export");
        return 0;
    }
    if ((explen = BN_bn2bin(rsa->e, bin_exponent)) <= 0) {
        log_ssl_err("BN_bn2bin failed for e");
        return 0;
    }
    if (explen > 4) {
        log(0, 0, "exponent too big, size %d", explen);
        return 0;
    }
    *exponent = 0;
    for (i = 0; i < explen; i++) {
        *exponent |= bin_exponent[i] << (8 * (explen - i - 1));
    }

    if ((l_modlen = BN_bn2bin(rsa->n, modulus)) <= 0) {
        log_ssl_err("BN_bn2bin failed for n");
        return 0;
    }
    *modlen = l_modlen;

    return 1;
}

/**
 * Generates an RSA private key with the given exponent and number of bits
 * and writes it to the given file (if specified).
 */
RSA_key_t gen_RSA_key(int bits, int exponent, const char *filename)
{
    RSA_key_t rsa;
    FILE *f;

    if ((rsa = RSA_generate_key(bits ? bits : DEF_RSA_LEN,
                                exponent, NULL, NULL)) == NULL) {
        log_ssl_err("couldn't generate rsa key");
        return NULL;
    }

    if (strcmp(filename, "")) {
        if ((f = fopen(filename, "rb")) != NULL) {
            log(0, 0, "Private key file already exists, won't overwrite");
            fclose(f);
            return NULL;
        }
        if ((f = fopen(filename, "wb")) == NULL) {
            syserror(0, 0, "failed to open key file");
            return NULL;
        }
        if (!PEM_write_RSAPrivateKey(f, rsa, NULL, NULL, 0, NULL, NULL)) {
            log_ssl_err("couldn't write rsa private key");
            fclose(f);
            return NULL;
        }
        fclose(f);
    }

    return rsa;
}

/**
 * Reads an RSA private key from the specified file
 */
RSA_key_t read_RSA_key(const char *filename)
{
    RSA_key_t rsa;
    FILE *f;

    if ((f = fopen(filename, "rb")) == NULL) {
        syserror(0, 0, "failed to open key file");
        return NULL;
    }
    if ((rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL)) == NULL) {
        log_ssl_err("couldn't read rsa private key");
        return NULL;
    }
    fclose(f);

    return rsa;
}

void free_RSA_key(RSA_key_t rsa)
{
    RSA_free(rsa);
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
