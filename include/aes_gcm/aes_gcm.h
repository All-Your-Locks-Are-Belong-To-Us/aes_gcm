/*
 * AES-based functions
 *
 * Copyright (c) 2003-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef AES_GCM_H
#define AES_GCM_H

#include "includes.h"

#define AES_BLOCK_SIZE      (16)
#define AES_128_KEY_SIZE    (16)
#define AES_256_KEY_SIZE    (32)
#define AES_GCM_TAG_SIZE    (16)

/**
 * @brief Authenticated encryption
 *
 * @param key Pointer to the key.
 * @param key_len Length of the key in bytes (e.g. 32 for 256 bit AES).
 * @param iv Pointer to initialization vector (IV).
 * @param iv_len Length of the IV in bytes.
 * @param plain Pointer to the plaintext to encrypt.
 * @param plain_len Length of the plaintext in bytes.
 * @param aad Pointer to data to associate with the encrypted text.
 * @param aad_len Length of the associated data in bytes.
 * @param crypt Pointer to where to write the encrypted text to. May be the same as plain.
 * @param tag Pointer to where to write the 16 byte long authentication tag to.
 * @return 0 on success.
 */
int aes_gcm_ae(const u8 *key, size_t key_len,
			    const u8 *iv, size_t iv_len,
			    const u8 *plain, size_t plain_len,
			    const u8 *aad, size_t aad_len,
			    u8 *crypt, u8 *tag);
/**
 * @brief Authenticated decryption
 *
 * @param key Pointer to the key.
 * @param key_len  Length of the key in bytes (e.g. 32 for 256 bit AES).
 * @param iv Pointer to the initialization vector (IV).
 * @param iv_len Length of the IV in bytes.
 * @param crypt Pointer to the ciphertext to decrypt.
 * @param crypt_len Length of the ciphertext in bytes.
 * @param aad Pointer to the associated data.
 * @param aad_len Length of the associated data in bytes.
 * @param tag Pointer to the 16 byte long authentication tag to verify.
 * @param plain Ponter to where to write the decrypted plaintext to. May be the same as crypt.
 * @return 0 on success.
 */
int aes_gcm_ad(const u8 *key, size_t key_len,
			    const u8 *iv, size_t iv_len,
			    const u8 *crypt, size_t crypt_len,
			    const u8 *aad, size_t aad_len, const u8 *tag,
			    u8 *plain);

/**
 * @brief Create an authenticator tag from associated data without encrypting anything.
 *
 * @param key Pointer the the key.
 * @param key_len Length of the key in bytes.
 * @param iv Pointer to the initialization vector (IV).
 * @param iv_len Length of the IV in bytes.
 * @param aad Pointer to the data for which an authentication tag should be produced.
 * @param aad_len Length of the associated data in bytes.
 * @param tag Pointer to where to write the 16 byte long authentication tag to.
 * @return 0 on success.
 */
int aes_gmac(const u8 *key, size_t key_len,
			  const u8 *iv, size_t iv_len,
			  const u8 *aad, size_t aad_len, u8 *tag);

#endif /* AES_GCM_H */
