/*
 * AES functions
 * Copyright (c) 2003-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef AES_H
#define AES_H

void aes_encrypt_init(void *ctx, const u8 *key, size_t len);
void aes_encrypt(void *ctx, const u8 *plain, u8 *crypt);
void aes_encrypt_deinit(void *ctx);

#endif /* AES_H */
