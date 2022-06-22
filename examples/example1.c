#include <aes_gcm.h>
#include <stdio.h>
#include <string.h>

#define AES_256_KEY_SIZE (32)
#define AES_BLOCK_SIZE (16)

int main(void) {
    u8 key[AES_256_KEY_SIZE] = "Yellow SubmarineYellow Submarine";
    u8 iv[AES_BLOCK_SIZE] = "1234567890123456";
    u8 associated_data[7] = "blob123";
    u8 plain[32] = "We all live in a yellowsubmarine";

    const size_t crypt_len = sizeof(plain) + ((sizeof(plain) % 16 != 0) ? (16 - (sizeof(plain) % 16)) : 0);

    u8 crypt[crypt_len];
    crypt[0] = 0;
    u8 tag[16] = { 0 };
    int ret = aes_gcm_ae(key, AES_256_KEY_SIZE, iv, AES_BLOCK_SIZE, plain, sizeof(plain), associated_data, sizeof(associated_data), crypt, tag);
    if (ret != 0) {
        fprintf(stderr, "Could not encrypt.\n");
        return -1;
    }

    u8 out[crypt_len];
    memset(out, 0, sizeof(out));

    ret = aes_gcm_ad(key, sizeof(key), iv, sizeof(iv), crypt, crypt_len, associated_data, sizeof(associated_data), tag, out);
    if (ret != 0) {
        fprintf(stderr, "Could not decrypt.\n");
        return -1;
    }

    if(memcmp(plain, out, sizeof(plain))) {
        fprintf(stderr, "Decrypted plain text does not match original.\n");
        return -1;
    }
    return 0;
}
