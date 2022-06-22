#include <aes_gcm.h>
#include <stdio.h>
#include <string.h>

#define AES_256_KEY_SIZE (32)
#define AES_BLOCK_SIZE (16)

int main(void) {
    u8 key[AES_256_KEY_SIZE] = {
        0xCA, 0x97, 0x81, 0x12, 0xCA, 0x1B, 0xBD, 0xCA, 0xFA, 0xC2, 0x31, 0xB3, 0x9A, 0x23, 0xDC, 0x4D, 0xA7, 0x86, 0xEF, 0xF8, 0x14, 0x7C, 0x4E, 0x72, 0xB9, 0x80, 0x77, 0x85, 0xAF, 0xEE, 0x48, 0xBB
    };
    u8 iv[AES_BLOCK_SIZE] = {
        0x33, 0x58, 0x2C, 0xB8, 0x9E, 0x78, 0xD6, 0x39, 0x67, 0x80, 0x1A, 0x77, 0xAB, 0x6A, 0xBC, 0x72
    };
    u8 ad[7] = "blob123";
    unsigned char cipher[] = {
       167, 195, 144, 31, 136, 38, 122, 159, 247, 246, 154, 91, 108, 97, 234, 224, 223, 156, 175, 63, 49, 63, 195, 37, 81, 122, 71, 28
    };
    unsigned char tag[] = { 69, 91, 44, 40, 33, 187, 238, 85, 148, 144, 60, 57, 145, 221, 116, 70 };
    u8 plain[sizeof(cipher)];
    memset(plain, 0, sizeof(cipher));

    int ret = aes_gcm_ad(key, sizeof(key), iv, sizeof(iv), cipher, sizeof(cipher), ad, 7, tag, plain);
    if (ret != 0) {
        fprintf(stderr, "Could not decrypt.\n");
        return -1;
    }
    for (size_t i = 0; i < sizeof(plain); ++i) {
        putc(plain[i], stdout);
    }
    putc('\n', stdout);
    return 0;
}
