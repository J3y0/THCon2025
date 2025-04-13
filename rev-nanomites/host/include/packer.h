#ifndef PACKER_H
#define PACKER_H

#include <sys/types.h>

#define SIZE_K 16

#define SIZE_KEYS_TABLE 0x80
#define SIZE_IV_TABLE 0x80

#define IV_SIZE 16
#define KEY_SIZE 16
#define SALT_SIZE 9

#define BLOCKSIZE 16

extern const u_int64_t K[SIZE_K];
extern const unsigned char IV_TABLE[SIZE_IV_TABLE][IV_SIZE];
extern const unsigned char KEYS_TABLE[SIZE_KEYS_TABLE][KEY_SIZE];
extern const unsigned char SALT[SALT_SIZE];

u_int64_t rol(u_int64_t val, unsigned int shift);
u_int64_t ror(u_int64_t val, unsigned int shift);

u_int64_t mask_low(u_int64_t iv_low);
u_int64_t mask_high(u_int64_t iv_high);

typedef unsigned char *Mask;
Mask compute_mask(unsigned char iv[IV_SIZE]);

int next_index(unsigned char block[BLOCKSIZE], int offset);
int decrypt_block(unsigned char block[], unsigned char decrypted[],
                  int idx_key);

#endif // !PACKER_H
