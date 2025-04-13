#include "base64.h"
#include <openssl/sha.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENCRYPTED_FLAG                                                         \
  "FIxxS8RHv8bL/cC5wgcGWknMm9CfIf4/br41UYPmtrOkIg5mwIzdF8SHdI4h7IA7f0Q/iC=="
#define FLAG_HASH                                                              \
  "e9cc2ba9d9e07b3847953efbb85a9ece10a921c61179354d3887e914fca0d343"
#define KEY "THCon2025"
#define ALPHABET                                                               \
  "IcU/4SfFP6um+VJw8lWibvrtsRqT5Q7dy9o2M0gjBnDaxzNHCGZ3EOkYXAhLe1pK"

void print_usage();

char *encrypt(char *input, int size_input) {
  char *cipher = malloc(size_input + 1);
  int size_key = strlen(KEY);

  for (int i = 0; i < size_input; i++) {
    cipher[i] = input[i] ^ KEY[(i + 1) % size_key];
  }
  cipher[size_input] = '\0';

  char *result = randomized_base64(cipher, size_input, ALPHABET);
  free(cipher);

  return result;
}

char *sha256_hexdigest(unsigned char *hash) {
  char *hexdigest = malloc(2 * SHA256_DIGEST_LENGTH);
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    snprintf(&hexdigest[2 * i], 3, "%02x", hash[i]);
  }

  return hexdigest;
}

int check_flag(char *input, int size_input) {
  // Compare hash
  unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);
  SHA256((unsigned char *)input, size_input, hash);
  char *hash_digest = sha256_hexdigest(hash);
  if (strncmp(hash_digest, FLAG_HASH, 2 * SHA256_DIGEST_LENGTH)) {
    return 0;
  }

  // Compare encryption
  char *cipher = encrypt(input, size_input);
  if (strncmp(cipher, ENCRYPTED_FLAG, strlen(ENCRYPTED_FLAG)) != 0) {
    return 0;
  }

  free(cipher);
  return 1;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    print_usage();
    exit(1);
  }

  if (check_flag(argv[1], strlen(argv[1]))) {
    printf("Well done ! You can validate with your input!\n");
  } else {
    printf("Intruder detected ! Deploying security troops !\n");
  }

  return 0;
}

void print_usage() {
  printf("Usage: ./<program> PASSWORD\n");
  printf("Let you reach new horizons if you have the right PASSWORD\n");
}
