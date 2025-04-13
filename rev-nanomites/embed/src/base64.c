#include "base64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void get_char_binary(char bin_str[CHAR_BINARY_LENGTH], char number) {
  int i_bin = 0;

  while (number != 0 || i_bin < 8) {
    int remainder = number % 2;

    bin_str[CHAR_BINARY_LENGTH - 1 - i_bin] = remainder ? '1' : '0';
    i_bin++;
    number = number / 2;
  }
}

/*
 * Generate the base64 of input with a specified alphabet
 * Output has to be freed afterwards
 */
char *randomized_base64(char *input, int size_input,
                        char alphabet[ALPHABET_SIZE]) {
  int padding = (3 - size_input % 3) % 3;

  // Convert input to binary string padded
  int size_binary_input = 8 * (size_input + padding);
  char *bin_input = malloc(size_binary_input);
  for (int i = 0; i < size_input; i++) {
    char binary[CHAR_BINARY_LENGTH];
    get_char_binary(binary, input[i]);
    strncpy(bin_input + 8 * i, binary, CHAR_BINARY_LENGTH);
  }
  for (int i = size_binary_input - 8 * padding; i < size_binary_input; i += 8) {
    char binary[CHAR_BINARY_LENGTH];
    get_char_binary(binary, 0);
    strncpy(bin_input + i, binary, CHAR_BINARY_LENGTH);
  }

  // Generate output encoding
  int size_output = size_binary_input / 6;
  char *output = malloc(size_output + 1);

  for (int i = 0; i < size_binary_input; i += 6) {
    // Slice in chunks of 6
    char offset_bin[6 + 1];
    strncpy(offset_bin, bin_input + i, 6);
    offset_bin[6] = '\0';
    long offset = strtol(offset_bin, NULL, 2);

    if (i / 6 < size_output - padding) {
      output[i / 6] = alphabet[offset];
    } else {
      // Padding
      output[i / 6] = '=';
    }
  }
  output[size_output] = '\0';

  free(bin_input);
  return output;
}
