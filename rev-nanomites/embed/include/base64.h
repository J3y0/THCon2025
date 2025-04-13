#ifndef BASE64_H
#define BASE64_H

#define ALPHABET_SIZE 64
#define CHAR_BINARY_LENGTH 8

void get_char_binary(char bin_str[8], char number);

char *randomized_base64(char *input, int size_input,
                        char alphabet[ALPHABET_SIZE]);

#endif // !BASE64_H
