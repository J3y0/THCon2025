INCLUDE := -I./include/
CC := $(shell which gcc)

CFLG_DBG := -g
CFLG_WRN := -Wall -W -Werror
CFLG_LD := -lcrypto

CFLAGS := $(CFLG_WRN) $(INCLUDE) $(CFLG_LD)

.PHONY: clean

clean:
	- rm -rf *.o
	- rm encrypted
	- find . -maxdepth 1 -executable -type f \( ! -name "Makefile" \) -delete

%.o: ./src/%.c
	$(CC) $(CFLAGS) -o $@ -c $^

main: main.o packer.o aes.o
	$(CC) $(CFLAGS) -o main main.o packer.o aes.o

debug: main.o packer.o aes.o
	$(CC) $(CFLAGS) $(CFLG_DBG) -o main main.o packer.o aes.o

strip: main
	- strip main --keep-symbol=AES_init_ctx_iv --keep-symbol=AES_CBC_decrypt_buffer -o main
