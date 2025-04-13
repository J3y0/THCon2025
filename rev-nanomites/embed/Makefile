INCLUDE := -I./include/
CC := $(shell which gcc)

CFLG_DBG := -g
CFLG_WRN := -Wall -W -Werror
CFLG_LD := -lcrypto
CFLAGS := $(CFLG_WRN) $(INCLUDE) $(CFLG_LD)

.PHONY: clean embedded debug strip

clean:
	- rm -rf *.o
	- find . -maxdepth 1 -executable -type f \( ! -name "Makefile" \) -delete

%.o: ./src/%.c
	$(CC) $(CFLAGS) -o $@ -c $^

embedded: embedded.o base64.o
	$(CC) $(CFLAGS) -o embedded embedded.o base64.o

debug: embedded.o base64.o
	$(CC) $(CFLAGS) $(CFLG_DBG) -o embedded embedded.o base64.o

strip: embedded
	- strip embedded --keep-symbol=randomized_base64 -o embedded
