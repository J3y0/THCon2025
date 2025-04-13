#!/bin/bash

# Compile embedded program
cd ./embed/

echo "[+] Cleaning embed/ dir"
make clean 2>/dev/null
echo "[+] Compile embedded program"
make strip
cp ./embedded ../host/embedded
cd ../

# Generate updated host program
cd ./host
echo "[+] Cleaning host/ dir"
make clean 2>/dev/null

echo "[+] Copy model of host to 'chall.c'"
cp host_model.c chall.c

# Generate encrypted version of embedded
echo "[+] Generate encrypted program"
python helper_scripts/packer.py

echo "[+] Copy encrypted bytes to 'chall.c'"
xxd -i encrypted >>chall.c

# Compile host
echo "[+] Compile host program"

mv src/main.c src/main.c.backup
mv chall.c src/main.c
make strip
mv src/main.c.backup src/main.c
cp main ../nano_mites
