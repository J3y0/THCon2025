ALPHABET = "IcU/4SfFP6um+VJw8lWibvrtsRqT5Q7dy9o2M0gjBnDaxzNHCGZ3EOkYXAhLe1pK"
FLAG_ENCRYPTED = "FIxxS8RHv8bL/cC5wgcGWknMm9CfIf4/br41UYPmtrOkIg5mwIzdF8SHdI4h7IA7f0Q/iC=="
KEY = b"THCon2025"


def decode_custom_base64(input: str, alphabet: str):
    bininput = ""
    for i in range(len(input)):
        idx = alphabet.find(input[i])
        if idx == -1: # must be =
            bininput += "0"*6
        else:
            bininput += bin(idx)[2:].zfill(6)

    assert len(bininput)%8 == 0

    res = b""
    for i in range(0, len(bininput), 8):
        res += int(bininput[i:i+8], 2).to_bytes(1, "little")

    while res.endswith(b"\x00"):
        res = res[:-1]
    return res


def decrypt(input: bytes):
    flag = ""
    for i in range(len(input)):
        flag += chr(input[i] ^ KEY[(i + 1) % len(KEY)])

    return flag


if __name__ == "__main__":
    print(decode_custom_base64(FLAG_ENCRYPTED, ALPHABET))
    raw_flag = decode_custom_base64(FLAG_ENCRYPTED, ALPHABET)
    print("Flag:", decrypt(raw_flag))
