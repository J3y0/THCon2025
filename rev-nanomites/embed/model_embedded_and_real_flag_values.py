import hashlib
import sys

FLAG_ENCRYPTED = b"FIxxS8RHv8bL/cC5wgcGWknMm9CfIf4/br41UYPmtrOkIg5mwIzdF8SHdI4h7IA7f0Q/iC=="
KEY = b"THCon2025"


def randomized_base64(input: bytes, alphabet: str):
    padding = (3 - len(input) % 3) % 3
    if padding != 0:
        input += b"\x00" * padding

    binaryinput = "".join([bin(b)[2:].zfill(8) for b in input])

    res = ""
    for i in range(0, len(binaryinput), 6):
        res += alphabet[int(binaryinput[i:i+6], 2)]

    res = res[:-padding] + "=" * padding
    return res.encode()


def check_flag(input: str) -> bool:
    if hashlib.sha256(input.encode()).hexdigest() != "e9cc2ba9d9e07b3847953efbb85a9ece10a921c61179354d3887e914fca0d343":
        return False

    input_bytes = input.encode()
    encoded = encrypt_input(input_bytes)

    if encoded != FLAG_ENCRYPTED:
        return False

    return True


def encrypt_input(input: bytes):
    res = b""
    for i in range(len(input)):
        res += (input[i] ^ KEY[(i+1) % len(KEY)]).to_bytes(1, "little")

    # --- GENERATED WITH ---
    # random.seed(2025)
    # listed = list(alphabet)
    # random.shuffle(listed)
    # alph_randomized = "".join(listed)
    # print(alph_randomized)
    # ----------------------
    randomized_alphabet = "IcU/4SfFP6um+VJw8lWibvrtsRqT5Q7dy9o2M0gjBnDaxzNHCGZ3EOkYXAhLe1pK"
    encoded = randomized_base64(res, randomized_alphabet)
    return encoded


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <PASSWORD>")
        exit(0)

    with open("../flag.txt", "rb") as f:
        true_flag = f.read().rstrip()
        encrypted = encrypt_input(true_flag)
        print(f"{true_flag=}")
        print(f"{encrypted=}")
        print("sha256(flag) =", hashlib.sha256(true_flag).hexdigest())
        print()
        print(len(true_flag), len(encrypted))

    password = sys.argv[1]
    if check_flag(password):
        print("Awesome ! You can validate with your input")
    else:
        print("Intruder detected ! Deploying security troops !")
