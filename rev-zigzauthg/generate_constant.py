def product(chars) -> int:
    pro = 1
    for c in chars:
        pro *= ord(c)
    return pro


if __name__ == "__main__":
    with open("./flag.txt", "r") as f:
        flag = f.read().rstrip()

    all_products = []
    all_starts = []
    all_third = []
    nb_exception = 4  # 4 ud2 occured before looping over passphrase
    state = 0
    login = "TheSecretShadow"
    for i in range(0, len(flag), 4):
        chunk = flag[i:i+4]
        print(chunk)
        all_starts.append(chunk[:2])
        all_third.append((ord(chunk[2]) ^ nb_exception) +
                         sum(list(map(ord, login))))

        pro = product(chunk)
        all_products.append(pro)

        state ^= pro
        nb_exception += 1

    print(f"{state=}")
    print(f"product = {all_products}")
    print(f"starts = {all_starts}")
    print(f"thirds = {all_third}")
