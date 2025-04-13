def product_chars(chars) -> int:
    pro = 1
    for c in chars:
        pro *= ord(c)
    return pro


def sum_chars(chars) -> int:
    return sum(list(map(ord, chars)))


def find_login():
    login = "TeerthdwhSceSao"

    find = [""]*len(login)
    for i in range(len(login)):
        find[(2*i) % len(login)] = login[i]

    return "".join(find)


def find_passphrase():
    real_login = "TheSecretShadow"
    product = [49841568, 38760000, 37620000,
               67581290, 38670320, 47516040, 41367375]
    starts = ['TH', 'd0', '_K', 'w_', 'g_', 'nG', 'g3']
    thirds = [1588, 1607, 1621, 1642, 1585, 1641, 1570]

    flag = ""
    num_exception = 4
    for i in range(len(product)):
        flag += starts[i]
        flag += chr((thirds[i] - sum_chars(real_login)) ^ num_exception)

        assert product[i] % product_chars(flag[-3:]) == 0
        flag += chr(product[i]//product_chars(flag[-3:]))

        num_exception += 1

    return flag


if __name__ == "__main__":
    print(f"Login = {find_login()}")
    print(f"Passphrase = {find_passphrase()}")
