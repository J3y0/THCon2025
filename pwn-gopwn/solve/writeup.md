# Write-Up

The challenge is a GO socket application which allows a user to log in / log out and request a flag.
However, he may receive it if he is an admin only.

Also, the challenge can be disturbing as we notice some C code defined in comments of the GO code.

## CGO

If we look over the `"C" module` in GO, we can find the [official documentation of the module](https://pkg.go.dev/cmd/cgo).
It is an interface that allows GO code to call C code and the other way around.

At build time, the `cgo` command will be invoked and it will produce C files on one side and GO files on the other. Then, `gcc` or `clang` is called to generate object files of `C files`. At the same time, `go files` are compiled into object files. Finally, all these files are linked together to generate a single executable.

## Socket Communication

Analyzing the code, we understand packets exchanged with the socket respects a certain format.

Here is the GO `struct` defining them:

```go
type PacketType int8
[...]

type Packet struct {
	// -- Packet header
	Type   PacketType
	Length int8
	// -- Packet header end
	Data []byte
}
```

defines the packet we are supposed to send to the socket.

```go
type ResponsePacket struct {
	Length   int16
	Response string
}
```

defines the packet we receive from the socket.

From those definitions, we can write a function to receive packets from the socket:

```python
def recv_packet(r):
    l = r.recv(2)
    length = int.from_bytes(l, byteorder="big")

    res = b""
    while len(res) < length:
        res += r.recv(1)
    return res
```
First, we receive the length of the data transferred and then the data itself.

Okay, we know how to receive data properly from the socket.

Now, if I want a `Flag type packet`, I can send the following bytes: `\x03\x00`. Or if you want a bash command to test it:

```bash
echo "\x03\x00" | nc <host> <port> | xxd
```

>Note that we set a length of 0, because the code does not read any data for this type of packet.

If we want to send actual data to the socket with a `Login type packet`, we can send the bytes: `\x01\x05hello`. The length is set to 5, which is the length of the "hello" string.

## The flag

The flag can be acquired if the user logged is an admin. However, there is no options that can change or update the admin status directly.

At the very start of the function `handleConnection(con net.Conn)`, a `struct User_t user` is defined through `malloc` allocation. The variable is freed once the connection ends.
Let's take a look at the `struct User_t` definition:

```c
#define MAX_SIZE_USERNAME 64

struct User_t {
  char username[MAX_SIZE_USERNAME];
  int isAdmin;
};
```

So we have a username of 64 chars and a `isAdmin` field which are initialized at 0:

```c
void init_user(struct User_t *user) {
  user->isAdmin = 0;
  memset(user->username, '\0', MAX_SIZE_USERNAME);
}
```

Also, we can see the length of the new username we send is checked and the packet is not accepted if the length is greater than `MAX_SIZE_USERNAME`. So it seems impossible to perform a buffer overflow naturally.

Even if we send `\x01\x05AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`, only 5 "A"s would be copied into `username` field because `memcpy` uses the `length` provided into the packet to define the number of bytes copied.

## The vulnerability

Actually, the buffer overflow IS possible ! But it requires an extra step: we need to find a way to bypass the `checkLength` function and still have a specified length > MAX_SIZE_USERNAME.

If you did not notice before, the code is vulnerable to a `int overflow`. The code messed up the handling of the length as an unsigned integer. 

Instead, it is defined as a **signed** integer of 8 bits. It encodes values between `-128 <= v <= 127`.

However, when the `memcpy` occurs, the length is cast as a `uint8_t = unsigned integer of 8 bits`. This type encodes values between: `0 <= v <= 255`.

```c
void setLoginUsername(char dst_username[MAX_SIZE_USERNAME], void *src_username, int8_t length) {
  memcpy(dst_username, src_username, (uint8_t)length);    // <------- Vulnerable cast
  dst_username[MAX_SIZE_USERNAME-1] = '\0';
}
```

Let's think of what would happen if a negative integer was sent as the length ! Let's send -1 which can be encoded as: `0xff`.

As the code considers `0xff` as a signed integer, the length is equal to -1.

When, `checkLength` is performed, it checks: `(-1 < MAX_SIZE_USERNAME ?) => this is TRUE`. Indeed, -1 < 64.

Now, the `memcpy` occurs. The length is cast to `uint8_t` and C code now understands `0xff = 255`, as it is now unsigned !!

So, there **is a way** to copy more bytes than allowed.

It is easy to think at a simple buffer overflow to override `isAdmin` and set 1 instead of 0.

The final packet to send to overflow `isAdmin` looks like this: `\x01\xff` + `A`*64 + `\x01\x00\x00\x00` (1 encoded on 32 bits in little endian)

This will do !

## Solve script

You can find a solve script [here](./solve.py).

It communicates through the socket and performs a int overflow to write more data than allowed.
As a result, it overwrites the `isAdmin` field in the `struct User_t` to set the value 1.

Then, we can request for the flag which would be given in the response.
