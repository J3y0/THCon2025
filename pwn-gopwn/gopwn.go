package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"unsafe"
)

// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
//
// #define MAX_SIZE_USERNAME 64
//
// struct User_t {
//   char username[MAX_SIZE_USERNAME];
//   int isAdmin;
// };
//
// int checkLength(int8_t length) {
//   if (length < MAX_SIZE_USERNAME) {
//     return 1;
//   }
//
//   return 0;
// }
//
// void init_user(struct User_t *user) {
//   user->isAdmin = 0;
//   memset(user->username, '\0', MAX_SIZE_USERNAME);
// }
//
// void setLoginUsername(char dst_username[MAX_SIZE_USERNAME], void *src_username, int8_t length) {
//   memcpy(dst_username, src_username, (uint8_t)length);
//   dst_username[MAX_SIZE_USERNAME-1] = '\0';
// }
import "C"

const MAX_UINT8 = 255

type PacketType int8

const (
	Login PacketType = 1 + iota
	Logout
	Flag
	Exit
)

type Packet struct {
	// -- Packet header
	Type   PacketType
	Length int8
	// -- Packet header end
	Data []byte
}

func (p *Packet) FromBytes(b []byte) (err error) {
	buf := bytes.NewBuffer(b)

	// Should have a header
	if buf.Len() < 2 {
		err = fmt.Errorf("Bad packet: incorrect header")
		return err
	}

	err = binary.Read(buf, binary.BigEndian, &p.Type)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.BigEndian, &p.Length)
	if err != nil {
		return err
	}

	p.Data = buf.Next(buf.Len())
	return nil
}

type ResponsePacket struct {
	Length   int16
	Response string
}

func (rp *ResponsePacket) Bytes() []byte {
	resp := make([]byte, 0, rp.Length+2)
	resp, _ = binary.Append(resp, binary.BigEndian, rp.Length)

	resp = append(resp, rp.Response...)

	return resp
}

func handleConnection(con net.Conn) {
	defer func(con net.Conn) {
		fmt.Println("Connection stopped")
		con.Close()
	}(con)

	user := (*C.struct_User_t)(C.malloc(MAX_UINT8))
	C.init_user(user)
	defer C.free(unsafe.Pointer(user))

	isLogged := false
	r := bufio.NewReader(con)
	resPacket := &ResponsePacket{}

Loop:
	for {
		// Read received packet
		read, err := r.ReadBytes('\n')
		if err != nil && err.Error() != "EOF" {
			resPacket.Response = err.Error() + "\n"
			resPacket.Length = int16(len(resPacket.Response))
			con.Write(resPacket.Bytes())
			break Loop
		}
		read = bytes.TrimSuffix(read, []byte("\n"))

		// Parse packet
		packet := Packet{}
		err = packet.FromBytes(read)
		if err != nil {
			resPacket.Response = err.Error() + "\n"
			resPacket.Length = int16(len(resPacket.Response))
			con.Write(resPacket.Bytes())
			break Loop
		}

		// Check length is less than max size allowed
		c_length := C.int8_t(packet.Length)
		if C.checkLength(c_length) == 0 {
			resPacket.Response = "Packet exceeds max length !\n"
			resPacket.Length = int16(len(resPacket.Response))
			con.Write(resPacket.Bytes())
			continue
		}

		switch packet.Type {
		case Login:
			c_data := C.CBytes(packet.Data)
			C.setLoginUsername(&user.username[0], c_data, c_length)

			var res bytes.Buffer

			res.WriteString("--- Login details ---\n")
			res.WriteString("Username: ")
			res.WriteString(C.GoString(&user.username[0]))
			res.WriteByte('\n')

			res.WriteString("Is admin: ")
			if user.isAdmin == 1 {
				res.WriteString("true")
			} else {
				res.WriteString("false")
			}
			res.WriteByte('\n')

			resPacket.Response = res.String()
			resPacket.Length = int16(len(resPacket.Response))
			con.Write(resPacket.Bytes())

			C.free(unsafe.Pointer(c_data))
			isLogged = true
		case Logout:
			if isLogged {
				isLogged = false
				resPacket.Response = "You successfully log out !\n"
			} else {
				resPacket.Response = "Please login in a first place...\n"
			}

			resPacket.Length = int16(len(resPacket.Response))
			con.Write(resPacket.Bytes())
		case Flag:
			if isLogged && user.isAdmin == 1 {
				flag, err := os.ReadFile("./flag.txt")
				if err != nil {
					resPacket.Response = "Something went wrong reading the file, please contact an admin..\n"
				} else {
					var res bytes.Buffer
					res.WriteString("Here is the flag: ")
					res.Write(flag)
					res.WriteByte('\n')

					resPacket.Response = res.String()
				}
			} else {
				resPacket.Response = "Looks like you are a simple user, why would you think you have the right to see this flag ?\n"
			}

			resPacket.Length = int16(len(resPacket.Response))
			con.Write(resPacket.Bytes())
		case Exit:
			resPacket.Response = "See you later !\n"
			resPacket.Length = int16(len(resPacket.Response))
			con.Write(resPacket.Bytes())
			break Loop
		default:
			resPacket.Response = "Unrecognized packet type\n"
			resPacket.Length = int16(len(resPacket.Response))
			con.Write(resPacket.Bytes())
			break Loop
		}
	}
}

func main() {
	ln, err := net.Listen("tcp", ":4000")
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Listening on port 4000")
	for {
		con, err := ln.Accept()
		if err != nil {
			fmt.Printf("something went wrong: cannot accept new connection '%v'\n", err)
		}

		fmt.Println("New connection accepted")
		go handleConnection(con)
	}
}
