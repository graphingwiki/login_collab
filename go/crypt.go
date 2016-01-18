// An SHA512-crypt implementation.
// Based on http://www.akkadia.org/drepper/SHA-crypt.txt

package main

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"crypto/subtle"
	"flag"
	"fmt"
	"hash"
	"log"
	"os"
	"regexp"
	"strconv"
)

const (
	b64Table  = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	minRounds = 1000
	maxRounds = 999999999
)

func b64(b1, b2, b3 byte) []byte {
	output := make([]byte, 4)
	num := (uint32(b1) << 16) | (uint32(b2) << 8) | uint32(b3)
	for i := 0; i < 4; i++ {
		output[i] = b64Table[num&0x3f]
		num >>= 6
	}
	return output
}

func b64Enc(in []byte) []byte {
	b := new(bytes.Buffer)
	b.Write(b64(in[0], in[21], in[42]))
	b.Write(b64(in[22], in[43], in[1]))
	b.Write(b64(in[44], in[2], in[23]))
	b.Write(b64(in[3], in[24], in[45]))
	b.Write(b64(in[25], in[46], in[4]))
	b.Write(b64(in[47], in[5], in[26]))
	b.Write(b64(in[6], in[27], in[48]))
	b.Write(b64(in[28], in[49], in[7]))
	b.Write(b64(in[50], in[8], in[29]))
	b.Write(b64(in[9], in[30], in[51]))
	b.Write(b64(in[31], in[52], in[10]))
	b.Write(b64(in[53], in[11], in[32]))
	b.Write(b64(in[12], in[33], in[54]))
	b.Write(b64(in[34], in[55], in[13]))
	b.Write(b64(in[56], in[14], in[35]))
	b.Write(b64(in[15], in[36], in[57]))
	b.Write(b64(in[37], in[58], in[16]))
	b.Write(b64(in[59], in[17], in[38]))
	b.Write(b64(in[18], in[39], in[60]))
	b.Write(b64(in[40], in[61], in[19]))
	b.Write(b64(in[62], in[20], in[41]))
	b.Write(b64(0, 0, in[63]))
	return truncate(b.Bytes(), 86)
}

var re = regexp.MustCompile(`^([^:]+):\$6\$(rounds=(\d+)\$)?([^\$]{0,16})\$(\S*)\s*$`)

func parseRounds(r string) (uint64, error) {
	if r == "" {
		return 5000, nil
	}
	return strconv.ParseUint(r, 10, 64)
}

func truncate(bytes []byte, length int) []byte {
	if length < len(bytes) {
		return bytes[:length]
	}
	return bytes
}

func fill(input []byte, length int) []byte {
	output := make([]byte, length)
	inputLength := len(input)
	for i := 0; i < length; i++ {
		output[i] = input[i%inputLength]
	}
	return output
}

func newSHA512(initial ...[]byte) hash.Hash {
	result := sha512.New()
	for _, init := range initial {
		result.Write(init)
	}
	return result
}

func digestA(password []byte, salt []byte) []byte {
	A := newSHA512(password, salt)
	B := newSHA512(password, salt, password).Sum(nil)
	l := len(password)

	A.Write(fill(B, l))

	for i := l; i > 0; i >>= 1 {
		if i&0x01 == 1 {
			A.Write(B)
		} else {
			A.Write(password)
		}
	}
	return A.Sum(nil)
}

func digestDP(password []byte) []byte {
	DP := newSHA512()
	for _ = range password {
		DP.Write(password)
	}
	return DP.Sum(nil)
}

func digestDS(A []byte, salt []byte) []byte {
	DS := newSHA512()
	repeats := int(A[0]) + 16
	for i := 0; i < repeats; i++ {
		DS.Write(salt)
	}
	return DS.Sum(nil)
}

func crypt(password []byte, rounds uint64, salt []byte) []byte {
	if rounds < minRounds {
		rounds = minRounds
	} else if rounds > maxRounds {
		rounds = maxRounds
	}

	salt = truncate(salt, 16)

	A := digestA(password, salt)

	DP := digestDP(password)
	P := fill(DP, len(password))

	DS := digestDS(A, salt)
	S := fill(DS, len(salt))

	AC := A
	for i := uint64(0); i < rounds; i++ {
		C := newSHA512()

		if i%2 == 1 {
			C.Write(P)
		} else {
			C.Write(AC)
		}

		if i%3 != 0 {
			C.Write(S)
		}

		if i%7 != 0 {
			C.Write(P)
		}

		if i%2 == 1 {
			C.Write(AC)
		} else {
			C.Write(P)
		}

		AC = C.Sum(nil)
	}

	return b64Enc(AC)
}

func checkLine(line string, username string, password string) bool {
	m := re.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	if username != m[1] {
		return false
	}

	rounds, err := parseRounds(m[3])
	if err != nil {
		return false
	}
	theirHash := m[5]
	salt := m[4]

	myHash := crypt([]byte(password), rounds, []byte(salt))
	return subtle.ConstantTimeCompare([]byte(myHash), []byte(theirHash)) == 1
}

func checkFile(filename string, username string, password string) (bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if checkLine(scanner.Text(), username, password) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func main() {
	flag.Parse()
	if flag.NArg() < 3 {
		flag.Usage()
		os.Exit(1)
	}

	filename := flag.Arg(0)
	username := flag.Arg(1)
	password := flag.Arg(2)
	if pass, err := checkFile(filename, username, password); err != nil {
		log.Fatal(err)
	} else if pass {
		fmt.Println("pass")
	} else {
		fmt.Println("fail")
	}
}
