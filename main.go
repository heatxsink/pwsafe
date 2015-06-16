package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/twofish"

	"github.com/howeyc/gopass"
	"github.com/kr/pretty"
)

type psv3Header struct {
	Tag                [4]byte // "PWS3"
	Salt               [32]byte
	Iter               uint32
	HashPPrime         [32]byte
	B1, B2, B3, B4, IV [16]byte
}

func main() {
	inputfile := flag.String("f", "", "input file")

	flag.Parse()

	infile, err := os.Open(*inputfile)
	if err != nil {
		log.Fatal(err)
	}
	defer infile.Close()

	var header psv3Header
	binary.Read(infile, binary.LittleEndian, &header)
	pretty.Printf("%#v\n", header)

	fmt.Printf("Password: ")
	pw := gopass.GetPasswd()

	sk := computeStretchKey(header.Salt[:], []byte(pw), int(header.Iter))
	hashsk := sha256.Sum256(sk)
	pretty.Println(hashsk)

	if hashsk != header.HashPPrime {
		log.Fatalln("invalid key password")
	}

	var key, hmacKey [32]byte
	tfish, _ := twofish.NewCipher(sk)
	tfish.Decrypt(key[:16], header.B1[:])
	tfish.Decrypt(key[16:], header.B2[:])
	tfish.Decrypt(hmacKey[:16], header.B3[:])
	tfish.Decrypt(hmacKey[16:], header.B4[:])

	pretty.Println("Keys", key, hmacKey)

	tfish, _ = twofish.NewCipher(key[:])
	engine := cipher.NewCBCDecrypter(tfish, header.IV[:])
	hmacEngine := hmac.New(sha256.New, hmacKey[:])

	readHeaders(infile, engine, hmacEngine)
	readAllFields(infile, engine, hmacEngine)
	readAllFields(infile, engine, hmacEngine)

	var filehmac [32]byte
	infile.Read(filehmac[:])

	pretty.Println(filehmac)
	pretty.Println(hmacEngine.Sum(nil))
}

func readHeaders(r io.Reader, engine cipher.BlockMode, hmacEngine hash.Hash) {
	for {
		ftype, fdata, ferr := readField(r, engine)
		if ferr != nil {
			log.Fatalln(ferr)
		} else {
			pretty.Println("Field", ftype, []byte(fdata), fdata)
		}
		if ftype == 0xFF {
			break
		}
		hmacEngine.Write([]byte(fdata))
	}
}

func readAllFields(r io.Reader, engine cipher.BlockMode, hmacEngine hash.Hash) {
	for {
		ftype, fdata, ferr := readField(r, engine)
		if ferr != nil {
			log.Fatalln(ferr)
		} else {
			pretty.Println("Field", ftype, []byte(fdata), fdata)
		}
		if ftype == 0xFF || fdata == "EOF" {
			break
		}
		hmacEngine.Write([]byte(fdata))
	}
}

func readField(r io.Reader, engine cipher.BlockMode) (fieldType uint8, fieldData string, err error) {
	var block [16]byte
	berr := binary.Read(r, binary.LittleEndian, &block)
	if berr != nil {
		return 0, "", berr
	}

	if string(block[:]) == "PWS3-EOFPWS3-EOF" {
		return 0, "EOF", nil
	}

	engine.CryptBlocks(block[:], block[:])

	buf := bytes.NewBuffer(block[:])

	type field struct {
		Length uint32
		Type   uint8
		Data   [11]byte
	}
	var clearField field

	binary.Read(buf, binary.LittleEndian, &clearField)

	if clearField.Length < 11 {
		return clearField.Type, string(clearField.Data[:clearField.Length]), nil
	}

	// Read long data
	clearField.Length = clearField.Length - 11
	numBlocksToRead := clearField.Length / 16
	if clearField.Length%16 != 0 {
		numBlocksToRead++
	}
	blockData := make([]byte, numBlocksToRead*16)
	_, blerr := r.Read(blockData)
	if blerr != nil {
		return 0, "", blerr
	}
	engine.CryptBlocks(blockData, blockData)
	return clearField.Type, string(append(clearField.Data[:], blockData[:clearField.Length]...)), nil
}

func computeStretchKey(salt, password []byte, iterations int) []byte {
	sha := sha256.New()

	sha.Write(password)
	sha.Write(salt)

	xi := sha.Sum(nil)

	for j := 0; j < iterations; j++ {
		result := sha256.Sum256(xi)
		xi = result[:]
	}
	return xi
}
