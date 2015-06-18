package pwsafe

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/twofish"
)

type psv3Header struct {
	Tag                [4]byte // "PWS3"
	Salt               [32]byte
	Iter               uint32
	HashPPrime         [32]byte
	B1, B2, B3, B4, IV [16]byte
}

func ParseFile(inputfile, password string) (*Safe, error) {
	var safe Safe
	infile, err := os.Open(inputfile)
	if err != nil {
		log.Fatal(err)
	}
	defer infile.Close()

	var header psv3Header
	binary.Read(infile, binary.LittleEndian, &header)
	if string(header.Tag[:]) != "PWS3" {
		return nil, fmt.Errorf("Invalid magic at start of file.")
	}

	sk := computeStretchKey(header.Salt[:], []byte(password), int(header.Iter))
	hashsk := sha256.Sum256(sk)

	if hashsk != header.HashPPrime {
		log.Fatalln("invalid key password")
	}

	var key, hmacKey [32]byte
	tfish, _ := twofish.NewCipher(sk)
	tfish.Decrypt(key[:16], header.B1[:])
	tfish.Decrypt(key[16:], header.B2[:])
	tfish.Decrypt(hmacKey[:16], header.B3[:])
	tfish.Decrypt(hmacKey[16:], header.B4[:])

	tfish, _ = twofish.NewCipher(key[:])
	engine := cipher.NewCBCDecrypter(tfish, header.IV[:])
	hmacEngine := hmac.New(sha256.New, hmacKey[:])

	safe.readHeaders(infile, engine, hmacEngine)
	for {
		eof := safe.readRecord(infile, engine, hmacEngine)
		if eof {
			break
		}
	}

	var filehmac [32]byte
	infile.Read(filehmac[:])

	if !hmac.Equal(filehmac[:], hmacEngine.Sum(nil)) {
		log.Fatalln("hmac verification failed")
	}
	return &safe, nil
}

func (safe *Safe) readHeaders(r io.Reader, engine cipher.BlockMode, hmacEngine hash.Hash) {
	for {
		ftype, fdata, ferr := safe.readField(r, engine)
		if ferr != nil {
			log.Fatalln(ferr)
		}
		//pretty.Println("Hdr Field", ftype, fdata, string(fdata))
		switch ftype {
		case 0x00:
			safe.Headers.VersionMajor = fdata[1]
			safe.Headers.VersionMinor = fdata[0]
		case 0x04:
			safe.Headers.LastSave, _ = parseTimeT(fdata)
		case 0x06:
			safe.Headers.ProgramSave = string(fdata)
		case 0x07:
			safe.Headers.User = string(fdata)
		case 0x08:
			safe.Headers.Host = string(fdata)
		case 0xFF:
			return
		}
		hmacEngine.Write([]byte(fdata))
	}
}

func parseTimeT(data []byte) (time.Time, error) {
	buf := bytes.NewReader(data)
	switch len(data) {
	case 4:
		var timet uint32
		binary.Read(buf, binary.LittleEndian, &timet)
		return time.Unix(int64(timet), 0), nil
	case 8:
		var timet uint64
		binary.Read(buf, binary.LittleEndian, &timet)
		return time.Unix(int64(timet), 0), nil
	}
	return time.Now(), fmt.Errorf("Unable to parse time_t")
}

func (safe *Safe) readRecord(r io.Reader, engine cipher.BlockMode, hmacEngine hash.Hash) (eof bool) {
	var record Record
	for {
		ftype, fdata, ferr := safe.readField(r, engine)
		if ferr != nil && ferr != io.EOF {
			log.Fatalln(ferr)
		}
		if ferr == io.EOF {
			return true
		}
		//pretty.Println("Rec Field", ftype, fdata, string(fdata))
		switch ftype {
		case 0x01:
			copy(record.UUID[:], fdata)
		case 0x02:
			record.Group = string(fdata)
		case 0x03:
			record.Title = string(fdata)
		case 0x04:
			record.Username = string(fdata)
		case 0x05:
			record.Notes = string(fdata)
		case 0x06:
			record.Password = string(fdata)
		case 0x07:
			record.CreationTime, _ = parseTimeT(fdata)
		case 0x0d:
			record.Url = string(fdata)
		case 0x14:
			record.Email = string(fdata)
		case 0xFF:
			safe.Records = append(safe.Records, record)
			record = Record{}
			return false
		}
		hmacEngine.Write([]byte(fdata))
	}
}

func (safe *Safe) readField(r io.Reader, engine cipher.BlockMode) (fieldType uint8, fieldData []byte, err error) {
	var block [16]byte
	berr := binary.Read(r, binary.LittleEndian, &block)
	if berr != nil {
		return 0, nil, berr
	}

	if string(block[:]) == "PWS3-EOFPWS3-EOF" {
		return 0, nil, io.EOF
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

	if clearField.Length <= 11 {
		return clearField.Type, clearField.Data[:clearField.Length], nil
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
		return 0, nil, blerr
	}
	engine.CryptBlocks(blockData, blockData)
	return clearField.Type, append(clearField.Data[:], blockData[:clearField.Length]...), nil
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
