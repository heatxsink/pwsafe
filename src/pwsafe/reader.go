package pwsafe

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/twofish"
)

// Enumeration of field types
type FieldType uint8

const (
	FldTypeEndOfEntry FieldType = 0xFF

	HdrTypeVersion           FieldType = 0x00
	HdrTypeUUID              FieldType = 0x01
	HdrTypeNonDefaultPrefs   FieldType = 0x02
	HdrTypeTreeDisplayStatus FieldType = 0x03
	HdrTypeLastSaveTime      FieldType = 0x04
	HdrTypeLastSaveProgram   FieldType = 0x06
	HdrTypeLastSaveUser      FieldType = 0x07
	HdrTypeLastSaveHost      FieldType = 0x08
	HdrTypeDatabaseName      FieldType = 0x09
	HdrTypeDatabaseDesc      FieldType = 0x0a
	HdrTypeDatabaseFilters   FieldType = 0x0b
	HdrTypeRecentlyUsed      FieldType = 0x0f
	HdrTypePasswordPolicies  FieldType = 0x10
	HdrTypeEmptyGroups       FieldType = 0x11

	RecTypeUUID         FieldType = 0x01
	RecTypeGroup        FieldType = 0x02
	RecTypeTitle        FieldType = 0x03
	RecTypeUsername     FieldType = 0x04
	RecTypeNotes        FieldType = 0x05
	RecTypePassword     FieldType = 0x06
	RecTypeCreationTime FieldType = 0x07
	RecTypeURL          FieldType = 0x0d
	RecTypeEmail        FieldType = 0x14
)

// Field structure for read/write to file
type Field struct {
	Type FieldType
	Data []byte
}

var (
	ErrBadFileType     = errors.New("invalid pwsafe file")
	ErrInvalidPassword = errors.New("invalid file password")
	ErrHMACFailed      = errors.New("hmac verification failed")
	EOF                = errors.New("end of field data")
)

type psv3Header struct {
	Tag                [4]byte // "PWS3"
	Salt               [32]byte
	Iter               uint32
	HashPPrime         [32]byte
	B1, B2, B3, B4, IV [16]byte
}

// A Reader parses fields from an encrypted psafe3 file.
type Reader struct {
	r              io.Reader
	password       string
	tfishDecrypter cipher.BlockMode
	hmacHash       hash.Hash
}

// Returns a new Reader that reads from r
//
// The header section storing the salt and keys is read from r to verify the file is
// actually a psafe3 file and the password is correct.
//
// All reads from this reader will return unencrypted data.
func NewReader(r io.Reader, password string) (*Reader, error) {
	reader := &Reader{r: r, password: password}

	var header psv3Header
	binary.Read(r, binary.LittleEndian, &header)
	if string(header.Tag[:]) != "PWS3" {
		return nil, ErrBadFileType
	}

	sk := computeStretchKey(header.Salt[:], []byte(password), int(header.Iter))
	hashsk := sha256.Sum256(sk)

	if hashsk != header.HashPPrime {
		return nil, ErrInvalidPassword
	}

	var key, hmacKey [32]byte
	tfish, _ := twofish.NewCipher(sk)
	tfish.Decrypt(key[:16], header.B1[:])
	tfish.Decrypt(key[16:], header.B2[:])
	tfish.Decrypt(hmacKey[:16], header.B3[:])
	tfish.Decrypt(hmacKey[16:], header.B4[:])

	tfish, _ = twofish.NewCipher(key[:])
	reader.tfishDecrypter = cipher.NewCBCDecrypter(tfish, header.IV[:])
	reader.hmacHash = hmac.New(sha256.New, hmacKey[:])

	return reader, nil
}

// Read one field from r
//
// A return of EOF marks the end of field data.
// Call Verify to verify the integrity of the file after EOF.
func (r *Reader) ReadField() (Field, error) {
	var field Field
	var block [16]byte
	berr := binary.Read(r.r, binary.LittleEndian, &block)
	if berr != nil {
		return field, berr
	}

	if string(block[:]) == "PWS3-EOFPWS3-EOF" {
		return field, EOF
	}

	r.tfishDecrypter.CryptBlocks(block[:], block[:])

	buf := bytes.NewBuffer(block[:])

	type blockField struct {
		Length uint32
		Type   uint8
		Data   [11]byte
	}
	var clearField blockField

	binary.Read(buf, binary.LittleEndian, &clearField)

	if clearField.Length <= 11 {
		field.Type = FieldType(clearField.Type)
		field.Data = clearField.Data[:clearField.Length]
		r.hmacHash.Write(field.Data)
		return field, nil
	}

	// Read long data
	clearField.Length = clearField.Length - 11
	numBlocksToRead := clearField.Length / 16
	if clearField.Length%16 != 0 {
		numBlocksToRead++
	}
	blockData := make([]byte, numBlocksToRead*16)
	_, blerr := r.r.Read(blockData)
	if blerr != nil {
		return field, blerr
	}
	r.tfishDecrypter.CryptBlocks(blockData, blockData)

	field.Type = FieldType(clearField.Type)
	field.Data = append(clearField.Data[:], blockData[:clearField.Length]...)
	r.hmacHash.Write(field.Data)

	return field, nil
}

// Verify the HMAC sum.
func (r *Reader) Verify() error {
	var filehmac [32]byte
	r.r.Read(filehmac[:])

	if !hmac.Equal(filehmac[:], r.hmacHash.Sum(nil)) {
		return ErrHMACFailed
	}

	return nil
}
