package pwsafe

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"os/user"
	"time"

	"github.com/satori/go.uuid"
	"golang.org/x/crypto/twofish"
)

const iterations = 2048

func OutputFile(outputfile, password string, safe Safe) error {
	outfile, err := os.Create(outputfile)
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()

	safe.Headers.LastSave = time.Now()
	safe.Headers.ProgramSave = "pwsafe 0.1"

	user, uerr := user.Current()
	if uerr == nil && user.Username != "" {
		safe.Headers.User = user.Username
	}

	if host, herr := os.Hostname(); herr == nil {
		safe.Headers.Host = host
	}

	fmt.Fprint(outfile, "PWS3")

	var randbytes [112]byte
	if _, rerr := rand.Read(randbytes[:]); rerr != nil {
		return rerr
	}
	salt := randbytes[:32]
	iv := randbytes[32:48]
	k := randbytes[48:80]
	l := randbytes[80:]

	outfile.Write(salt)
	binary.Write(outfile, binary.LittleEndian, uint32(iterations))

	sk := computeStretchKey(salt[:], []byte(password), iterations)
	hashsk := sha256.Sum256(sk)
	outfile.Write(hashsk[:])

	var b1, b2, b3, b4 [16]byte
	tfish, _ := twofish.NewCipher(sk)
	tfish.Encrypt(b1[:], k[:16])
	tfish.Encrypt(b2[:], k[16:])
	tfish.Encrypt(b3[:], l[:16])
	tfish.Encrypt(b4[:], l[16:])

	binary.Write(outfile, binary.LittleEndian, b1[:])
	binary.Write(outfile, binary.LittleEndian, b2[:])
	binary.Write(outfile, binary.LittleEndian, b3[:])
	binary.Write(outfile, binary.LittleEndian, b4[:])

	outfile.Write(iv[:])

	tfish, _ = twofish.NewCipher(k[:])
	engine := cipher.NewCBCEncrypter(tfish, iv[:])
	hmacEngine := hmac.New(sha256.New, l[:])

	var buf bytes.Buffer
	var endSection, blockData [16]byte
	endSection[4] = 0xFF

	// Headers
	writeField(outfile, engine, hmacEngine, 0x00, []byte{safe.Headers.VersionMinor, safe.Headers.VersionMajor})
	binary.Write(&buf, binary.LittleEndian, uint32(safe.Headers.LastSave.Unix()))
	writeField(outfile, engine, hmacEngine, 0x04, buf.Bytes())
	buf.Reset()
	writeField(outfile, engine, hmacEngine, 0x06, []byte(safe.Headers.ProgramSave))
	writeField(outfile, engine, hmacEngine, 0x07, []byte(safe.Headers.User))
	writeField(outfile, engine, hmacEngine, 0x08, []byte(safe.Headers.Host))
	engine.CryptBlocks(blockData[:], endSection[:])
	outfile.Write(blockData[:])

	for _, record := range safe.Records {
		id := uuid.NewV1()
		writeField(outfile, engine, hmacEngine, 0x01, id.Bytes())
		writeField(outfile, engine, hmacEngine, 0x02, []byte(record.Group))
		writeField(outfile, engine, hmacEngine, 0x03, []byte(record.Title))
		writeField(outfile, engine, hmacEngine, 0x04, []byte(record.Username))
		writeField(outfile, engine, hmacEngine, 0x05, []byte(record.Notes))
		writeField(outfile, engine, hmacEngine, 0x06, []byte(record.Password))

		binary.Write(&buf, binary.LittleEndian, uint32(record.CreationTime.Unix()))
		writeField(outfile, engine, hmacEngine, 0x07, buf.Bytes())
		buf.Reset()

		writeField(outfile, engine, hmacEngine, 0x0d, []byte(record.Url))
		writeField(outfile, engine, hmacEngine, 0x14, []byte(record.Email))

		engine.CryptBlocks(blockData[:], endSection[:])
		outfile.Write(blockData[:])
	}
	outfile.Write([]byte("PWS3-EOFPWS3-EOF"))

	outfile.Write(hmacEngine.Sum(nil))

	return nil
}

func writeField(w io.Writer, engine cipher.BlockMode, hmacEngine hash.Hash, ftype uint8, fdata []byte) error {
	if len(fdata) < 1 {
		return nil
	}

	type field struct {
		Length uint32
		Type   uint8
		Data   [11]byte
	}
	var datafield field
	datafield.Length = uint32(len(fdata))
	datafield.Type = ftype
	copy(datafield.Data[:], fdata)

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, &datafield)

	if datafield.Length > 11 {
		datafield.Length = datafield.Length - 11
		numBlocksToWrite := datafield.Length / 16
		if datafield.Length%16 != 0 {
			numBlocksToWrite++
		}
		blockData := make([]byte, numBlocksToWrite*16)
		copy(blockData, fdata[11:])
		buf.Write(blockData)
	}

	bufData := buf.Bytes()
	blockData := make([]byte, len(bufData))

	engine.CryptBlocks(blockData[:], bufData[:])

	hmacEngine.Write(fdata)

	_, errw := w.Write(blockData)
	return errw
}
