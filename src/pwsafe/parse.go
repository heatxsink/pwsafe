package pwsafe

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

func ParseFile(inputfile, password string) (*Safe, error) {
	var safe Safe
	infile, err := os.Open(inputfile)
	if err != nil {
		log.Fatal(err)
	}
	defer infile.Close()

	r, rerr := NewReader(infile, password)
	if rerr != nil {
		return nil, rerr
	}

	headers, herr := readHeaders(r)
	if herr != nil {
		return nil, herr
	}
	safe.Headers = headers

	for {
		record, rerr := readRecord(r)
		if rerr != nil && rerr == io.EOF {
			break
		} else if rerr != nil {
			return nil, rerr
		}
		safe.Records = append(safe.Records, record)
	}

	var filehmac [32]byte
	infile.Read(filehmac[:])

	if !hmac.Equal(filehmac[:], r.hmacHash.Sum(nil)) {
		return nil, ErrHMACFailed
	}
	return &safe, nil
}

func readHeaders(r *Reader) (Headers, error) {
	var headers Headers
	for {
		field, ferr := r.ReadField()
		if ferr != nil {
			return headers, ferr
		}
		//pretty.Println("Hdr Field", ftype, fdata, string(fdata))
		switch field.Type {
		case HdrTypeVersion:
			headers.VersionMajor = field.Data[1]
			headers.VersionMinor = field.Data[0]
		case HdrTypeLastSaveTime:
			headers.LastSave, _ = parseTimeT(field.Data)
		case HdrTypeLastSaveProgram:
			headers.ProgramSave = string(field.Data)
		case HdrTypeLastSaveUser:
			headers.User = string(field.Data)
		case HdrTypeLastSaveHost:
			headers.Host = string(field.Data)
		case FldTypeEndOfEntry:
			return headers, nil
		}
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

func readRecord(r *Reader) (Record, error) {
	var record Record
	for {
		field, ferr := r.ReadField()
		if ferr != nil {
			return record, ferr
		}
		//pretty.Println("Rec Field", ftype, fdata, string(fdata))
		switch field.Type {
		case RecTypeUUID:
			copy(record.UUID[:], field.Data)
		case RecTypeGroup:
			record.Group = string(field.Data)
		case RecTypeTitle:
			record.Title = string(field.Data)
		case RecTypeUsername:
			record.Username = string(field.Data)
		case RecTypeNotes:
			record.Notes = string(field.Data)
		case RecTypePassword:
			record.Password = string(field.Data)
		case RecTypeCreationTime:
			record.CreationTime, _ = parseTimeT(field.Data)
		case RecTypeURL:
			record.Url = string(field.Data)
		case RecTypeEmail:
			record.Email = string(field.Data)
		case FldTypeEndOfEntry:
			return record, nil
		}
	}
}
