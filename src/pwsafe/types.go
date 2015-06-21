package pwsafe

import (
	"time"

	"github.com/satori/go.uuid"
)

type Headers struct {
	VersionMajor, VersionMinor uint8
	LastSave                   time.Time
	ProgramSave                string
	User                       string
	Host                       string
}

type Record struct {
	UUID         uuid.UUID
	Group        string
	Title        string
	Username     string
	Notes        string
	Password     string
	CreationTime time.Time
	Url          string
	Email        string
}

type Safe struct {
	Headers Headers
	Records []Record
}
