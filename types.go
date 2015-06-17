package pwsafe

import (
	"net/url"
	"time"
)

type Headers struct {
	VersionMajor, VersionMinor uint8
	LastSave                   time.Time
	ProgramSave                string
	User                       string
	Host                       string
}

type Record struct {
	UUID         [16]byte
	Group        string
	Title        string
	Username     string
	Notes        string
	Password     string
	CreationTime time.Time
	Url          *url.URL
	Email        string
}

type Safe struct {
	Headers Headers
	Records []Record
}
