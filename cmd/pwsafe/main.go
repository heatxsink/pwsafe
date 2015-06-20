package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"pwsafe"

	"github.com/gizak/termui"
	"github.com/howeyc/gopass"
	"github.com/satori/go.uuid"
)

// ByGroupTitle
type ByGroupTitle []pwsafe.Record

func (b ByGroupTitle) Len() int      { return len(b) }
func (b ByGroupTitle) Swap(i, j int) { b[i], b[j] = b[j], b[i] }
func (b ByGroupTitle) Less(i, j int) bool {
	if b[i].Group == b[j].Group {
		return b[i].Title < b[j].Title
	}
	return b[i].Group < b[j].Group
}

func main() {
	pfile := flag.String("f", "", "psafe3 file")
	flag.Parse()

	fmt.Printf("Password: ")
	pw := gopass.GetPasswd()

	safe, err := pwsafe.ParseFile(*pfile, string(pw))
	if err != nil {
		log.Fatalln(err)
	}

	sort.Sort(ByGroupTitle(safe.Records))

	errt := termui.Init()
	if errt != nil {
		log.Fatal(errt)
	}

	rightpar := termui.NewPar(fmt.Sprintf("Last Saved: %s\nLast Saved By %s @ %s",
		safe.Headers.LastSave.Format("2006-01-02 15:04:05"),
		safe.Headers.User, safe.Headers.Host))
	rightpar.Height = 2
	rightpar.HasBorder = false

	leftpar := termui.NewPar(fmt.Sprintf("File Name: %s\nLast Program: %s",
		filepath.Base(*pfile),
		safe.Headers.ProgramSave))
	leftpar.Height = 2
	leftpar.HasBorder = false

	recordlist := termui.NewList()
	recordlist.Height = termui.TermHeight() - 9
	recordlist.Items = getRecordList(safe)
	recordlist.Border.Label = fmt.Sprintf("Records (%d)", len(safe.Records))

	recorddetail := termui.NewPar("")
	recorddetail.Height = recordlist.Height
	recorddetail.Border.Label = "Record Information"

	inputbox := termui.NewPar("")
	inputbox.Height = 3
	inputbox.Border.Label = "Input Box ([Enter] to save, [Esc] to cancel)"

	commandinfo := termui.NewPar(strings.Join([]string{
		"Select record by typing the index number",
		"Edit field by typing field marker",
	}, "\n"))
	commandinfo.Height = 4
	commandinfo.Border.Label = "Help"

	termui.Body.AddRows(
		termui.NewRow(
			termui.NewCol(6, 0, leftpar),
			termui.NewCol(6, 0, rightpar),
		),
		termui.NewRow(
			termui.NewCol(6, 0, recordlist),
			termui.NewCol(6, 0, recorddetail),
		),
		termui.NewRow(
			termui.NewCol(12, 0, inputbox),
		),
		termui.NewRow(
			termui.NewCol(12, 0, commandinfo),
		),
	)

	termui.Body.Align()
	termui.Render(termui.Body)

	evt := termui.EventCh()

	inputMode := false
	valBuffer := bytes.Buffer{}
	numBuffer := bytes.Buffer{}
	var selRecord *pwsafe.Record
	var selField *string
	var inputPrompt string
	var startIndex int
Main:
	for {
		select {
		case e := <-evt:
			if !inputMode && e.Type == termui.EventKey {
				switch e.Ch {
				case 'q':
					break Main
				case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
					numBuffer.WriteRune(e.Ch)
				case '#':
					selIndex, _ := strconv.ParseInt(numBuffer.String(), 10, 64)
					selRecord = &safe.Records[selIndex]
					selField = nil
					numBuffer.Reset()
				case 'j':
					startIndex++
					rlist := getRecordList(safe)
					recordlist.Items = rlist[startIndex:]
				case 'k':
					if startIndex > 1 {
						startIndex--
						rlist := getRecordList(safe)
						recordlist.Items = rlist[startIndex:]
					}
				case 'a':
					selIndex := len(safe.Records)
					safe.Records = append(safe.Records, pwsafe.Record{})
					selRecord = &safe.Records[selIndex]
					selRecord.UUID = uuid.NewV1()
					selRecord.CreationTime = time.Now()
					selField = nil
					rlist := getRecordList(safe)
					recordlist.Items = rlist[startIndex:]
					recordlist.Border.Label = fmt.Sprintf("Records (%d)", len(safe.Records))
				case 'g':
					selField = &selRecord.Group
					inputPrompt = "Group: "
					inputMode = true
					valBuffer.WriteString(selRecord.Group)
					inputbox.Text = inputPrompt + valBuffer.String()
				case 't':
					selField = &selRecord.Title
					inputPrompt = "Title: "
					inputMode = true
					valBuffer.WriteString(selRecord.Title)
					inputbox.Text = inputPrompt + valBuffer.String()
				case 'u':
					selField = &selRecord.Username
					inputPrompt = "Username: "
					inputMode = true
					valBuffer.WriteString(selRecord.Username)
					inputbox.Text = inputPrompt + valBuffer.String()
				case 'p':
					selField = &selRecord.Password
					inputPrompt = "Password: "
					inputMode = true
					valBuffer.WriteString(selRecord.Password)
					inputbox.Text = inputPrompt + valBuffer.String()
				case 'r':
					selField = &selRecord.Url
					inputPrompt = "Url: "
					inputMode = true
					valBuffer.WriteString(selRecord.Url)
					inputbox.Text = inputPrompt + valBuffer.String()
				case 'n':
					selField = &selRecord.Notes
					inputPrompt = "Notes: "
					inputMode = true
					valBuffer.WriteString(selRecord.Notes)
					inputbox.Text = inputPrompt + valBuffer.String()
				case 'e':
					selField = &selRecord.Email
					inputPrompt = "Email: "
					inputMode = true
					valBuffer.WriteString(selRecord.Email)
					inputbox.Text = inputPrompt + valBuffer.String()
				}
			} else if inputMode && e.Type == termui.EventKey {
				if e.Key == termui.KeyEnter {
					if selField != nil {
						*selField = valBuffer.String()
					}
					valBuffer.Reset()
					inputMode = false
					inputbox.Text = ""
					rlist := getRecordList(safe)
					recordlist.Items = rlist[startIndex:]
				} else if e.Key == termui.KeyEsc {
					valBuffer.Reset()
					inputMode = false
					inputbox.Text = ""
				} else if e.Key == termui.KeySpace {
					valBuffer.WriteRune(' ')
				} else if e.Key == termui.KeyBackspace || e.Ch == '' {
					s := valBuffer.String()
					valBuffer = bytes.Buffer{}
					if len(s) > 0 {
						s = s[0 : len(s)-1]
					}
					valBuffer.WriteString(s)
					inputbox.Text = inputPrompt + valBuffer.String()
				} else {
					valBuffer.WriteRune(e.Ch)
					inputbox.Text = inputPrompt + valBuffer.String()
				}
			}
			if e.Type == termui.EventResize {
				termui.Body.Width = termui.TermWidth()
				termui.Body.Align()
			}
			if selRecord != nil {
				recorddetail.Text = getRecordDetail(*selRecord)
			}
			termui.Render(termui.Body)
		}
	}

	oerr := pwsafe.OutputFile(*pfile, string(pw), *safe)
	if oerr != nil {
		log.Fatalln(oerr)
	}

}

func getRecordDetail(record pwsafe.Record) string {
	return strings.Join([]string{
		fmt.Sprintf("    UUID: %v", record.UUID),
		fmt.Sprintf("[g] Group: %s", record.Group),
		fmt.Sprintf("[t] Title: %s", record.Title),
		fmt.Sprintf("[u] Username: %s", record.Username),
		fmt.Sprintf("[p] Password: %s", record.Password),
		fmt.Sprintf("[n] Notes: %s", record.Notes),
		fmt.Sprintf("[r] Url: %s", record.Url),
		fmt.Sprintf("[e] Email: %s", record.Email),
		fmt.Sprintf("    Create Time: %s", record.CreationTime.Format("2006-01-02 15:04:05")),
	}, "\n")
}

func getRecordList(safe *pwsafe.Safe) []string {
	rlist := make([]string, 0)
	for idx, record := range safe.Records {
		rlist = append(rlist, fmt.Sprintf("[%02d#] %s/%s", idx, record.Group, record.Title))
	}
	rlist = append(rlist, "[a] Add Record")
	return rlist
}
