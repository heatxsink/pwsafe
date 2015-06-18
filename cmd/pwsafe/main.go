package main

import (
	"flag"
	"fmt"
	"log"

	"pwsafe"

	"github.com/howeyc/gopass"
	"github.com/kr/pretty"
)

func main() {
	inputfile := flag.String("f", "", "input file")
	outputfile := flag.String("o", "", "output file")
	flag.Parse()

	fmt.Printf("Password: ")
	pw := gopass.GetPasswd()

	safe, err := pwsafe.ParseFile(*inputfile, string(pw))
	if err != nil {
		log.Fatalln(err)
	}

	pretty.Println(safe)

	fmt.Printf("New Password: ")
	newpw := gopass.GetPasswd()

	oerr := pwsafe.OutputFile(*outputfile, string(newpw), *safe)
	if oerr != nil {
		log.Fatalln(oerr)
	}

	pretty.Println(safe)
}
