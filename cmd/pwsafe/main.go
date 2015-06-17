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
	flag.Parse()

	fmt.Printf("Password: ")
	pw := gopass.GetPasswd()

	safe, err := pwsafe.ParseFile(*inputfile, string(pw))
	if err != nil {
		log.Fatalln(err)
	}

	pretty.Println(safe)
}
