package main

import (
	"bufio"
	"dsig/internal/safenet"
	"dsig/internal/signer"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/beevik/etree"
)

func main() {

	pinPtr := flag.String("pin", "", "(Required) Pin is used for unlocking SafeNet token.")
	libPtr := flag.String("lib", "", "(Optional) Path to the SafeNet library, eg \"C:\\Windows\\System32\\eTPKCS11.dll\"")
	var xmlPtr *string

	info, _ := os.Stdin.Stat()
	if (info.Mode() & os.ModeCharDevice) == os.ModeCharDevice {
		xmlPtr = flag.String("xml", "", "(Required) XML document that needs to be signed")
		// fmt.Println("The command is intended to work with pipes.")
		// fmt.Println("Usage:")
		// fmt.Println("  cat yourfile.txt | searchr -pattern=<your_pattern>")
		// os.Exit(1)
	} else if info.Size() > 0 {
		reader := bufio.NewReader(os.Stdin)
		buf, err := ioutil.ReadAll(reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			os.Exit(1)
		}
		tmp := string(buf)
		xmlPtr = &tmp
	} else {
		xmlPtr = flag.String("xml", "", "(Required) XML document that needs to be signed")
	}

	flag.Parse()

	if !flag.Parsed() {
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *pinPtr == "" || *xmlPtr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	dSigToken := &safenet.SafeNet{}
	err := dSigToken.Initialize(
		&safenet.Config{
			LibPath:   *libPtr,
			UnlockPin: *pinPtr,
		},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
	defer dSigToken.Finalize()

	xmlDoc := etree.NewDocument()
	err = xmlDoc.ReadFromString(*xmlPtr)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	signer := &signer.Signer{
		Sig: dSigToken,
		Cer: dSigToken,
	}
	signedXML, err := signer.Sign(xmlDoc)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
	signedXMLStr, err := signedXML.WriteToString()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, signedXMLStr)
	os.Exit(0)
}
