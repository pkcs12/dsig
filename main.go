package main

import (
	"dsig/internal/safenet"
	"dsig/internal/signer"
	"dsig/internal/utils"
	"flag"
	"fmt"
	"os"

	"github.com/beevik/etree"
)

func main() {

	softCode := flag.String("soft", "", "Softcode registered in efi portal (Required)")
	businUnitCode := flag.String("busin", "", "BusinUnitCode registered in efi portal (Required)")
	pin := flag.String("pin", "", "(Required) Pin is used for unlocking SafeNet token.")
	lib := flag.String("lib", "", "(Optional) Path to the SafeNet library, eg \"C:\\Windows\\System32\\eTPKCS11.dll\"")
	inFile := flag.String("in", "", "Path to file with Typless extracted data (Required)")
	outFile := flag.String("out", "", "Path to file where to save extracted invoice fields (Required)")
	flag.Parse()
	if *softCode == "" || *businUnitCode == "" || *inFile == "" || *outFile == "" || *pin == "" {
		flag.CommandLine.Usage()
		os.Exit(1)
	}

	dSigToken := &safenet.SafeNet{}
	if err := dSigToken.Initialize(
		&safenet.Config{
			LibPath:   *lib,
			UnlockPin: *pin,
		},
	); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	defer dSigToken.Finalize()

	xmlDoc := etree.NewDocument()
	if err := xmlDoc.ReadFromFile(*inFile); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	xmlDoc, err := utils.Envelope(xmlDoc)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	signer := &signer.Signer{
		Sig:            dSigToken,
		Cer:            dSigToken,
		PKCS1c15Signer: dSigToken,
		SoftCode:       *softCode,
		BusinUnitCode:  *businUnitCode,
		TCRCode:        "",
	}
	signedXML, err := signer.Sign(xmlDoc)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// signedXML.IndentTabs()
	// // removes extra \n at the ned of the docuemnt
	// signedXML.Root().SetTail("")

	if err = signedXML.WriteToFile(*outFile); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
