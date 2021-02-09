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

const (
	// BusinUnitCode represent registered Business unit code
	BusinUnitCode = ""
	// SoftCode represents software code
	SoftCode = "ge788jm169"
	TCRCode  = ""
)

func main() {

	pinPtr := flag.String("pin", "", "(Required) Pin is used for unlocking SafeNet token.")
	// businUnitPtr := flag.String("busin_unit", "", "(Required) Business unit code.")
	libPtr := flag.String("lib", "", "(Optional) Path to the SafeNet library, eg \"C:\\Windows\\System32\\eTPKCS11.dll\"")
	var xmlPtr *string

	info, _ := os.Stdin.Stat()
	if (info.Mode() & os.ModeCharDevice) == os.ModeCharDevice {
		xmlPtr := flag.String("xml", "", "(Required) Pin is used for unlocking SafeNet token.")
		buf, err := ioutil.ReadFile(*xmlPtr)
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			os.Exit(1)
		}
		tmp := string(buf)
		xmlPtr = &tmp
		// fmt.Println("dsig command is intended to work with pipes.")
		// fmt.Println("Usage:")
		// fmt.Println("\tcat yourfile.xml | dsig -pin=<your_pin>")
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
		flag.Parse()
	} else {
		xmlPtr = flag.String("xml", "", "(Required) Pin is used for unlocking SafeNet token.")
		flag.Parse()
		buf, err := ioutil.ReadFile(*xmlPtr)
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			os.Exit(1)
		}
		tmp := string(buf)
		xmlPtr = &tmp
	}
	// flag.Parse()

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
		fmt.Fprintf(os.Stderr, "%v\n", err.Error())
		os.Exit(1)
	}
	defer dSigToken.Finalize()

	xmlDoc := etree.NewDocument()
	err = xmlDoc.ReadFromString(*xmlPtr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err.Error())
		os.Exit(1)
	}
	xmlDoc, err = envelope(xmlDoc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err.Error())
		os.Exit(1)
	}

	signer := &signer.Signer{
		Sig:            dSigToken,
		Cer:            dSigToken,
		PKCS1c15Signer: dSigToken,
		SoftCode:       SoftCode,
		BusinUnitCode:  BusinUnitCode,
		TCRCode:        TCRCode,
	}
	signedXML, err := signer.Sign(xmlDoc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err.Error())
		os.Exit(1)
	}
	signedXMLStr, err := signedXML.WriteToString()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err.Error())
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, signedXMLStr)
	os.Exit(0)
}

func envelope(req *etree.Document) (*etree.Document, error) {
	doc := etree.NewDocument()
	doc.IndentTabs()

	root := doc.CreateElement("s:Envelope")
	root.CreateAttr("xmlns:s", "http://schemas.xmlsoap.org/soap/envelope/")
	body := root.CreateElement("s:Body")
	body.CreateAttr("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
	body.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")

	tmp := req.FindElement("RegisterInvoiceRequest")
	body.AddChild(tmp)

	return doc, nil
}

// func setIIC(invoice *efi.Invoice, BusinUnitCode string) error {

// 	TCRCode := ""
// 	IICString := fmt.Sprintf(
// 		"%s|%s|%s|%s|%s|%s|%s",
// 		invoice.Seller.IDNum,
// 		time.Time(invoice.IssueDateTime).Format(time.RFC3339),
// 		fmt.Sprintf("%d", invoice.InvOrdNum),
// 		BusinUnitCode,
// 		TCRCode,
// 		"ge788jm169",
// 		fmt.Sprintf("%.02f", invoice.TotPrice),
// 	)
// 	hasher := crypto.SHA256.New()

// 	_, err := hasher.Write([]byte(IICString))
// 	if err != nil {
// 		rec.Error = err.Error()
// 		return err
// 	}
// 	hashedIIC := hasher.Sum(nil)
// 	IICSignature, err := i.Tkn.SignPKCS1v15(hashedIIC)
// 	if err != nil {
// 		rec.Error = err.Error()
// 		return err
// 	}
// 	md5Hasher := crypto.MD5.New()
// 	_, err = md5Hasher.Write([]byte(IICSignature))
// 	if err != nil {
// 		rec.Error = err.Error()
// 		return err
// 	}
// 	IIC := md5Hasher.Sum(nil)

// 	inv.IIC = fmt.Sprintf("%x", IIC)
// 	inv.IICSignature = fmt.Sprintf("%x", IICSignature)

// 	return nil
// }
