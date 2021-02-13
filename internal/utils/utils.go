package utils

import (
	"errors"

	"github.com/beevik/etree"
)

// Envelope wraps up given RegisterInvoiceRequest into standard SOAP Envelope
func Envelope(req *etree.Document) (*etree.Document, error) {
	doc := etree.NewDocument()

	root := doc.CreateElement("s:Envelope")
	root.CreateAttr("xmlns:s", "http://schemas.xmlsoap.org/soap/envelope/")
	body := root.CreateElement("s:Body")
	body.CreateAttr("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
	body.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")

	if len(req.Child) != 1 {
		return nil, errors.New("Invalid XML document")
	}
	body.AddChild(req.Child[0])

	doc.IndentTabs()
	doc.Root().SetTail("")

	return doc, nil
}
