package signer

import (
	"crypto"
	"crypto/x509"
	"dsig/internal/signedxml"
	"encoding/base64"

	"github.com/beevik/etree"
)

// Cert represents interface of Certificate provider
type Cert interface {
	GetCertificate() (x509.Certificate, error)
}

// Signer represents an interface of signer
type Signer struct {
	Sig crypto.Signer
	Cer Cert
}

// Sign signs given xml
func (s *Signer) Sign(doc *etree.Document) (*etree.Document, error) {

	// Fill in certificate and subject of signature element
	cert, err := s.Cer.GetCertificate()
	if err != nil {
		return nil, err
	}

	x509Cert := doc.FindElement("//X509Certificate")
	if nil != x509Cert {
		x509Cert.SetText(base64.StdEncoding.EncodeToString(cert.Raw))
	}
	sub := doc.FindElement("//X509SubjectName")
	if nil != sub {
		sub.SetText(cert.Subject.String())
	}

	// sign
	str, err := doc.WriteToString()
	if err != nil {
		return nil, err
	}
	signer, err := signedxml.NewSigner(str, &s.Sig)
	if err != nil {
		return nil, err
	}
	signer.SetReferenceIDAttribute("Id")
	str, err = signer.Sign()
	if err != nil {
		return nil, err
	}
	doc = etree.NewDocument()
	err = doc.ReadFromString(str)
	if err != nil {
		return nil, err
	}
	return doc, nil
}
