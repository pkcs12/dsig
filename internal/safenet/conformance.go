package safenet

import (
	"crypto"
	"io"
)

// Public returns Public key
func (t SafeNet) Public() crypto.PublicKey {
	cert, err := t.GetCertificate()
	if err != nil {
		return nil
	}
	return cert.PublicKey.(crypto.PublicKey)
}

// Sign signs digest with SHA256 RSA v1.5
func (t SafeNet) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return t.SignPKCS1v15(digest)
}