package cu

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/miekg/pkcs11"
)

// Signer is an interface for an opaque private key that can be used for signing operations
type Signer interface {
	crypto.Signer
}

// privateKey contains generic private key
type privateKey struct {
	ctx       *Context
	prvHandle pkcs11.ObjectHandle
	pubHandle pkcs11.ObjectHandle
	publicKey crypto.PublicKey
}

// ecdsaPrivateKey contains ECDSA private key
type ecdsaPrivateKey struct {
	*privateKey
}

// NewSigner returns a new Signer instance, which algorithm is defined by the key type
func NewSigner(ctx *Context, prvLabel, pubLabel string) (Signer, error) {
	prvHandle, err := findObject(ctx,
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, prvLabel),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	)
	if err != nil {
		return nil, err
	}
	pubHandle, err := findObject(ctx,
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, pubLabel),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	)
	if err != nil {
		return nil, err
	}

	publicTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	}
	publicAttributes, err := ctx.handle.GetAttributeValue(ctx.session, pubHandle, publicTemplate)
	if err != nil {
		return nil, err
	}
	publicKeyType := binary.LittleEndian.Uint32(publicAttributes[0].Value)

	privateTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	}
	privateAttributes, err := ctx.handle.GetAttributeValue(ctx.session, prvHandle, privateTemplate)
	if err != nil {
		return nil, err
	}
	privateKeyType := binary.LittleEndian.Uint32(privateAttributes[0].Value)

	if publicKeyType != privateKeyType {
		return nil, fmt.Errorf("Provided keys are not of the same type")
	}

	if publicKeyType == pkcs11.CKK_ECDSA {
		publicKey, err := exportECDSAPublicKey(ctx, pubHandle)
		if err != nil {
			return nil, err
		}
		return &ecdsaPrivateKey{
			privateKey: &privateKey{
				ctx:       ctx,
				prvHandle: prvHandle,
				pubHandle: pubHandle,
				publicKey: publicKey,
			},
		}, nil
	}
	return nil, fmt.Errorf("Unsupported key type")
}

// Public return the Signer's public key
func (self *privateKey) Public() crypto.PublicKey {
	return self.publicKey
}

// Sign signs the digest
func (self *privateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	handle := self.ctx.handle
	session := self.ctx.session

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}
	if err := handle.SignInit(session, mechanism, self.prvHandle); err != nil {
		return nil, err
	}

	sigBytes, err := handle.Sign(session, digest)
	if err != nil {
		return nil, err
	}

	sig := DsaSignature{}
	if err = sig.unmarshalBytes(sigBytes); err != nil {
		return nil, err
	}
	return sig.marshalDER()
}
