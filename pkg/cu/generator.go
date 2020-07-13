package cu

import (
	"errors"

	"github.com/miekg/pkcs11"
)

var (
	ErrUnknownKeyPairTemplate = errors.New("Unknown key pair template")
)

// ECDSAKeyPairTemplate defines ECDSA key pair
type ECDSAKeyPairTemplate struct {
	Curve        string
	PublicLabel  string
	PrivateLabel string
	Token        bool
	Sign         bool
	Verify       bool
	Encrypt      bool
	Decrypt      bool
	Sensitive    bool
	Extractable  bool
	Modifiable   bool
}

// Generator generates different crypto objects
type Generator interface {
	// GenerateKeyPair generates the key pair defined by the template
	GenerateKeyPair(template interface{}) (pub pkcs11.ObjectHandle, prv pkcs11.ObjectHandle, err error)
}

// generator imlements Generator interface
type generator struct {
	ctx *Context
}

// NewGenerator creates a new instance of Generator
func NewGenerator(ctx *Context) Generator {
	return &generator{
		ctx: ctx,
	}
}

// GenerateKeyPair generates key pair depending on template type
// Supported algorithms: ECDSA
func (self *generator) GenerateKeyPair(template interface{}) (pub pkcs11.ObjectHandle, prv pkcs11.ObjectHandle, err error) {
	if t, ok := template.(ECDSAKeyPairTemplate); ok {
		return generateECDSAKeyPair(self.ctx, t)
	}
	err = ErrUnknownKeyPairTemplate
	return
}

// generateECDSAKeyPair generated ECDSA key pair
var generateECDSAKeyPair = func(ctx *Context, template ECDSAKeyPairTemplate) (pub pkcs11.ObjectHandle, prv pkcs11.ObjectHandle, err error) {
	curve, ok := wellKnownCurves[template.Curve]
	if !ok {
		err = ErrUnsupportedEllipticCurve
		return
	}

	public := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, curve.oid),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, template.Encrypt),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, template.PublicLabel),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, template.Modifiable),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, template.Token),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, template.Verify),
	}

	private := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, template.Decrypt),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, template.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, template.PrivateLabel),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, template.Modifiable),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, template.Sensitive),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, template.Sign),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, template.Token),
	}

	pub, prv, err = ctx.handle.GenerateKeyPair(ctx.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_KEY_PAIR_GEN, nil)},
		public, private)
	return
}
