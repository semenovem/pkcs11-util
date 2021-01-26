package cu

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"

	"github.com/miekg/pkcs11"
)

// ImportCertificate imports the certificate cert.
func ImportCertificate(ctx *Context, label string, cert *x509.Certificate) (res pkcs11.ObjectHandle, err error) {
	serial, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, cert.RawIssuer),
		pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, serial),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, cert.Raw),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(label)),
	}

	res, err = ctx.handle.CreateObject(ctx.session, template)
	return
}

// FindObjects returns PKCS11 Object handles specified by the template
func FindObjects(ctx *Context, template ...*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := ctx.handle.FindObjectsInit(ctx.session, template); err != nil {
		return nil, err
	}
	defer func() {
		ctx.handle.FindObjectsFinal(ctx.session)
	}()

	var res []pkcs11.ObjectHandle

	for {
		objs, _, err := ctx.handle.FindObjects(ctx.session, 5)
		if err != nil {
			return nil, err
		}
		if len(objs) == 0 {
			return res, nil
		}
		res = append(res, objs...)
	}
}

// GetAttributes returns the object's attributes specified by the template
func GetAttributes(ctx *Context, object pkcs11.ObjectHandle, template ...*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	return ctx.handle.GetAttributeValue(ctx.session, object, template)
}

// DestroyObject destroys the object
func DestroyObject(ctx *Context, object pkcs11.ObjectHandle) error {
	return ctx.handle.DestroyObject(ctx.session, object)
}

// AttributeToString returns the attribute's string representation
func AttributeToString(attribute *pkcs11.Attribute) string {
	switch attribute.Type {
	case pkcs11.CKA_CLASS:
		v := binary.LittleEndian.Uint32(attribute.Value)
		switch uint(v) {
		case pkcs11.CKO_DATA:
			return "CKO_DATA"
		case pkcs11.CKO_CERTIFICATE:
			return "CKO_CERTIFICATE"
		case pkcs11.CKO_PUBLIC_KEY:
			return "CKO_PUBLIC_KEY"
		case pkcs11.CKO_PRIVATE_KEY:
			return "CKO_PRIVATE_KEY"
		case pkcs11.CKO_SECRET_KEY:
			return "CKO_SECRET_KEY"
		case pkcs11.CKO_HW_FEATURE:
			return "CKO_HW_FEATURE"
		case pkcs11.CKO_DOMAIN_PARAMETERS:
			return "CKO_DOMAIN_PARAMETERS"
		case pkcs11.CKO_MECHANISM:
			return "CKO_MECHANISM"
		case pkcs11.CKO_OTP_KEY:
			return "CKO_OTP_KEY"
		case pkcs11.CKO_VENDOR_DEFINED:
			return "CKO_VENDOR_DEFINED"
		default:
			return "UNKNOWN"
		}
	case pkcs11.CKA_LABEL:
		return string(attribute.Value)
	default:
		panic(fmt.Errorf("Not implemented for type: %v", attribute.Type))
	}
}

func findObject(ctx *Context, tmpl ...*pkcs11.Attribute) (handle pkcs11.ObjectHandle, err error) {
	err = ctx.handle.FindObjectsInit(ctx.session, tmpl)
	if err != nil {
		return
	}
	defer func() {
		err = ctx.handle.FindObjectsFinal(ctx.session)
	}()

	objs, _, err := ctx.handle.FindObjects(ctx.session, 1)
	if err != nil {
		return
	}
	if len(objs) == 0 {
		err = fmt.Errorf("Object not found: %v", tmpl)
		return
	}
	if len(objs) > 1 {
		err = fmt.Errorf("Multiple objects found : %v", tmpl)
		return
	}

	handle = objs[0]
	return
}

// ASN.1 marshal some value and panic on error
func mustMarshal(val interface{}) []byte {
	b, err := asn1.Marshal(val)
	if err != nil {
		panic(err)
	}
	return b
}
