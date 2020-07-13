package cu

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
)

const (
	CurveP224 = "P224"
	CurveP256 = "P256"
	CurveP384 = "P384"
	CurveP521 = "P521"
)

var ErrUnsupportedEllipticCurve = errors.New("unsupported elliptic curve")

// curveInfo conainst elliptic curve info
type curveInfo struct {
	// ASN.1 marshaled OID
	oid []byte

	// Curve definition in Go form
	curve elliptic.Curve
}

var wellKnownCurves = map[string]curveInfo{
	CurveP224: {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 33}),
		elliptic.P224(),
	},
	CurveP256: {
		mustMarshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}),
		elliptic.P256(),
	},
	CurveP384: {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}),
		elliptic.P384(),
	},
	CurveP521: {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}),
		elliptic.P521(),
	},
}

// WellKnownCurve returns if the curve specified name is in the well known curve list
func WellKnownCurve(name string) bool {
	_, ok := wellKnownCurves[name]
	return ok
}

func exportECDSAPublicKey(ctx *Context, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	attributes, err := ctx.handle.GetAttributeValue(ctx.session, pubHandle, template)
	if err != nil {
		return nil, err
	}

	curve, err := unmarshalEcParams(attributes[0].Value)
	if err != nil {
		return nil, err
	}

	x, y, err := unmarshalEcPoint(attributes[1].Value, curve)
	if err != nil {
		return nil, err
	}

	pub := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return &pub, nil
}

func unmarshalEcParams(b []byte) (elliptic.Curve, error) {
	for _, ci := range wellKnownCurves {
		if bytes.Equal(b, ci.oid) && ci.curve != nil {
			return ci.curve, nil
		}
	}
	return nil, ErrUnsupportedEllipticCurve
}

func unmarshalEcPoint(b []byte, c elliptic.Curve) (*big.Int, *big.Int, error) {
	var pointBytes []byte
	extra, err := asn1.Unmarshal(b, &pointBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("elliptic curve point is invalid ASN.1: %w", err)
	}

	if len(extra) > 0 {
		return nil, nil, fmt.Errorf("unexpected data found when parsing elliptic curve point: %v", extra)
	}

	x, y := elliptic.Unmarshal(c, pointBytes)
	if x == nil || y == nil {
		return nil, nil, fmt.Errorf("failed to parse elliptic curve point")
	}
	return x, y, nil
}
