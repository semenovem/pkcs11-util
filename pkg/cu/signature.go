package cu

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

// DsaSignature contains DSA signature
type DsaSignature struct {
	R, S *big.Int
}

// Populate a DsaSignature from a raw byte sequence
func (self *DsaSignature) unmarshalBytes(in []byte) error {
	if len(in) == 0 || len(in)%2 != 0 {
		return fmt.Errorf("DSA signature length is invalid from token: %v", in)
	}
	n := len(in) / 2
	self.R, self.S = new(big.Int), new(big.Int)
	self.R.SetBytes(in[:n])
	self.S.SetBytes(in[n:])
	return nil
}

// Populate a DsaSignature from DER encoding
func (self *DsaSignature) unmarshalDER(in []byte) error {
	if rest, err := asn1.Unmarshal(in, self); err != nil {
		return fmt.Errorf("DSA signature contains invalid ASN.1 data: %w", err)
	} else if len(rest) > 0 {
		return fmt.Errorf("unexpected data found after DSA signature: %v", rest)
	}
	return nil
}

// Return the DER encoding of a DsaSignature
func (self *DsaSignature) marshalDER() ([]byte, error) {
	return asn1.Marshal(*self)
}
