package cu

import (
  "C"
  "crypto"
  "crypto/rsa"
  "errors"
  "io"
  "math/big"
  "unsafe"

  "github.com/miekg/pkcs11"
)

var errMalformedRSAPublicKey = errors.New("malformed RSA public key")
var errUnsupportedRSAOptions = errors.New("unsupported RSA option value")

var pkcs1Prefix = map[crypto.Hash][]byte{
  crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
  crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
  crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
  crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
  crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

type rsaPrivateKey struct {
  *privateKey
}

// Sign signs the digest
func (k *rsaPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
  switch opts.(type) {
  case *rsa.PSSOptions:
    signature, err = signPSS(k, digest, opts.(*rsa.PSSOptions))
  default:
    signature, err = signPKCS1v15(k, digest, opts.HashFunc())
  }
  return
}

func signPSS(k *rsaPrivateKey, digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
  handle := k.ctx.handle
  session := k.ctx.session

  var hMech, mgf, hLen, sLen uint
  var err error
  if hMech, mgf, hLen, err = hashToPKCS11(opts.Hash); err != nil {
    return nil, err
  }
  switch opts.SaltLength {
  case rsa.PSSSaltLengthAuto:
    return nil, errUnsupportedRSAOptions
  case rsa.PSSSaltLengthEqualsHash:
    sLen = hLen
  default:
    sLen = uint(opts.SaltLength)
  }

  parameters := concat(ulongToBytes(hMech), ulongToBytes(mgf), ulongToBytes(sLen))
  mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, parameters)}

  if err := handle.SignInit(session, mechanism, k.prvHandle); err != nil {
    return nil, err
  }
  return handle.Sign(session, digest)
}

func ulongToBytes(n uint) []byte {
  return C.GoBytes(unsafe.Pointer(&n), C.sizeof_ulong)
}

func concat(slices ...[]byte) []byte {
  n := 0
  for _, slice := range slices {
    n += len(slice)
  }
  r := make([]byte, n)
  n = 0
  for _, slice := range slices {
    n += copy(r[n:], slice)
  }
  return r
}

func hashToPKCS11(hashFunction crypto.Hash) (hashAlg uint, mgfAlg uint, hashLen uint, err error) {
  switch hashFunction {
  case crypto.SHA1:
    return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, 20, nil
  case crypto.SHA224:
    return pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, 28, nil
  case crypto.SHA256:
    return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32, nil
  case crypto.SHA384:
    return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, 48, nil
  case crypto.SHA512:
    return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, 64, nil
  default:
    return 0, 0, 0, errUnsupportedRSAOptions
  }
}

func signPKCS1v15(k *rsaPrivateKey, digest []byte, hash crypto.Hash) (signature []byte, err error) {
  oid := pkcs1Prefix[hash]
  T := make([]byte, len(oid)+len(digest))
  copy(T[0:len(oid)], oid)
  copy(T[len(oid):], digest)

  handle := k.ctx.handle
  session := k.ctx.session

  mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
  err = handle.SignInit(session, mechanism, k.prvHandle)
  if err == nil {
    signature, err = handle.Sign(session, T)
  }
  return
}

func exportRSAPublicKey(ctx *Context, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
  template := []*pkcs11.Attribute{
    pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
    pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
  }
  attributes, err := ctx.handle.GetAttributeValue(ctx.session, pubHandle, template)
  if err != nil {
    return nil, err
  }

  var modulus = new(big.Int)
  modulus.SetBytes(attributes[0].Value)

  var bigExponent = new(big.Int)
  bigExponent.SetBytes(attributes[1].Value)
  if bigExponent.BitLen() > 32 {
    return nil, errMalformedRSAPublicKey
  }
  if bigExponent.Sign() < 1 {
    return nil, errMalformedRSAPublicKey
  }
  exponent := int(bigExponent.Uint64())

  pub := rsa.PublicKey{
    N: modulus,
    E: exponent,
  }
  if pub.E < 2 {
    return nil, errMalformedRSAPublicKey
  }
  return &pub, nil
}
