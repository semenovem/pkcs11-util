package cu

import (
  "crypto/x509"
  "errors"
)

var ErrUnsupportedSignatureAlgorithm = errors.New("unsupported signature algorithm")

var wellKnownSignatureAlgoruthms = map[string]x509.SignatureAlgorithm{
  "ECDSAWithSHA1":   x509.ECDSAWithSHA1,
  "ECDSAWithSHA256": x509.ECDSAWithSHA256,
  "ECDSAWithSHA384": x509.ECDSAWithSHA384,
  "ECDSAWithSHA512": x509.ECDSAWithSHA512,
  "MD5WithRSA":      x509.MD5WithRSA,
  "SHA1WithRSA":     x509.SHA1WithRSA,
  "SHA256WithRSA":   x509.SHA256WithRSA,
  "SHA384WithRSA":   x509.SHA384WithRSA,
  "SHA512WithRSA":   x509.SHA512WithRSA,
}

// GetSignatureAlgorithmName returns the name of the algorithm
func GetSignatureAlgorithmName(algorithm x509.SignatureAlgorithm) (string, error) {
  for k, v := range wellKnownSignatureAlgoruthms {
    if algorithm == v {
      return k, nil
    }
  }
  return "", ErrUnsupportedSignatureAlgorithm
}

// GetSignatureAlgorithmByName returns x509.SignatureAlgorithm by the name
func GetSignatureAlgorithmByName(name string) (x509.SignatureAlgorithm, error) {
  if a, ok := wellKnownSignatureAlgoruthms[name]; ok {
    return a, nil
  }
  return x509.UnknownSignatureAlgorithm, ErrUnsupportedSignatureAlgorithm
}

// GetSupportedSignatureAlgorithmNames returns the list of supported x509.SignatureAlgorithm names
func GetSupportedSignatureAlgorithmNames() []string {
  res := make([]string, 0, len(wellKnownSignatureAlgoruthms))
  for a, _ := range wellKnownSignatureAlgoruthms {
    res = append(res, a)
  }
  return res
}

// GetSupportedSignatureAlgorithms returns the list of supported x509.SignatureAlgorithm
func GetSupportedSignatureAlgorithms() []x509.SignatureAlgorithm {
  res := make([]x509.SignatureAlgorithm, 0, len(wellKnownSignatureAlgoruthms))
  for _, v := range wellKnownSignatureAlgoruthms {
    res = append(res, v)
  }
  return res
}
