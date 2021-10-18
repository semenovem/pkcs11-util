package command

import (
  "crypto/x509"
  "errors"
  "flag"
  "fmt"
  "net"
  "regexp"
  "strconv"
  "strings"

  "vtb.ru/pkcs11-util/pkg/cu"
)

// Supported commands
const (
  CertificateRequest = "certificateRequest"
  Destroy            = "destroy"
  Generate           = "generate"
  List               = "list"
  SetPin             = "setpin"
  Slots              = "slots"
  Version            = "version"
  ImportCertificate  = "importCertificate"
  ImportKey          = "importKey"
)

// Supported keys
const (
  KeyECDSA = "ecdsa"
  KeyRSA   = "rsa"
)

// Command defines the app command
type Command interface {
  // Name returns the command name
  Name() string
  // Parse parses command line arguments
  Parse([]string) error
  // Verify veriies parsed command line arguments
  Verify() error
  // Execute executes parsed and verified command
  Execute() error
}

type (
  // versionCmd prints out the app name and version
  versionCmd struct{}

  // slotsCmd contains Slots command arguments
  slotsCmd struct {
    *flag.FlagSet
    lib string
  }

  // absctactCmd contains common fields
  abstractCmd struct {
    *flag.FlagSet
    lib      string
    slot     string
    pin      string
    verified bool
    before   func() error
    after    func() error
    exec     func() error
    ctx      *cu.Context
  }

  // listCmd contains List command arguments
  listCmd struct {
    *abstractCmd
    // class contains PKCS11 object class
    class string
  }

  // destroyCmd contains Destroy command arguments
  destroyCmd struct {
    *abstractCmd
    // confirm defines operation confirmation status
    confirm bool
  }

  // setPinCmd contains SetPin command arguments
  setPinCmd struct {
    *abstractCmd
  }

  // generateCmd contains Generate command arguments
  generateCmd struct {
    *abstractCmd
    keyType      string
    keyBits      int
    curve        string
    publicLabel  string
    privateLabel string
    token        bool
    sign         bool
    verify       bool
    encrypt      bool
    decrypt      bool
    sensitive    bool
    extractable  bool
    modifiable   bool
  }

  // csrCmd contains Certiricate request command arguments
  csrCmd struct {
    *abstractCmd
    // out contains output file name
    out string
    // publicLabel identifies the public key to use in the request
    publicLabel string
    // privateLabel identifies the private key to use in the request
    privateLabel string
    // countryName 2-letter country code (US for the United States)
    countryName string
    // state the state in which the domain owner is incorporated
    state string
    // locality the city in which the domain owner is incorporated
    locality string
    // organizationName the legal entity that owns the domain
    organizationName string
    // organizationalUnitName the name of the department or group in your organization that deals with certificates
    organizationalUnitName string
    // commonName  the fully qualified domain name (FQDN)
    commonName string

    // signature contains signature algorithm
    signature string

    // signatureAlgorithm contains parsed signature algorith
    signatureAlgorithm x509.SignatureAlgorithm

    //  dns contains comma separated SAN DNS names
    dns string
    // dnsNames contains parsed SAN DNS names
    dnsNames []string
    // ip contains comma separated SAN IP addresses
    ip string
    // ipAddresses contains parsed SAN IP addresses
    ipAddresses []net.IP
  }

  // importCertificateCmd contains ImportCertificate command arguments
  importCertificateCmd struct {
    *abstractCmd
    in    string
    label string
  }

  // importKeyCmd contains ImportKey command arguments
  importKeyCmd struct {
    *abstractCmd
    in    string
    label string
  }
)

var (
  // appName contains the app name
  appName = "hsmc"
  // appVersion contains the app version (should be injected at build-time)
  appVersion = "UNKNOWN"
)

var (
  ErrCommonNameEmpty       = errors.New("Common name must not be empty")
  ErrEllipticCurveEmpty    = errors.New("Elliptic curve must not be empty")
  ErrFailedToDecodePEM     = errors.New("Failed to decode PEM")
  ErrIncorrectArgumentType = errors.New("Incorrect argument type")
  ErrIncorrectArguments    = errors.New("Incorrect argument(s)")
  ErrKeyTypeEmpty          = errors.New("Key type must not be empty")
  ErrLabelEmpty            = errors.New("Label must not be empty")
  ErrMustBeParsed          = errors.New("Must be parsed first")
  ErrMustBeVerifyed        = errors.New("Must be verified first")
  ErrNotEnoughArguments    = errors.New("Not enough arguments")
  ErrPathEmpty             = errors.New("Path must not be empty")
  ErrPinsDoesNotMatch      = errors.New("Pins does not match")
  ErrPrivateKeyLabelEmpty  = errors.New("Private key label must not be empty")
  ErrProcessorMustBeSet    = errors.New("Processor must be set")
  ErrPublicKeyLabelEmpty   = errors.New("Public key label must not be empty")
  ErrTooManyArguments      = errors.New("Too many arguments")
  ErrUnknownKeyType        = errors.New("Unknown key type")
  ErrWrongKeySize          = errors.New("Wrong key size")
)

var (
  // PKCS11 library path on host
  DefaultLib = ""
)

var commands = make(map[string]Command)

func init() {
  cmds := []Command{
    newCsrCmd(),
    newDestroyCmd(),
    newGenerateCmd(),
    newListCmd(),
    newSetPinCmd(),
    newSlotsCmd(),
    newVersionCmd(),
    newImportCertificateCmd(),
    newImportKeyCmd(),
  }
  for _, c := range cmds {
    commands[c.Name()] = c
  }
}

// Get returns the Command specified by the name
func Get(name string) Command {
  return commands[name]
}

func newVersionCmd() Command             { return &versionCmd{} }
func (*versionCmd) Name() string         { return Version }
func (*versionCmd) Parse([]string) error { return nil }
func (*versionCmd) Verify() error        { return nil }
func (*versionCmd) Execute() error       { fmt.Printf("%s %s\n", appName, appVersion); return nil }

func newSlotsCmd() Command {
  const LibOptionUsage = "PKCS11 library path"

  cmd := slotsCmd{
    FlagSet: flag.NewFlagSet(Slots, flag.ContinueOnError),
  }
  cmd.StringVar(&cmd.lib, "lib", DefaultLib, LibOptionUsage)
  cmd.StringVar(&cmd.lib, "l", DefaultLib, LibOptionUsage+" (shorthand)")
  return &cmd
}

func (*slotsCmd) Name() string { return Slots }

func (c *slotsCmd) Verify() error {
  if !c.Parsed() {
    return ErrMustBeParsed
  }
  if len(c.Args()) > 0 {
    return ErrTooManyArguments
  }
  return nil
}

func newAbstractCmd(name string) *abstractCmd {
  const LibOptionUsage = "PKCS11 library path"
  const SlotOptionUsage = "HSM slot"
  const PinOptionUsage = "HSM pin"

  cmd := abstractCmd{
    FlagSet: flag.NewFlagSet(name, flag.ContinueOnError),
  }

  cmd.StringVar(&cmd.lib, "lib", DefaultLib, LibOptionUsage)
  cmd.StringVar(&cmd.lib, "l", DefaultLib, LibOptionUsage+" (shorthand)")

  cmd.StringVar(&cmd.slot, "slot", "", SlotOptionUsage)
  cmd.StringVar(&cmd.slot, "s", "", SlotOptionUsage+" (shorthand)")

  cmd.StringVar(&cmd.pin, "pin", "", PinOptionUsage)
  cmd.StringVar(&cmd.pin, "p", "", PinOptionUsage+" (shorthand)")

  cmd.before = func() error { return cmd.beforeFunc() }
  cmd.after = func() error { return cmd.afterFunc() }
  return &cmd
}

func newListCmd() Command {
  cmd := listCmd{
    abstractCmd: newAbstractCmd(List),
  }
  cmd.StringVar(&cmd.class, "class", "", "object class: public|private")
  cmd.exec = cmd.execFunc
  return &cmd
}

func (c *listCmd) Verify() error {
  if !c.Parsed() {
    return ErrMustBeParsed
  }
  if len(c.Args()) > 0 {
    return ErrTooManyArguments
  }
  if c.class != "" && c.class != "public" && c.class != "private" {
    return ErrIncorrectArguments
  }
  c.verified = true
  return nil
}

func newDestroyCmd() Command {
  cmd := destroyCmd{
    abstractCmd: newAbstractCmd(Destroy),
  }
  cmd.BoolVar(&cmd.confirm, "confirm", true, "confirm operation")
  cmd.exec = cmd.execFunc
  return &cmd
}

func (c *destroyCmd) Verify() error {
  if !c.Parsed() {
    return ErrMustBeParsed
  }
  if len(c.Args()) < 1 {
    return ErrNotEnoughArguments
  }
  for _, a := range c.Args() {
    if _, err := strconv.Atoi(a); err != nil {
      return ErrIncorrectArgumentType
    }
  }
  c.verified = true
  return nil
}

func newSetPinCmd() Command {
  cmd := setPinCmd{
    abstractCmd: newAbstractCmd(SetPin),
  }
  cmd.exec = cmd.execFunc
  return &cmd
}

func (c *setPinCmd) Verify() error {
  if !c.Parsed() {
    return ErrMustBeParsed
  }
  if len(c.Args()) > 0 {
    return ErrTooManyArguments
  }
  c.verified = true
  return nil
}

func newGenerateCmd() Command {
  cmd := generateCmd{
    abstractCmd: newAbstractCmd(Generate),
  }
  cmd.StringVar(&cmd.keyType, "type", "", fmt.Sprintf("key type: %s|%s", KeyECDSA, KeyRSA))
  cmd.IntVar(&cmd.keyBits, "bits", 2048, "key size")
  cmd.StringVar(&cmd.curve, "curve", "", fmt.Sprintf("elliptic curve: %s|%s|%s|%s",
    cu.CurveP224, cu.CurveP256, cu.CurveP384, cu.CurveP521))
  cmd.StringVar(&cmd.publicLabel, "publicLabel", "", "public key label")
  cmd.StringVar(&cmd.privateLabel, "privateLabel", "", "private key label")
  cmd.BoolVar(&cmd.token, "token", true, "the token setting for both keys")
  cmd.BoolVar(&cmd.sign, "sign", false, "the sign setting for the private key")
  cmd.BoolVar(&cmd.verify, "verify", false, "the verify setting for the public key")
  cmd.BoolVar(&cmd.encrypt, "encrypt", false, "the encrypt setting for the public key")
  cmd.BoolVar(&cmd.decrypt, "decrypt", false, "the decrypt setting for the private key")
  cmd.BoolVar(&cmd.sensitive, "sensitive", true, "the sensitive setting for the private key")
  cmd.BoolVar(&cmd.extractable, "extractable", false, "the extractble setting for the private key")
  cmd.BoolVar(&cmd.modifiable, "modifiable", false, "the modifiable setting for both keys")
  cmd.exec = cmd.execFunc
  return &cmd
}

func (c *generateCmd) Verify() error {
  if !c.Parsed() {
    return ErrMustBeParsed
  }
  if len(c.Args()) > 0 {
    return ErrTooManyArguments
  }

  if c.keyType == "" {
    return ErrKeyTypeEmpty
  }
  switch c.keyType {
  case KeyECDSA:
    if c.curve == "" {
      return ErrEllipticCurveEmpty
    }
    if !cu.WellKnownCurve(c.curve) {
      return cu.ErrUnsupportedEllipticCurve
    }
  case KeyRSA:
    if c.keyBits != 2048 && c.keyBits != 4096 {
      return ErrWrongKeySize
    }
  default:
    return ErrUnknownKeyType
  }

  if c.publicLabel == "" {
    return ErrPublicKeyLabelEmpty
  }
  if c.privateLabel == "" {
    return ErrPrivateKeyLabelEmpty
  }

  c.verified = true
  return nil
}

func newCsrCmd() Command {
  const (
    DefaultCountryName        = "RU"
    DefaultLocality           = "Moscow"
    DefaultState              = "Moscow"
    DefaultOrganizationName   = "VTB Bank (PJSC)"
    DefaultSignatureAlgorithm = x509.ECDSAWithSHA512

    CountryNameOptionUsage            = "2-letter country code (RU for Russian Federation)"
    StateOptionUsage                  = "the state in which the domain owner is incorporated"
    LocalityOptionUsage               = "the city in which the domain owner is incorporated"
    OrganizationNameOptionUsage       = "the legal entity that owns the domain"
    OrganizationalUnitNameOptionUsage = "the name of the department or group in your organization that deals with certificates"
    CommonNameOptionUsage             = "the fully qualified domain name (FQDN)"
  )

  cmd := csrCmd{
    abstractCmd: newAbstractCmd(CertificateRequest),
  }

  cmd.StringVar(&cmd.out, "out", "", "output file name")

  cmd.StringVar(&cmd.publicLabel, "publicLabel", "", "public key label")
  cmd.StringVar(&cmd.privateLabel, "privateLabel", "", "private key label")

  cmd.StringVar(&cmd.countryName, "countryName", DefaultCountryName, CountryNameOptionUsage)
  cmd.StringVar(&cmd.countryName, "C", DefaultCountryName, CountryNameOptionUsage+" (shorthand)")

  cmd.StringVar(&cmd.state, "state", DefaultState, StateOptionUsage)
  cmd.StringVar(&cmd.state, "ST", DefaultState, StateOptionUsage+" (shorthand)")

  cmd.StringVar(&cmd.locality, "locality", DefaultLocality, LocalityOptionUsage)
  cmd.StringVar(&cmd.locality, "L", DefaultLocality, LocalityOptionUsage+" (shorthand)")

  cmd.StringVar(&cmd.organizationName, "organizationName", DefaultOrganizationName, OrganizationNameOptionUsage)
  cmd.StringVar(&cmd.organizationName, "O", DefaultOrganizationName, OrganizationNameOptionUsage+" (shorthand)")

  cmd.StringVar(&cmd.organizationalUnitName, "organizationalUnitName", "", OrganizationalUnitNameOptionUsage)
  cmd.StringVar(&cmd.organizationalUnitName, "OU", "", OrganizationalUnitNameOptionUsage+" (shorthand)")

  cmd.StringVar(&cmd.commonName, "commonName", "", CommonNameOptionUsage)
  cmd.StringVar(&cmd.commonName, "CN", "", CommonNameOptionUsage+" (shorthand)")

  cmd.StringVar(&cmd.dns, "dns", "", "comma separated SAN DNS names")
  cmd.StringVar(&cmd.ip, "ip", "", "comma separated SAN IP addresses")

  defaultSignatureName, _ := cu.GetSignatureAlgorithmName(DefaultSignatureAlgorithm)
  cmd.StringVar(&cmd.signature, "signature", defaultSignatureName, fmt.Sprintf("signature algorithm: %s",
    strings.Join(cu.GetSupportedSignatureAlgorithmNames(), "|")))

  cmd.exec = cmd.execFunc
  return &cmd
}

func (c *csrCmd) Verify() error {
  if !c.Parsed() {
    return ErrMustBeParsed
  }
  if len(c.Args()) > 0 {
    return ErrTooManyArguments
  }
  if c.publicLabel == "" {
    return ErrPublicKeyLabelEmpty
  }
  if c.privateLabel == "" {
    return ErrPrivateKeyLabelEmpty
  }
  if c.commonName == "" {
    return ErrCommonNameEmpty
  }

  var err error
  if c.signatureAlgorithm,
    err = cu.GetSignatureAlgorithmByName(c.signature); err != nil {
    return err
  }

  r := regexp.MustCompile("\\s")

  if c.dns != "" {
    c.dnsNames = strings.Split(r.ReplaceAllString(c.dns, ""), ",")
  }

  if c.ip != "" {
    for _, s := range strings.Split(r.ReplaceAllString(c.ip, ""), ",") {
      ip := net.ParseIP(s)
      if ip == nil {
        return fmt.Errorf("invalid IP address: %s", s)
      }
      c.ipAddresses = append(c.ipAddresses, ip)
    }
  }

  c.verified = true
  return nil
}

func newImportCertificateCmd() Command {
  cmd := importCertificateCmd{
    abstractCmd: newAbstractCmd(ImportCertificate),
  }
  cmd.StringVar(&cmd.in, "in", "", "input file name")
  cmd.StringVar(&cmd.label, "label", "", "label")
  cmd.exec = cmd.execFunc
  return &cmd
}

func (*importCertificateCmd) Name() string { return ImportCertificate }

func (c *importCertificateCmd) Verify() error {
  if !c.Parsed() {
    return ErrMustBeParsed
  }
  if len(c.Args()) > 0 {
    return ErrTooManyArguments
  }
  if c.in == "" {
    return ErrPathEmpty
  }
  if c.label == "" {
    return ErrLabelEmpty
  }

  c.verified = true
  return nil
}

func newImportKeyCmd() Command {
  cmd := importKeyCmd{
    abstractCmd: newAbstractCmd(ImportKey),
  }
  cmd.StringVar(&cmd.in, "in", "", "input file name")
  cmd.StringVar(&cmd.label, "label", "", "label")
  cmd.exec = cmd.execFunc
  return &cmd
}

func (*importKeyCmd) Name() string { return ImportKey }

func (c *importKeyCmd) Verify() error {
  if !c.Parsed() {
    return ErrMustBeParsed
  }
  if len(c.Args()) > 0 {
    return ErrTooManyArguments
  }
  if c.in == "" {
    return ErrPathEmpty
  }
  if c.label == "" {
    return ErrLabelEmpty
  }

  c.verified = true
  return nil
}
