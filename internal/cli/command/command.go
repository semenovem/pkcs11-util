package command

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"

	"vtb.ru/pkcs11-util/pkg/cu"
)

// Supported commands
const (
	Version            = "version"
	List               = "list"
	Destroy            = "destroy"
	Generate           = "generate"
	CertificateRequest = "certificateRequest"
)

// Supported keys
const (
	KeyECDSA = "ecdsa"
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

	// generateCmd contains Generate command arguments
	generateCmd struct {
		*abstractCmd
		keyType      string
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

		// signature conatins signature algorithm
		signature string

		// signatureAlgorithm contains parsed signature algorith
		signatureAlgorithm x509.SignatureAlgorithm

		//	dns contains comma separated SAN DNS names
		dns string
		// dnsNames contains parsed SAN DNS names
		dnsNames []string
		// ip contains comma separated SAN IP addresses
		ip string
		// ipAddresses contains parsed SAN IP addresses
		ipAddresses []net.IP
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
	ErrIncorrectArguments    = errors.New("Incorrect argument(s)")
	ErrIncorrectArgumentType = errors.New("Incorrect argument type")
	ErrKeyTypeEmpty          = errors.New("Key type must not be empty")
	ErrMustBeParsed          = errors.New("Must be parsed first")
	ErrMustBeVerifyed        = errors.New("Must be verified first")
	ErrNotEnoughArguments    = errors.New("Not enough arguments")
	ErrPrivateKeyLabelEmpty  = errors.New("Private key label must not be empty")
	ErrProcessorMustBeSet    = errors.New("Processor must be set")
	ErrPublicKeyLabelEmpty   = errors.New("Public key label must not be empty")
	ErrTooManyArguments      = errors.New("Too many arguments")
	ErrUnknownKeyType        = errors.New("Unknown key type")
)

var (
	DefaultLib = "/usr/safenet/lunaclient/lib/libCryptoki2_64.so"
)

var commands map[string]Command = make(map[string]Command)

func init() {
	cmds := []Command{
		newVersionCmd(),
		newListCmd(),
		newDestroyCmd(),
		newGenerateCmd(),
		newCsrCmd(),
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

func (self *abstractCmd) Execute() error {
	if !self.verified {
		return ErrMustBeVerifyed
	}
	if self.exec == nil {
		return ErrProcessorMustBeSet
	}

	if err := self.before(); err != nil {
		return err
	}
	defer self.after()
	return self.exec()
}

func newListCmd() Command {
	cmd := listCmd{
		abstractCmd: newAbstractCmd(List),
	}
	cmd.StringVar(&cmd.class, "class", "", "object class: public|private")
	cmd.exec = cmd.execFunc
	return &cmd
}

func (self *listCmd) Verify() error {
	if !self.Parsed() {
		return ErrMustBeParsed
	}
	if len(self.Args()) > 0 {
		return ErrTooManyArguments
	}
	if self.class != "" && self.class != "public" && self.class != "private" {
		return ErrIncorrectArguments
	}
	self.verified = true
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

func (self *destroyCmd) Verify() error {
	if !self.Parsed() {
		return ErrMustBeParsed
	}
	if len(self.Args()) < 1 {
		return ErrNotEnoughArguments
	}
	for _, a := range self.Args() {
		if _, err := strconv.Atoi(a); err != nil {
			return ErrIncorrectArgumentType
		}
	}
	self.verified = true
	return nil
}

func newGenerateCmd() Command {
	cmd := generateCmd{
		abstractCmd: newAbstractCmd(Generate),
	}
	cmd.StringVar(&cmd.keyType, "type", "", "key type: "+KeyECDSA)
	cmd.StringVar(&cmd.curve, "curve", "",
		fmt.Sprintf("elliptic curve: %s|%s|%s|%s",
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

func (self *generateCmd) Verify() error {
	if !self.Parsed() {
		return ErrMustBeParsed
	}
	if len(self.Args()) > 0 {
		return ErrTooManyArguments
	}

	if self.keyType == "" {
		return ErrKeyTypeEmpty
	}
	if self.keyType != KeyECDSA {
		return ErrUnknownKeyType
	}

	if self.curve == "" {
		return ErrEllipticCurveEmpty
	}
	if !cu.WellKnownCurve(self.curve) {
		return cu.ErrUnsupportedEllipticCurve
	}

	if self.publicLabel == "" {
		return ErrPublicKeyLabelEmpty
	}
	if self.privateLabel == "" {
		return ErrPrivateKeyLabelEmpty
	}

	self.verified = true
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
	cmd.StringVar(&cmd.signature, "signature", defaultSignatureName,
		fmt.Sprintf("signature algorithm: %s",
			strings.Join(cu.GetSupportedSignatureAlgorithmNames(), "|")))

	cmd.exec = cmd.execFunc
	return &cmd
}

func (self *csrCmd) Verify() error {
	if !self.Parsed() {
		return ErrMustBeParsed
	}
	if self.publicLabel == "" {
		return ErrPublicKeyLabelEmpty
	}
	if self.privateLabel == "" {
		return ErrPrivateKeyLabelEmpty
	}
	if self.commonName == "" {
		return ErrCommonNameEmpty
	}

	var err error
	if self.signatureAlgorithm,
		err = cu.GetSignatureAlgorithmByName(self.signature); err != nil {
		return err
	}

	if self.dns != "" {
		self.dnsNames = strings.Split(self.dns, ",")
	}

	if self.ip != "" {
		for _, s := range strings.Split(self.ip, ",") {
			ip := net.ParseIP(s)
			if ip == nil {
				return fmt.Errorf("invalid IP address: %s", s)
			}
			self.ipAddresses = append(self.ipAddresses, ip)
		}
	}

	self.verified = true
	return nil
}
