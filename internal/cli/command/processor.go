package command

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/miekg/pkcs11"
	"golang.org/x/crypto/ssh/terminal"

	"vtb.ru/pkcs11-util/pkg/cu"
)

func (self *slotsCmd) Execute() (err error) {
	handle := pkcs11.New(self.lib)
	err = handle.Initialize()
	if err != nil {
		return
	}

	var slots []uint
	slots, err = handle.GetSlotList(true)
	if err != nil {
		return
	}

	if len(slots) == 0 {
		fmt.Printf("Not found")
	}

	var ti pkcs11.TokenInfo
	for i, slot := range slots {
		ti, err = handle.GetTokenInfo(slot)
		if err != nil {
			return
		}
		fmt.Printf("%3d Label=%-16s ManufacturerID=%s Model=%s SerialNumber=%s\n",
			i, ti.Label, ti.ManufacturerID, ti.Model, ti.SerialNumber)
	}
	return
}

func (self *abstractCmd) beforeFunc() (err error) {
	self.ctx, err = cu.NewContext(
		self.lib,
		cu.WithSlotLabel(self.slot), cu.WithSlotPin(self.pin))
	return
}

func (self *abstractCmd) afterFunc() error {
	if self.ctx != nil {
		self.ctx.Close()
	}
	return nil
}

func (self *abstractCmd) Execute() error {
	if !self.verified {
		return ErrMustBeVerifyed
	}
	if self.exec == nil {
		return ErrProcessorMustBeSet
	}

	if self.before != nil {
		if err := self.before(); err != nil {
			return err
		}
	}
	if self.after != nil {
		defer self.after()
	}
	return self.exec()
}

func (self *listCmd) execFunc() error {
	var attrs []*pkcs11.Attribute
	switch self.class {
	case "":
	case "private":
		attrs = append(attrs, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY))
	case "public":
		attrs = append(attrs, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY))
	}

	objs, err := cu.FindObjects(self.ctx, attrs...)
	if err != nil {
		return fmt.Errorf("Error: %w", err)
	}

	if len(objs) == 0 {
		return fmt.Errorf("Objects not found")
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	}
	for _, obj := range objs {
		attributes, err := cu.GetAttributes(self.ctx, obj, template...)
		if err != nil {
			return fmt.Errorf("Error: %w", err)
		}
		fmt.Printf("handle=%v\tclass=%v\tlabel=%s\n",
			obj,
			cu.AttributeToString(attributes[0]),
			cu.AttributeToString(attributes[1]))
	}
	return nil
}

func (self *destroyCmd) execFunc() error {
	for _, a := range self.Args() {
		o, _ := strconv.Atoi(a)
		if self.confirm {
			fmt.Printf("Destroy handle %v (y/n/q [n])? ", o)
			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			ch := string([]byte(input)[0])
			switch ch {
			case "q":
				fmt.Println("Aborted!")
				return nil
			case "y":
				break
			default:
				continue
			}
		}
		if err := cu.DestroyObject(self.ctx, pkcs11.ObjectHandle(o)); err != nil {
			return err
		}
		fmt.Printf("destroyed handle=%v\n", o)
	}
	return nil
}

func (self *setPinCmd) execFunc() error {
	fmt.Print("Enter new pin: ")
	pin1, err := terminal.ReadPassword(0)
	fmt.Println()
	if err != nil {
		return err
	}

	fmt.Print("Reenter pin: ")
	pin2, err := terminal.ReadPassword(0)
	fmt.Println()
	if err != nil {
		return err
	}

	if !bytes.Equal(pin1, pin2) {
		return ErrPinsDoesNotMatch
	}

	handle := self.ctx.GetHandle()
	session := self.ctx.GetSession()
	if err := handle.SetPIN(session, self.pin, string(pin1)); err != nil {
		return err
	}

	fmt.Printf("Pin has been changed for slot: %s\n", self.slot)
	return nil
}

func (self *generateCmd) execFunc() error {
	// check if the labels already in use
	objs, err := cu.FindObjects(self.ctx)
	if err != nil {
		return fmt.Errorf("Error: %w", err)
	}
	labelTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	}
	for _, obj := range objs {
		attributes, err := cu.GetAttributes(self.ctx, obj, labelTemplate...)
		if err != nil {
			return fmt.Errorf("Error: %w", err)
		}
		label := cu.AttributeToString(attributes[0])
		if label == self.publicLabel || label == self.privateLabel {
			return fmt.Errorf("Label already in use: %s", label)
		}
	}

	template := cu.ECDSAKeyPairTemplate{
		Curve:        self.curve,
		PublicLabel:  self.publicLabel,
		PrivateLabel: self.privateLabel,
		Token:        self.token,
		Sign:         self.sign,
		Verify:       self.verify,
		Encrypt:      self.encrypt,
		Decrypt:      self.decrypt,
		Sensitive:    self.sensitive,
		Extractable:  self.extractable,
		Modifiable:   self.modifiable,
	}
	pub, prv, err := cu.NewGenerator(self.ctx).GenerateKeyPair(template)
	if err != nil {
		return err
	}
	fmt.Printf("public=%v private=%v\n", pub, prv)
	return nil
}

func (self *csrCmd) execFunc() (err error) {
	key, err := cu.NewSigner(self.ctx, self.privateLabel, self.publicLabel)
	if err != nil {
		return
	}

	subject := pkix.Name{
		CommonName: self.commonName,
	}

	if self.countryName != "" {
		subject.Country = []string{self.countryName}
	}
	if self.state != "" {
		subject.Province = []string{self.state}
	}
	if self.locality != "" {
		subject.Locality = []string{self.locality}
	}
	if self.organizationName != "" {
		subject.Organization = []string{self.organizationName}
	}
	if self.organizationalUnitName != "" {
		subject.OrganizationalUnit = []string{self.organizationalUnitName}
	}

	csrTemplate := x509.CertificateRequest{
		Subject:            subject,
		DNSNames:           self.dnsNames,
		IPAddresses:        self.ipAddresses,
		SignatureAlgorithm: self.signatureAlgorithm,
	}

	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return
	}

	var out io.Writer
	if self.out != "" {
		var file *os.File
		file, err = os.OpenFile(self.out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return
		}
		out = file
		defer func() {
			file.Close()
			if err != nil {
				os.Remove(self.out)
				return
			}
			file.Close()
		}()
	} else {
		buf := &bytes.Buffer{}
		out = buf
		defer func() {
			if err != nil {
				return
			}
			fmt.Printf("%s\n", buf.String())
		}()
	}

	err = pem.Encode(out, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrCertificate,
	})
	return
}
