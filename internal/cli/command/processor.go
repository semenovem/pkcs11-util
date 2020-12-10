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

func (c *slotsCmd) Execute() (err error) {
	handle := pkcs11.New(c.lib)
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

func (c *abstractCmd) beforeFunc() (err error) {
	if c.pin == "" {
		fmt.Printf("Enter PIN: ")
		var pin []byte
		pin, err = terminal.ReadPassword(0)
		if err != nil {
			return
		}
		c.pin = string(pin)
	}

	c.ctx, err = cu.NewContext(
		c.lib,
		cu.WithSlotLabel(c.slot), cu.WithSlotPin(c.pin))
	return
}

func (c *abstractCmd) afterFunc() error {
	if c.ctx != nil {
		c.ctx.Close()
	}
	return nil
}

func (c *abstractCmd) Execute() error {
	if !c.verified {
		return ErrMustBeVerifyed
	}
	if c.exec == nil {
		return ErrProcessorMustBeSet
	}

	if c.before != nil {
		if err := c.before(); err != nil {
			return err
		}
	}
	if c.after != nil {
		defer c.after()
	}
	return c.exec()
}

func (c *listCmd) execFunc() error {
	var attrs []*pkcs11.Attribute
	switch c.class {
	case "":
	case "private":
		attrs = append(attrs, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY))
	case "public":
		attrs = append(attrs, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY))
	}

	objs, err := cu.FindObjects(c.ctx, attrs...)
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
		attributes, err := cu.GetAttributes(c.ctx, obj, template...)
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

func (c *destroyCmd) execFunc() error {
	for _, a := range c.Args() {
		o, _ := strconv.Atoi(a)
		if c.confirm {
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
		if err := cu.DestroyObject(c.ctx, pkcs11.ObjectHandle(o)); err != nil {
			return err
		}
		fmt.Printf("destroyed handle=%v\n", o)
	}
	return nil
}

func (c *setPinCmd) execFunc() error {
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

	handle := c.ctx.GetHandle()
	session := c.ctx.GetSession()
	if err := handle.SetPIN(session, c.pin, string(pin1)); err != nil {
		return err
	}

	fmt.Printf("Pin has been changed for slot: %s\n", c.slot)
	return nil
}

func (c *generateCmd) execFunc() error {
	// check if the labels already in use
	objs, err := cu.FindObjects(c.ctx)
	if err != nil {
		return fmt.Errorf("Error: %w", err)
	}
	labelTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	}
	for _, obj := range objs {
		attributes, err := cu.GetAttributes(c.ctx, obj, labelTemplate...)
		if err != nil {
			return fmt.Errorf("Error: %w", err)
		}
		label := cu.AttributeToString(attributes[0])
		if label == c.publicLabel || label == c.privateLabel {
			return fmt.Errorf("Label already in use: %s", label)
		}
	}

	var template interface{}
	if c.keyType == KeyECDSA {
		template = cu.ECDSAKeyPairTemplate{
			Curve:        c.curve,
			PublicLabel:  c.publicLabel,
			PrivateLabel: c.privateLabel,
			Token:        c.token,
			Sign:         c.sign,
			Verify:       c.verify,
			Encrypt:      c.encrypt,
			Decrypt:      c.decrypt,
			Sensitive:    c.sensitive,
			Extractable:  c.extractable,
			Modifiable:   c.modifiable,
		}
	}
	if c.keyType == KeyRSA {
		template = cu.RSAKeyPairTemplate{
			Size:         c.keyBits,
			PublicLabel:  c.publicLabel,
			PrivateLabel: c.privateLabel,
			Token:        c.token,
			Sign:         c.sign,
			Verify:       c.verify,
			Encrypt:      c.encrypt,
			Decrypt:      c.decrypt,
			Sensitive:    c.sensitive,
			Extractable:  c.extractable,
			Modifiable:   c.modifiable,
		}
	}
	pub, prv, err := cu.NewGenerator(c.ctx).GenerateKeyPair(template)
	if err != nil {
		return err
	}
	fmt.Printf("public=%v private=%v\n", pub, prv)
	return nil
}

func (c *csrCmd) execFunc() (err error) {
	key, err := cu.NewSigner(c.ctx, c.privateLabel, c.publicLabel)
	if err != nil {
		return
	}

	subject := pkix.Name{
		CommonName: c.commonName,
	}

	if c.countryName != "" {
		subject.Country = []string{c.countryName}
	}
	if c.state != "" {
		subject.Province = []string{c.state}
	}
	if c.locality != "" {
		subject.Locality = []string{c.locality}
	}
	if c.organizationName != "" {
		subject.Organization = []string{c.organizationName}
	}
	if c.organizationalUnitName != "" {
		subject.OrganizationalUnit = []string{c.organizationalUnitName}
	}

	csrTemplate := x509.CertificateRequest{
		Subject:            subject,
		DNSNames:           c.dnsNames,
		IPAddresses:        c.ipAddresses,
		SignatureAlgorithm: c.signatureAlgorithm,
	}

	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return
	}

	var out io.Writer
	if c.out != "" {
		var file *os.File
		file, err = os.OpenFile(c.out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return
		}
		out = file
		defer func() {
			file.Close()
			if err != nil {
				os.Remove(c.out)
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
