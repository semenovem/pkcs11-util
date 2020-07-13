package command

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"vtb.ru/pkcs11-util/pkg/cu"
)

func TestListCommand(t *testing.T) {
	const Command = List

	t.Run("Should be parsed before verification", func(t *testing.T) {
		cmd := Get(Command)
		assert.NotNil(t, cmd)

		err := cmd.Verify()
		assert.Equal(t, ErrMustBeParsed, err)
	})

	t.Run("Should be verified before execution", func(t *testing.T) {
		cmd := Get(Command)
		assert.NotNil(t, cmd)

		err := cmd.Parse(nil)
		assert.Nil(t, err)

		err = cmd.Execute()
		assert.Equal(t, ErrMustBeVerifyed, err)
	})

	tests := []struct {
		name string
		args []string
		err  error
	}{
		{
			name: "defaults",
			args: []string{"-slot", "testslot", "-pin", "testpin"},
		},
		{
			name: "class public",
			args: []string{"-slot", "testslot", "-pin", "testpin", "-class", "public"},
		},
		{
			name: "class private",
			args: []string{"-slot", "testslot", "-pin", "testpin", "-class", "private"},
		},
		{
			name: "class unknown",
			args: []string{"-slot", "testslot", "-pin", "testpin", "-class", "UNKNOWN"},
			err:  ErrIncorrectArguments,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := Get(Command)
			assert.Nil(t, cmd.Parse(tt.args))
			assert.Equal(t, tt.err, cmd.Verify())
		})
	}
}

func TestDestroyCommand(t *testing.T) {
	const Command = Destroy

	t.Run("Should be parsed before verification", func(t *testing.T) {
		cmd := Get(Command)
		assert.NotNil(t, cmd)

		err := cmd.Verify()
		assert.Equal(t, ErrMustBeParsed, err)
	})

	t.Run("Should be verified before execution", func(t *testing.T) {
		cmd := Get(Command)
		assert.NotNil(t, cmd)

		err := cmd.Parse(nil)
		assert.Nil(t, err)

		err = cmd.Execute()
		assert.Equal(t, ErrMustBeVerifyed, err)
	})

	tests := []struct {
		name string
		args []string
		err  error
	}{
		{
			name: "ok",
			args: []string{"-slot", "testslot", "-pin", "testpin", "100"},
		},
		{
			name: "not enough arguments",
			args: []string{"-slot", "testslot", "-pin", "testpin"},
			err:  ErrNotEnoughArguments,
		},
		{
			name: "incorrect argument type",
			args: []string{"-slot", "testslot", "-pin", "testpin", "foo"},
			err:  ErrIncorrectArgumentType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := Get(Command)
			assert.Nil(t, cmd.Parse(tt.args))
			assert.Equal(t, tt.err, cmd.Verify())
		})
	}
}

func TestGenerateCommand(t *testing.T) {
	const Command = Generate

	t.Run("Should be parsed before verification", func(t *testing.T) {
		cmd := Get(Command)
		assert.NotNil(t, cmd)

		err := cmd.Verify()
		assert.Equal(t, ErrMustBeParsed, err)
	})

	t.Run("Should be verified before execution", func(t *testing.T) {
		cmd := Get(Command)
		assert.NotNil(t, cmd)

		err := cmd.Parse(nil)
		assert.Nil(t, err)

		err = cmd.Execute()
		assert.Equal(t, ErrMustBeVerifyed, err)
	})

	tests := []struct {
		name string
		args []string
		err  error
	}{
		{
			name: "err: empty key type",
			args: []string{"-slot", "testslot", "-pin", "testpin"},
			err:  ErrKeyTypeEmpty,
		},
		{
			name: "err: incorrect key type",
			args: []string{"-slot", "testslot", "-pin", "testpin", "-type", "UNKNOWN"},
			err:  ErrUnknownKeyType,
		},
		{
			name: "err: ECDSA with empty curve",
			args: []string{"-slot", "testslot", "-pin", "testpin", "-type", KeyECDSA},
			err:  ErrEllipticCurveEmpty,
		},
		{
			name: "err: ECDSA with unsupported curve",
			args: []string{"-slot", "testslot", "-pin", "testpin", "-type", KeyECDSA, "-curve", "UNSUPPORTED"},
			err:  cu.ErrUnsupportedEllipticCurve,
		},
		{
			name: "err: public key label empty",
			args: []string{"-slot", "testslot", "-pin", "testpin", "-type", KeyECDSA, "-curve", "P521"},
			err:  ErrPublicKeyLabelEmpty,
		},
		{
			name: "err: private key label empty",
			args: []string{"-slot", "testslot", "-pin", "testpin", "-type", KeyECDSA, "-curve", "P521", "-publicLabel", "pub"},
			err:  ErrPrivateKeyLabelEmpty,
		},
		{
			name: "ok: ECDSA with valid curve",
			args: []string{"-slot", "testslot", "-pin", "testpin", "-type", KeyECDSA, "-curve", "P521", "-publicLabel", "pub", "-privateLabel", "prv"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := Get(Command)
			assert.Nil(t, cmd.Parse(tt.args))
			assert.Equal(t, tt.err, cmd.Verify())
		})
	}
}

func TestCertificateRequestCommandCommand(t *testing.T) {
	const Command = CertificateRequest

	t.Run("Should be parsed before verification", func(t *testing.T) {
		cmd := Get(Command)
		assert.NotNil(t, cmd)

		err := cmd.Verify()
		assert.Equal(t, ErrMustBeParsed, err)
	})

	t.Run("Should be verified before execution", func(t *testing.T) {
		cmd := Get(Command)
		assert.NotNil(t, cmd)

		err := cmd.Parse(nil)
		assert.Nil(t, err)

		err = cmd.Execute()
		assert.Equal(t, ErrMustBeVerifyed, err)
	})

	tests := []struct {
		name string
		args []string
		err  error
	}{
		{
			name: "err: public key label empty",
			args: []string{"-slot", "testslot", "-pin", "testpin"},
			err:  ErrPublicKeyLabelEmpty,
		},
		{
			name: "err: private key label empty",
			args: []string{"-slot", "testslot", "-pin", "testpin", "-publicLabel", "pub"},
			err:  ErrPrivateKeyLabelEmpty,
		},
		{
			name: "err: common name empty",
			args: []string{"-slot", "testslot", "-pin", "testpin", "-publicLabel", "pub", "-privateLabel", "prv"},
			err:  ErrCommonNameEmpty,
		},
		{
			name: "ok",
			args: []string{"-slot", "testslot", "-pin", "testpin", "-publicLabel", "pub", "-privateLabel", "prv", "-CN", "common_name"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := Get(Command)
			assert.Nil(t, cmd.Parse(tt.args))
			assert.Equal(t, tt.err, cmd.Verify())
		})
	}
}
