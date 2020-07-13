package cu

import (
	"errors"
	"io"

	"github.com/miekg/pkcs11"
)

var ErrUninitializedContext = errors.New("uninitialized context")

type contextOpts struct {
	slotID    uint
	slotLabel string
	slotPin   string
}

// ContextOpt defines an option to create Context with
type ContextOpt func(*contextOpts)

// WithSlotID defines PKCS11 slot to use
func WithSlotID(v uint) ContextOpt { return func(o *contextOpts) { o.slotID = v } }

// WithSlotLabel defines PKCS11 slot label
func WithSlotLabel(v string) ContextOpt { return func(o *contextOpts) { o.slotLabel = v } }

// WithSlotPin defines PKCS11 slot pin
func WithSlotPin(v string) ContextOpt { return func(o *contextOpts) { o.slotPin = v } }

// Context holds current PKCS11 connection
type Context struct {
	io.Closer
	slotID  uint
	handle  *pkcs11.Ctx
	session pkcs11.SessionHandle
}

// NewContext creates new Context instance
func NewContext(soPath string, opts ...ContextOpt) (context *Context, err error) {
	handle := pkcs11.New(soPath)
	err = handle.Initialize()
	if err != nil {
		return
	}

	defer func() {
		if err != nil {
			handle.Destroy()
			handle.Finalize()
		}
	}()

	co := contextOpts{}
	for _, o := range opts {
		o(&co)
	}

	if co.slotLabel != "" {
		var slots []uint
		slots, err = handle.GetSlotList(true)
		if err != nil {
			return
		}

		var ti pkcs11.TokenInfo
		for i, slot := range slots {
			ti, err = handle.GetTokenInfo(slot)
			if err != nil {
				return
			}
			if ti.Label == co.slotLabel {
				co.slotID = uint(i)
				break
			}
		}
	}

	session, err := handle.OpenSession(co.slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return
	}

	err = handle.Login(session, pkcs11.CKU_USER, co.slotPin)
	if err != nil {
		return
	}

	context = &Context{
		slotID:  co.slotID,
		handle:  handle,
		session: session,
	}
	return
}

// GetSessionInfo returns information about open PKCS11 session
func (self *Context) GetSessionInfo() (pkcs11.SessionInfo, error) {
	return self.handle.GetSessionInfo(self.session)
}

// Close closes Context
func (self *Context) Close() error {
	if self.handle == nil {
		return ErrUninitializedContext
	}
	self.handle.Logout(self.session)
	self.handle.CloseSession(self.session)
	self.handle.Destroy()
	self.handle.Finalize()
	return nil
}
