package smtpsrv

import "github.com/emersion/go-smtp"

// The Backend implements SMTP server methods.
type Backend struct {
	handler HandlerFunc
	auther  AuthFunc
}

func NewBackend(auther AuthFunc, handler HandlerFunc) *Backend {
	return &Backend{
		handler: handler,
		auther:  auther,
	}
}

// NewSession is called after client greeting (EHLO, HELO).
func (bkd *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return NewSession(c, bkd.auther, bkd.handler), nil
}
