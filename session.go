package smtpsrv

import (
	"errors"
	"io"
	"net/mail"

	"github.com/emersion/go-smtp"
)

// A Session is returned after successful login.
type Session struct {
	conn     *smtp.Conn
	From     *mail.Address
	To       *mail.Address
	auther   AuthFunc
	handler  HandlerFunc
	body     io.Reader
	username *string
	password *string
}

// NewSession initialize a new session
func NewSession(c *smtp.Conn, auther AuthFunc, handler HandlerFunc) *Session {
	return &Session{
		conn:    c,
		auther:  auther,
		handler: handler,
	}
}

// Authenticate the user using SASL PLAIN.
func (s *Session) AuthPlain(username, password string) error {
	if s.auther == nil {
		return nil
	}

	s.username = &username
	s.password = &password
	return s.auther(username, password)
}

// Set return path for currently processed message.
func (s *Session) Mail(from string, opts *smtp.MailOptions) (err error) {
	s.From, err = mail.ParseAddress(from)
	return
}

// Add recipient for currently processed message.
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) (err error) {
	s.To, err = mail.ParseAddress(to)
	return
}

// Set currently processed message contents and send it.
// r must be consumed before Data returns.
func (s *Session) Data(r io.Reader) error {
	if s.handler == nil {
		return errors.New("internal error: no handler")
	}

	s.body = r

	c := Context{
		session: s,
	}

	return s.handler(&c)
}

// Discard currently processed message.
func (s *Session) Reset() {
}

// Free all resources associated with session.
func (s *Session) Logout() error {
	return nil
}
