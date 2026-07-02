package smtpsrv

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

type countingReader struct {
	r     io.Reader
	count int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.count += n
	return n, err
}

func TestParseEmailToleratesQuotedPrintablePartEndingWithEquals(t *testing.T) {
	raw := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Test\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"mail-boundary\"\r\n" +
		"\r\n" +
		"--mail-boundary\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" +
		"memory used more than 80%=\r\n" +
		"--mail-boundary--\r\n"

	msg, err := ParseEmail(bytes.NewReader([]byte(raw)), 65536)
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}

	if msg.TextBody != "memory used more than 80%=" {
		t.Fatalf("TextBody = %q", msg.TextBody)
	}
}

func TestParseEmailToleratesMixedCaseQuotedPrintableEncoding(t *testing.T) {
	raw := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Test\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"mail-boundary\"\r\n" +
		"\r\n" +
		"--mail-boundary\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: Quoted-Printable\r\n" +
		"\r\n" +
		"hello=20world\r\n" +
		"--mail-boundary--\r\n"

	msg, err := ParseEmail(bytes.NewReader([]byte(raw)), 65536)
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}

	if msg.TextBody != "hello world" {
		t.Fatalf("TextBody = %q", msg.TextBody)
	}
}

func TestDecodeContentToleratesMixedCaseBase64Encoding(t *testing.T) {
	reader, err := decodeContent(
		strings.NewReader("aGVsbG8="),
		"Base64",
		"text/plain; charset=utf-8",
	)
	if err != nil {
		t.Fatalf("decodeContent() error = %v", err)
	}

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("decodeContent() = %q", got)
	}
}

func TestParseEmailToleratesMalformedSpamHeaderFragments(t *testing.T) {
	fragments := []string{
		"X-SPAM-SOURCE-CHE",
		"X-SPAM-SOURCE-C",
		"X-SPAM-SOURCE-CH",
		"X-SPA",
		"X-S",
		"X-SP",
	}

	for _, fragment := range fragments {
		t.Run(fragment, func(t *testing.T) {
			raw := "From: sender@example.com\r\n" +
				fragment + "\r\n" +
				"To: recipient@example.com\r\n" +
				"Subject: Test\r\n" +
				"\r\n" +
				"body"

			msg, err := ParseEmail(bytes.NewReader([]byte(raw)), 65536)
			if err != nil {
				t.Fatalf("ParseEmail() error = %v", err)
			}

			if msg.Subject != "Test" {
				t.Fatalf("Subject = %q", msg.Subject)
			}
			if msg.TextBody != "body" {
				t.Fatalf("TextBody = %q", msg.TextBody)
			}
		})
	}
}

func TestParseEmailDropsMalformedHeaderContinuations(t *testing.T) {
	raw := "From: sender@example.com\r\n" +
		"X-SPAM-SOURCE-C\r\n" +
		" continuation that must not attach to From\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"body"

	msg, err := ParseEmail(bytes.NewReader([]byte(raw)), 65536)
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}

	if got := msg.Header.Get("From"); got != "sender@example.com" {
		t.Fatalf("From header = %q", got)
	}
}

func TestParseEmailRejectsOversizedHeader(t *testing.T) {
	raw := "From: sender@example.com\r\n" +
		"X-Large: " + strings.Repeat("x", 128) + "\r\n" +
		"\r\n" +
		"body"

	_, err := ParseEmail(bytes.NewReader([]byte(raw)), 64)
	if err == nil {
		t.Fatal("ParseEmail() error is nil")
	}
	if !strings.Contains(err.Error(), "message header exceeds") {
		t.Fatalf("ParseEmail() error = %v", err)
	}
}

func TestParseEmailRejectsOversizedHeaderBeforeReadingWholeLine(t *testing.T) {
	raw := "From: sender@example.com\r\n" +
		"X-Large: " + strings.Repeat("x", 1024*1024)
	reader := &countingReader{r: strings.NewReader(raw)}

	_, err := ParseEmail(reader, 64)
	if err == nil {
		t.Fatal("ParseEmail() error is nil")
	}
	if !strings.Contains(err.Error(), "message header exceeds") {
		t.Fatalf("ParseEmail() error = %v", err)
	}
	if reader.count > 65 {
		t.Fatalf("ParseEmail read %d bytes before rejecting oversized header; want at most 65", reader.count)
	}
}

func TestParseEmailDoesNotEagerlyReadOpaqueBody(t *testing.T) {
	header := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Test\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"\r\n"
	body := strings.Repeat("x", 1024*1024)
	reader := &countingReader{r: strings.NewReader(header + body)}

	msg, err := ParseEmail(reader, 65536)
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}
	if msg.Content == nil {
		t.Fatal("Content is nil")
	}

	if reader.count >= len(header)+len(body) {
		t.Fatalf("ParseEmail eagerly read %d bytes; want less than full message size %d", reader.count, len(header)+len(body))
	}
}

func BenchmarkParseEmailPlainText(b *testing.B) {
	raw := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Test\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		strings.Repeat("alert body\n", 100))

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := ParseEmail(bytes.NewReader(raw), 65536)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseEmailOpaqueLargeBody(b *testing.B) {
	raw := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Test\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"\r\n" +
		strings.Repeat("x", 1024*1024))

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		msg, err := ParseEmail(bytes.NewReader(raw), 65536)
		if err != nil {
			b.Fatal(err)
		}
		if msg.Content == nil {
			b.Fatal("Content is nil")
		}
	}
}
