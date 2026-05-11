package smtpsrv

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

func TestSanitizeBase64(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "clean data unchanged",
			input: "SGVsbG8gV29ybGQ=",
			want:  "SGVsbG8gV29ybGQ=",
		},
		{
			name:  "strips spaces",
			input: "SGVs bG8g V29y bGQ=",
			want:  "SGVsbG8gV29ybGQ=",
		},
		{
			name:  "strips tabs and newlines",
			input: "SGVs\tbG8g\r\nV29ybGQ=",
			want:  "SGVsbG8gV29ybGQ=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(sanitizeBase64([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("sanitizeBase64() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeContentBase64Lenient(t *testing.T) {
	original := "Hello World! This is a test message."
	encoded := base64.StdEncoding.EncodeToString([]byte(original))

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "valid base64",
			input: encoded,
			want:  original,
		},
		{
			name:  "base64 with leading spaces on continuation lines (header folding style)",
			input: encoded[:20] + "\r\n " + encoded[20:],
			want:  original,
		},
		{
			name:  "base64 with multiple space-prefixed lines",
			input: encoded[:10] + "\r\n " + encoded[10:20] + "\r\n " + encoded[20:],
			want:  original,
		},
		{
			name:  "base64 with tab characters",
			input: encoded[:20] + "\t" + encoded[20:],
			want:  original,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, err := decodeContent(
				strings.NewReader(tt.input),
				"base64",
				"text/plain; charset=utf-8",
			)
			if err != nil {
				t.Fatalf("decodeContent() error = %v", err)
			}

			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("ReadAll() error = %v", err)
			}

			if string(got) != tt.want {
				t.Errorf("decodeContent() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestParseEmailMultipartRelatedWithBadBase64(t *testing.T) {
	htmlContent := "<html><body>Hello</body></html>"
	b64 := base64.StdEncoding.EncodeToString([]byte(htmlContent))
	// Simulate the real-world bug: split into ~20-char lines with leading spaces
	dirtyB64 := b64[:20] + "\r\n " + b64[20:]

	imgData := []byte{0x89, 0x50, 0x4E, 0x47} // PNG header
	imgB64 := base64.StdEncoding.EncodeToString(imgData)

	eml := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Test\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related;\r\n" +
		"\ttype=\"multipart/alternative\";\r\n" +
		"\tboundary=\"outer\"\r\n" +
		"\r\n" +
		"--outer\r\n" +
		"Content-Type: multipart/alternative;\r\n" +
		"\tboundary=\"inner\"\r\n" +
		"\r\n" +
		"--inner\r\n" +
		"Content-Type: text/html; charset=\"utf-8\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		dirtyB64 + "\r\n" +
		"--inner--\r\n" +
		"\r\n" +
		"--outer\r\n" +
		"Content-Type: image/png; name=\"logo.png\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-ID: <logo.png>\r\n" +
		"\r\n" +
		imgB64 + "\r\n" +
		"--outer--\r\n"

	email, err := ParseEmail(bytes.NewReader([]byte(eml)))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}

	if email.HTMLBody != htmlContent {
		t.Errorf("HTMLBody = %q, want %q", email.HTMLBody, htmlContent)
	}

	if len(email.EmbeddedFiles) != 1 {
		t.Fatalf("expected 1 embedded file, got %d", len(email.EmbeddedFiles))
	}

	if email.EmbeddedFiles[0].CID != "logo.png" {
		t.Errorf("EmbeddedFile CID = %q, want %q", email.EmbeddedFiles[0].CID, "logo.png")
	}
}

func TestParseEmailMultipartRelatedTextDecoding(t *testing.T) {
	htmlContent := "<html><body>直接在 related 中的 HTML</body></html>"
	b64 := base64.StdEncoding.EncodeToString([]byte(htmlContent))

	eml := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Test\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related;\r\n" +
		"\tboundary=\"boundary\"\r\n" +
		"\r\n" +
		"--boundary\r\n" +
		"Content-Type: text/html; charset=\"utf-8\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64 + "\r\n" +
		"--boundary--\r\n"

	email, err := ParseEmail(bytes.NewReader([]byte(eml)))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}

	if email.HTMLBody != htmlContent {
		t.Errorf("HTMLBody = %q, want %q", email.HTMLBody, htmlContent)
	}
}
