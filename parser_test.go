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

func TestParseEmailMultipartMixedEmbeddedFile(t *testing.T) {
	htmlContent := "<html><body><p>alert</p><img src=\"cid:img1\"/></body></html>"
	imgData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	imgB64 := base64.StdEncoding.EncodeToString(imgData)

	eml := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Alert\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"mix\"\r\n" +
		"\r\n" +
		"--mix\r\n" +
		"Content-Type: text/html; charset=\"utf-8\"\r\n" +
		"Content-Transfer-Encoding: 7bit\r\n" +
		"\r\n" +
		htmlContent + "\r\n" +
		"--mix\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-ID: <img1>\r\n" +
		"\r\n" +
		imgB64 + "\r\n" +
		"--mix--\r\n"

	email, err := ParseEmail(bytes.NewReader([]byte(eml)))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}
	if email.HTMLBody != htmlContent {
		t.Errorf("HTMLBody = %q, want %q", email.HTMLBody, htmlContent)
	}
	if len(email.Attachments) != 0 {
		t.Fatalf("expected 0 attachments, got %d", len(email.Attachments))
	}
	if len(email.EmbeddedFiles) != 1 {
		t.Fatalf("expected 1 embedded file, got %d", len(email.EmbeddedFiles))
	}
	if email.EmbeddedFiles[0].CID != "img1" {
		t.Errorf("EmbeddedFile CID = %q, want %q", email.EmbeddedFiles[0].CID, "img1")
	}
	if email.EmbeddedFiles[0].ContentType != "image/png" {
		t.Errorf("EmbeddedFile ContentType = %q, want %q", email.EmbeddedFiles[0].ContentType, "image/png")
	}
	gotData, err := io.ReadAll(email.EmbeddedFiles[0].Data)
	if err != nil {
		t.Fatalf("ReadAll(EmbeddedFiles[0].Data) error = %v", err)
	}
	if !bytes.Equal(gotData, imgData) {
		t.Errorf("EmbeddedFile Data = %x, want %x", gotData, imgData)
	}
}

func TestParseEmailMultipartMixedAccumulatesNestedParts(t *testing.T) {
	img1 := []byte{0x89, 0x50, 0x4E, 0x47}
	img2 := []byte{0xFF, 0xD8, 0xFF, 0xE0}

	eml := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Ordered Parts\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"mix\"\r\n" +
		"\r\n" +
		"--mix\r\n" +
		"Content-Type: text/plain; charset=\"utf-8\"\r\n" +
		"\r\n" +
		"prefix:\r\n" +
		"--mix\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-ID: <first>\r\n" +
		"\r\n" +
		base64.StdEncoding.EncodeToString(img1) + "\r\n" +
		"--mix\r\n" +
		"Content-Type: multipart/alternative; boundary=\"alt\"\r\n" +
		"\r\n" +
		"--alt\r\n" +
		"Content-Type: text/plain; charset=\"utf-8\"\r\n" +
		"\r\n" +
		"body-text\r\n" +
		"--alt\r\n" +
		"Content-Type: text/html; charset=\"utf-8\"\r\n" +
		"\r\n" +
		"<p>body-html</p>\r\n" +
		"--alt--\r\n" +
		"--mix\r\n" +
		"Content-Type: multipart/related; boundary=\"rel\"\r\n" +
		"\r\n" +
		"--rel\r\n" +
		"Content-Type: text/html; charset=\"utf-8\"\r\n" +
		"\r\n" +
		"<p>footer</p>\r\n" +
		"--rel\r\n" +
		"Content-Type: image/jpeg\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-ID: <second>\r\n" +
		"\r\n" +
		base64.StdEncoding.EncodeToString(img2) + "\r\n" +
		"--rel--\r\n" +
		"--mix--\r\n"

	email, err := ParseEmail(bytes.NewReader([]byte(eml)))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}
	if !strings.Contains(email.TextBody, "prefix:") || !strings.Contains(email.TextBody, "body-text") {
		t.Errorf("TextBody = %q, want both prefix and body-text", email.TextBody)
	}
	if !strings.Contains(email.HTMLBody, "<p>body-html</p>") || !strings.Contains(email.HTMLBody, "<p>footer</p>") {
		t.Errorf("HTMLBody = %q, want both body-html and footer", email.HTMLBody)
	}
	if len(email.EmbeddedFiles) != 2 {
		t.Fatalf("expected 2 embedded files, got %d", len(email.EmbeddedFiles))
	}
	if email.EmbeddedFiles[0].CID != "first" || email.EmbeddedFiles[1].CID != "second" {
		t.Errorf("EmbeddedFiles CIDs = [%q, %q], want [\"first\", \"second\"]", email.EmbeddedFiles[0].CID, email.EmbeddedFiles[1].CID)
	}
}

func TestParseEmailMultipartMixedAttachmentPrecedence(t *testing.T) {
	imgData := []byte{0x89, 0x50, 0x4E, 0x47}
	eml := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Attachment\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"mix\"\r\n" +
		"\r\n" +
		"--mix\r\n" +
		"Content-Type: text/plain; charset=\"utf-8\"\r\n" +
		"\r\n" +
		"hello\r\n" +
		"--mix\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-Disposition: attachment; filename=\"chart.png\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		base64.StdEncoding.EncodeToString(imgData) + "\r\n" +
		"--mix--\r\n"

	email, err := ParseEmail(bytes.NewReader([]byte(eml)))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}
	if len(email.Attachments) != 1 || email.Attachments[0].Filename != "chart.png" {
		t.Fatalf("Attachments = %+v, want 1 attachment named chart.png", email.Attachments)
	}
	if len(email.EmbeddedFiles) != 0 {
		t.Fatalf("expected 0 embedded files, got %d", len(email.EmbeddedFiles))
	}
}

func TestParseEmailMultipartMixedRejectsUnknownMultipart(t *testing.T) {
	eml := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Unknown Multipart\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"mix\"\r\n" +
		"\r\n" +
		"--mix\r\n" +
		"Content-Type: multipart/signed; boundary=\"sig\"\r\n" +
		"Content-Transfer-Encoding: 7bit\r\n" +
		"\r\n" +
		"--sig\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"signed body\r\n" +
		"--sig--\r\n" +
		"--mix--\r\n"

	_, err := ParseEmail(bytes.NewReader([]byte(eml)))
	if err == nil {
		t.Fatalf("ParseEmail() expected error for unknown nested multipart, got nil")
	}
	if !strings.Contains(err.Error(), "unknown multipart/mixed nested mime type: multipart/signed") {
		t.Errorf("ParseEmail() error = %v, want unknown multipart/mixed nested mime type: multipart/signed", err)
	}
}

func TestParseEmailMultipartMixedBinaryEncodingBuffersData(t *testing.T) {
	imgData := []byte{0x89, 0x50, 0x4E, 0x47, 0x01, 0x02}
	var buf bytes.Buffer
	buf.WriteString("From: sender@example.com\r\n")
	buf.WriteString("To: recipient@example.com\r\n")
	buf.WriteString("Subject: Binary Part\r\n")
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: multipart/mixed; boundary=\"mix\"\r\n\r\n")
	buf.WriteString("--mix\r\n")
	buf.WriteString("Content-Type: image/png\r\n")
	buf.WriteString("Content-Transfer-Encoding: binary\r\n")
	buf.WriteString("Content-ID: <bin1>\r\n\r\n")
	buf.Write(imgData)
	buf.WriteString("\r\n--mix\r\n")
	buf.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
	buf.WriteString("after binary\r\n")
	buf.WriteString("--mix--\r\n")

	email, err := ParseEmail(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}
	if email.TextBody != "after binary" {
		t.Errorf("TextBody = %q, want %q", email.TextBody, "after binary")
	}
	if len(email.EmbeddedFiles) != 1 {
		t.Fatalf("expected 1 embedded file, got %d", len(email.EmbeddedFiles))
	}
	gotData, err := io.ReadAll(email.EmbeddedFiles[0].Data)
	if err != nil {
		t.Fatalf("ReadAll(EmbeddedFiles[0].Data) error = %v", err)
	}
	if !bytes.Equal(gotData, imgData) {
		t.Errorf("EmbeddedFile Data = %x, want %x", gotData, imgData)
	}
}

func TestParseEmailMultipartMixedEmbeddedWithoutTransferEncoding(t *testing.T) {
	eml := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: CID Without CTE\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"mix\"\r\n" +
		"\r\n" +
		"--mix\r\n" +
		"Content-Type: image/svg+xml; name=\"badge.svg\"\r\n" +
		"Content-ID: <badge>\r\n" +
		"\r\n" +
		"<svg></svg>\r\n" +
		"--mix\r\n" +
		"Content-Type: text/plain; charset=\"utf-8\"\r\n" +
		"\r\n" +
		"after svg\r\n" +
		"--mix--\r\n"

	email, err := ParseEmail(bytes.NewReader([]byte(eml)))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}
	if email.TextBody != "after svg" {
		t.Errorf("TextBody = %q, want %q", email.TextBody, "after svg")
	}
	if len(email.Attachments) != 0 {
		t.Fatalf("expected 0 attachments, got %d", len(email.Attachments))
	}
	if len(email.EmbeddedFiles) != 1 {
		t.Fatalf("expected 1 embedded file, got %d", len(email.EmbeddedFiles))
	}
	if email.EmbeddedFiles[0].CID != "badge" {
		t.Errorf("EmbeddedFile CID = %q, want %q", email.EmbeddedFiles[0].CID, "badge")
	}
	gotData, err := io.ReadAll(email.EmbeddedFiles[0].Data)
	if err != nil {
		t.Fatalf("ReadAll(EmbeddedFiles[0].Data) error = %v", err)
	}
	if string(gotData) != "<svg></svg>" {
		t.Errorf("EmbeddedFile Data = %q, want %q", string(gotData), "<svg></svg>")
	}
}
