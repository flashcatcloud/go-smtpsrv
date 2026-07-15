package smtpsrv

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"golang.org/x/text/encoding/charmap"
)

var (
	invalidQPTrailingEquals       = regexp.MustCompile(`=([^0-9A-Fa-f\r\n]|[0-9A-Fa-f]$|$)`)
	invalidQPTerminalSoftLineFeed = regexp.MustCompile(`=\r?\n?$`)
)

const (
	contentTypeMultipartMixed       = "multipart/mixed"
	contentTypeMultipartAlternative = "multipart/alternative"
	contentTypeMultipartRelated     = "multipart/related"
	contentTypeTextHtml             = "text/html"
	contentTypeTextPlain            = "text/plain"
	contentTypeTextEnriched         = "text/enriched"
)

// Parse an email message read from io.Reader into parsemail.Email struct
func ParseEmail(r io.Reader, maxHeaderBytes ...int) (email *Email, err error) {
	var msg *mail.Message
	msg, err = readMailMessage(r, maxHeaderBytes...)
	if err != nil {
		return
	}

	email, err = createEmailFromHeader(msg.Header)
	if err != nil {
		return
	}

	email.ContentType = msg.Header.Get("Content-Type")
	contentType, params, err := parseContentType(email.ContentType)
	if err != nil {
		return
	}

	switch contentType {
	case contentTypeMultipartMixed:
		email.TextBody, email.HTMLBody, email.Attachments, email.EmbeddedFiles, err = parseMultipartMixed(msg.Body, params["boundary"])
	case contentTypeMultipartAlternative:
		email.TextBody, email.HTMLBody, email.EmbeddedFiles, err = parseMultipartAlternative(msg.Body, params["boundary"])
	case contentTypeMultipartRelated:
		email.TextBody, email.HTMLBody, email.EmbeddedFiles, err = parseMultipartRelated(msg.Body, params["boundary"])
	case contentTypeTextPlain, contentTypeTextEnriched:
		newPart, err := decodeContent(msg.Body, msg.Header.Get("Content-Transfer-Encoding"), msg.Header.Get("Content-Type"))
		if err != nil {
			return email, err
		}

		message, _ := io.ReadAll(newPart)
		email.TextBody = strings.TrimSuffix(string(message[:]), "\n")
	case contentTypeTextHtml:
		newPart, err := decodeContent(msg.Body, msg.Header.Get("Content-Transfer-Encoding"), msg.Header.Get("Content-Type"))
		if err != nil {
			return email, err
		}

		message, err := io.ReadAll(newPart)
		if err != nil {
			return email, err
		}

		email.HTMLBody = strings.TrimSuffix(string(message[:]), "\n")
	default:
		email.Content, err = decodeContent(msg.Body, msg.Header.Get("Content-Transfer-Encoding"), msg.Header.Get("Content-Type"))
	}

	return
}

func readMailMessage(r io.Reader, maxHeaderBytes ...int) (*mail.Message, error) {
	readerSize := 4096
	headerLimit := 0
	if len(maxHeaderBytes) > 0 && maxHeaderBytes[0] > 0 {
		readerSize = maxHeaderBytes[0]
		headerLimit = maxHeaderBytes[0]
	}

	headerReader := r
	if headerLimit > 0 {
		limitedHeaderReader := &io.LimitedReader{R: r, N: int64(headerLimit) + 2}
		headerReader = limitedHeaderReader
	}

	br := bufio.NewReaderSize(headerReader, readerSize)
	bodyReader := io.Reader(br)
	if headerLimit > 0 {
		bodyReader = io.MultiReader(br, r)
	}

	header, sep, err := readRawMessageHeader(br, headerLimit)
	if err != nil {
		return nil, err
	}

	header = sanitizeMalformedHeaderLines(header)
	rawMessage := io.MultiReader(bytes.NewReader(header), bytes.NewReader(sep), bodyReader)
	return mail.ReadMessage(rawMessage)
}

func readRawMessageHeader(r *bufio.Reader, maxHeaderBytes int) (header, sep []byte, err error) {
	for {
		line, readErr := r.ReadSlice('\n')
		if len(line) > 0 {
			if readErr != bufio.ErrBufferFull && isMessageHeaderSeparator(line) {
				return header, line, nil
			}

			header = append(header, line...)
			if maxHeaderBytes > 0 && len(header) > maxHeaderBytes {
				return nil, nil, fmt.Errorf("message header exceeds the %d-byte limit", maxHeaderBytes)
			}
		}

		if readErr != nil {
			if readErr == bufio.ErrBufferFull {
				continue
			}
			if readErr == io.EOF {
				return nil, nil, fmt.Errorf("message is missing the blank line between the header and body")
			}
			return nil, nil, readErr
		}
	}
}

func isMessageHeaderSeparator(line []byte) bool {
	return bytes.Equal(line, []byte("\n")) || bytes.Equal(line, []byte("\r\n"))
}

func sanitizeMalformedHeaderLines(header []byte) []byte {
	var sanitized []byte
	previousLineValid := false

	for start := 0; start < len(header); {
		end := bytes.IndexByte(header[start:], '\n')
		if end < 0 {
			end = len(header)
		} else {
			end += start + 1
		}

		line := header[start:end]
		isContinuation := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
		valid := isContinuation && previousLineValid
		if !isContinuation {
			valid = bytes.IndexByte(line, ':') >= 0
		}

		if !valid {
			if sanitized == nil {
				sanitized = make([]byte, 0, len(header))
				sanitized = append(sanitized, header[:start]...)
			}
		} else if sanitized != nil {
			sanitized = append(sanitized, line...)
		}

		previousLineValid = valid
		start = end
	}

	if sanitized == nil {
		return header
	}
	return sanitized
}

func createEmailFromHeader(header mail.Header) (email *Email, err error) {
	hp := headerParser{header: &header}

	email = &Email{}
	email.Subject = decodeMimeSentence(header.Get("Subject"))
	email.From = hp.parseAddressList(header.Get("From"))
	email.Sender = hp.parseAddress(header.Get("Sender"))
	email.ReplyTo = hp.parseAddressList(header.Get("Reply-To"))
	email.To = hp.parseAddressList(header.Get("To"))
	email.Cc = hp.parseAddressList(header.Get("Cc"))
	email.Bcc = hp.parseAddressList(header.Get("Bcc"))
	email.Date = hp.parseTime(header.Get("Date"))
	email.ResentFrom = hp.parseAddressList(header.Get("Resent-From"))
	email.ResentSender = hp.parseAddress(header.Get("Resent-Sender"))
	email.ResentTo = hp.parseAddressList(header.Get("Resent-To"))
	email.ResentCc = hp.parseAddressList(header.Get("Resent-Cc"))
	email.ResentBcc = hp.parseAddressList(header.Get("Resent-Bcc"))
	email.ResentMessageID = hp.parseMessageId(header.Get("Resent-Message-ID"))
	email.MessageID = hp.parseMessageId(header.Get("Message-ID"))
	email.InReplyTo = hp.parseMessageIdList(header.Get("In-Reply-To"))
	email.References = hp.parseMessageIdList(header.Get("References"))
	email.ResentDate = hp.parseTime(header.Get("Resent-Date"))

	if hp.err != nil {
		err = hp.err
		return
	}

	// decode whole header for easier access to extra fields
	// todo: should we decode? aren't only standard fields mime encoded?
	email.Header, err = decodeHeaderMime(header)
	if err != nil {
		return
	}

	return
}

func parseContentType(contentTypeHeader string) (contentType string, params map[string]string, err error) {
	if contentTypeHeader == "" {
		contentType = contentTypeTextPlain
		return
	}

	return mime.ParseMediaType(contentTypeHeader)
}

func parseMultipartRelated(msg io.Reader, boundary string) (textBody, htmlBody string, embeddedFiles []EmbeddedFile, err error) {
	pmr := multipart.NewReader(msg, boundary)
	for {
		part, err := pmr.NextRawPart()

		if err == io.EOF {
			break
		} else if err != nil {
			return textBody, htmlBody, embeddedFiles, err
		}

		contentType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			return textBody, htmlBody, embeddedFiles, err
		}

		switch contentType {
		case contentTypeTextPlain, contentTypeTextEnriched:
			newPart, err := decodeContent(part, part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-Type"))
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			ppContent, err := io.ReadAll(newPart)
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			textBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		case contentTypeTextHtml:
			newPart, err := decodeContent(part, part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-Type"))
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			ppContent, err := io.ReadAll(newPart)
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			htmlBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		case contentTypeMultipartAlternative:
			tb, hb, ef, err := parseMultipartAlternative(part, params["boundary"])
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			htmlBody += hb
			textBody += tb
			embeddedFiles = append(embeddedFiles, ef...)
		default:
			if isEmbeddedFile(part) {
				ef, err := decodeEmbeddedFile(part)
				if err != nil {
					return textBody, htmlBody, embeddedFiles, err
				}

				embeddedFiles = append(embeddedFiles, ef)
			} else {
				return textBody, htmlBody, embeddedFiles, fmt.Errorf("can't process multipart/related inner mime type: %s", contentType)
			}
		}
	}

	return textBody, htmlBody, embeddedFiles, err
}

func decodeCharset(content io.Reader, contentTypeWithCharset string) io.Reader {
	charset := "default"
	if strings.Contains(contentTypeWithCharset, "; charset=") {
		split := strings.Split(contentTypeWithCharset, "; charset=")
		charset = strings.Trim(split[1], " \"'\n\r")
	}

	tr := content
	if charset != "default" {
		switch charset {
		case "Windows-1252":
			tr = charmap.Windows1252.NewDecoder().Reader(content)
		case "iso-8859-1", "ISO-8859-1":
			tr = charmap.ISO8859_1.NewDecoder().Reader(content)
		default:
		}
	}

	return tr
}

func parseMultipartAlternative(msg io.Reader, boundary string) (textBody, htmlBody string, embeddedFiles []EmbeddedFile, err error) {
	pmr := multipart.NewReader(msg, boundary)
	for {
		part, err := pmr.NextRawPart()

		if err == io.EOF {
			break
		} else if err != nil {
			return textBody, htmlBody, embeddedFiles, err
		}

		contentType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			return textBody, htmlBody, embeddedFiles, err
		}

		switch contentType {
		case contentTypeTextPlain, contentTypeTextEnriched:
			newPart, err := decodeContent(part, part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-Type"))
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			ppContent, err := io.ReadAll(newPart)
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			textBody += strings.TrimSuffix(string(ppContent[:]), "\n")

		case contentTypeTextHtml:
			newPart, err := decodeContent(part, part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-Type"))
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			ppContent, err := io.ReadAll(newPart)
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			htmlBody += strings.TrimSuffix(string(ppContent[:]), "\n")

		case contentTypeMultipartRelated:
			tb, hb, ef, err := parseMultipartRelated(part, params["boundary"])
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			htmlBody += hb
			textBody += tb
			embeddedFiles = append(embeddedFiles, ef...)

		default:
			if isEmbeddedFile(part) {
				ef, err := decodeEmbeddedFile(part)
				if err != nil {
					return textBody, htmlBody, embeddedFiles, err
				}

				embeddedFiles = append(embeddedFiles, ef)
			} else {
				return textBody, htmlBody, embeddedFiles, fmt.Errorf("can't process multipart/alternative inner mime type: %s", contentType)
			}
		}
	}

	return textBody, htmlBody, embeddedFiles, err
}

func parseMultipartMixed(msg io.Reader, boundary string) (textBody, htmlBody string, attachments []Attachment, embeddedFiles []EmbeddedFile, err error) {
	mr := multipart.NewReader(msg, boundary)
	for {
		part, err := mr.NextRawPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return textBody, htmlBody, attachments, embeddedFiles, err
		}

		contentType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			return textBody, htmlBody, attachments, embeddedFiles, err
		}

		if contentType == contentTypeMultipartMixed {
			nestedText, nestedHtml, nestedAttachments, nestedEmbedded, err := parseMultipartMixed(part, params["boundary"])
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, err
			}

			textBody += nestedText
			htmlBody += nestedHtml
			attachments = append(attachments, nestedAttachments...)
			embeddedFiles = append(embeddedFiles, nestedEmbedded...)
		} else if contentType == contentTypeMultipartAlternative {
			textBody, htmlBody, embeddedFiles, err = parseMultipartAlternative(part, params["boundary"])
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, err
			}
		} else if contentType == contentTypeMultipartRelated {
			textBody, htmlBody, embeddedFiles, err = parseMultipartRelated(part, params["boundary"])
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, err
			}
		} else if contentType == contentTypeTextPlain || contentType == contentTypeTextEnriched {
			newPart, err := decodeContent(part, part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-Type"))
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, err
			}

			ppContent, err := io.ReadAll(newPart)
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, err
			}

			textBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		} else if contentType == contentTypeTextHtml {
			newPart, err := decodeContent(part, part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-Type"))
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, err
			}

			ppContent, err := io.ReadAll(newPart)
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, err
			}

			htmlBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		} else if isAttachment(part) {
			at, err := decodeAttachment(part)
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, err
			}

			attachments = append(attachments, at)
		} else {
			return textBody, htmlBody, attachments, embeddedFiles, fmt.Errorf("unknown multipart/mixed nested mime type: %s", contentType)
		}
	}

	return textBody, htmlBody, attachments, embeddedFiles, err
}

func decodeMimeSentence(s string) string {
	result := []string{}
	ss := strings.Split(s, " ")

	for _, word := range ss {
		dec := new(mime.WordDecoder)
		w, err := dec.Decode(word)
		if err != nil {
			if len(result) == 0 {
				w = word
			} else {
				w = " " + word
			}
		}

		result = append(result, w)
	}

	return strings.Join(result, "")
}

func decodeHeaderMime(header mail.Header) (mail.Header, error) {
	parsedHeader := map[string][]string{}

	for headerName, headerData := range header {

		parsedHeaderData := []string{}
		for _, headerValue := range headerData {
			parsedHeaderData = append(parsedHeaderData, decodeMimeSentence(headerValue))
		}

		parsedHeader[headerName] = parsedHeaderData
	}

	return mail.Header(parsedHeader), nil
}

func isEmbeddedFile(part *multipart.Part) bool {
	return part.Header.Get("Content-Transfer-Encoding") != ""
}

func decodeEmbeddedFile(part *multipart.Part) (ef EmbeddedFile, err error) {
	cid := decodeMimeSentence(part.Header.Get("Content-Id"))
	decoded, err := decodeContent(part, part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-Type"))
	if err != nil {
		return
	}

	ef.CID = strings.Trim(cid, "<>")
	ef.Data = decoded
	ef.ContentType = part.Header.Get("Content-Type")

	return
}

func isAttachment(part *multipart.Part) bool {
	return part.FileName() != ""
}

func decodeAttachment(part *multipart.Part) (at Attachment, err error) {
	filename := decodeMimeSentence(part.FileName())
	decoded, err := decodeContent(part, part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-Type"))
	if err != nil {
		return
	}

	at.Filename = filename
	at.Data = decoded
	at.ContentType = strings.Split(part.Header.Get("Content-Type"), ";")[0]

	return
}

func decodeContent(content io.Reader, encoding string, contentTypeWithCharset string) (io.Reader, error) {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	switch encoding {
	case "base64":
		raw, err := io.ReadAll(content)
		if err != nil {
			return nil, err
		}

		b, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(raw)))
		if err != nil {
			// Lenient retry: strip all non-base64 characters (spaces, tabs, etc.)
			// Many mailers produce non-RFC-compliant base64 with stray whitespace.
			cleaned := sanitizeBase64(raw)
			b, err = io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(cleaned)))
			if err != nil {
				b = raw
			}
		}

		return decodeCharset(bytes.NewReader(b), contentTypeWithCharset), nil

	case "7bit", "8bit":
		dd, err := io.ReadAll(content)
		if err != nil {
			return nil, err
		}

		return decodeCharset(bytes.NewReader(dd), contentTypeWithCharset), nil

	case "quoted-printable":
		raw, err := io.ReadAll(content)
		if err != nil {
			return nil, err
		}
		sanitized := sanitizeQuotedPrintable(raw)
		decoded := quotedprintable.NewReader(bytes.NewReader(sanitized))
		b, err := io.ReadAll(decoded)
		if err != nil {
			b = raw
		}
		return decodeCharset(bytes.NewReader(b), contentTypeWithCharset), nil

	default:
		return decodeCharset(content, contentTypeWithCharset), nil
	}
}

type headerParser struct {
	header *mail.Header
	err    error
}

func (hp headerParser) parseAddress(s string) (ma *mail.Address) {
	if hp.err != nil {
		return nil
	}

	if strings.Trim(s, " \n") != "" {
		ma, hp.err = mail.ParseAddress(s)
		return ma
	}

	return nil
}

func (hp headerParser) parseAddressList(s string) (ma []*mail.Address) {
	if hp.err != nil {
		return
	}

	if strings.Trim(s, " \n") != "" {
		ma, hp.err = mail.ParseAddressList(s)
		return
	}

	return
}

func (hp headerParser) parseTime(s string) (t time.Time) {
	if hp.err != nil || s == "" {
		return
	}

	formats := []string{
		time.RFC1123Z,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		time.RFC1123Z + " (MST)",
		"Mon, 2 Jan 2006 15:04:05 -0700 (MST)",
	}

	for _, format := range formats {
		t, hp.err = time.Parse(format, s)
		if hp.err == nil {
			return
		}
	}

	return
}

func (hp headerParser) parseMessageId(s string) string {
	if hp.err != nil {
		return ""
	}

	return strings.Trim(s, "<> ")
}

func (hp headerParser) parseMessageIdList(s string) (result []string) {
	if hp.err != nil {
		return
	}

	for _, p := range strings.Split(s, " ") {
		if strings.Trim(p, " \n") != "" {
			result = append(result, hp.parseMessageId(p))
		}
	}

	return
}

// Attachment with filename, content type and data (as a io.Reader)
type Attachment struct {
	Filename    string
	ContentType string
	Data        io.Reader
}

// EmbeddedFile with content id, content type and data (as a io.Reader)
type EmbeddedFile struct {
	CID         string
	ContentType string
	Data        io.Reader
}

// Email with fields for all the headers defined in RFC5322 with it's attachments and
type Email struct {
	Header mail.Header

	Subject    string
	Sender     *mail.Address
	From       []*mail.Address
	ReplyTo    []*mail.Address
	To         []*mail.Address
	Cc         []*mail.Address
	Bcc        []*mail.Address
	Date       time.Time
	MessageID  string
	InReplyTo  []string
	References []string

	ResentFrom      []*mail.Address
	ResentSender    *mail.Address
	ResentTo        []*mail.Address
	ResentDate      time.Time
	ResentCc        []*mail.Address
	ResentBcc       []*mail.Address
	ResentMessageID string

	ContentType string
	Content     io.Reader

	HTMLBody string
	TextBody string

	Attachments   []Attachment
	EmbeddedFiles []EmbeddedFile
}

func sanitizeBase64(data []byte) []byte {
	buf := make([]byte, 0, len(data))
	for _, b := range data {
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
			(b >= '0' && b <= '9') || b == '+' || b == '/' || b == '=' {
			buf = append(buf, b)
		}
	}
	return buf
}

func sanitizeQuotedPrintable(data []byte) []byte {
	data = invalidQPTerminalSoftLineFeed.ReplaceAll(data, []byte("=3D"))
	return invalidQPTrailingEquals.ReplaceAllFunc(data, func(match []byte) []byte {
		if len(match) == 1 {
			return []byte("=3D")
		}
		return append([]byte("=3D"), match[1:]...)
	})
}
