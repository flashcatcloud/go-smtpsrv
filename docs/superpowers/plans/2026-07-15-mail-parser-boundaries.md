# Mail Parser Boundary Safety Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse complete RFC-style mail headers at their configured size limit, reject messages missing the header/body separator, and avoid allocations while validating ordinary headers.

**Architecture:** Keep the existing `ParseEmail` API and the `readMailMessage` pipeline. Permit two bytes beyond the configured header limit only to identify a CRLF separator, report an explicit error at EOF without a separator, and perform malformed-line filtering directly on byte slices so valid headers are returned unchanged.

**Tech Stack:** Go 1.13-compatible standard library APIs; existing `go test` and `go vet` checks.

## Global Constraints

- Preserve `ParseEmail` and `Context.Parse` public signatures.
- `maxHeaderBytes` counts header bytes and excludes the terminating blank-line separator.
- Missing separators must return `message is missing the header/body separator`.
- Header-limit errors must return `message header exceeds the %d-byte limit`.
- Do not add dependencies, options, compatibility shims, or new abstractions.
- Normal valid headers must not require string conversion or header reconstruction.

---

### Task 1: Lock down parser boundary behavior with regression tests

**Files:**
- Modify: `parser_regression_test.go`

**Interfaces:**
- Consumes: `ParseEmail(io.Reader, ...int) (*Email, error)` and `sanitizeMalformedHeaderLines([]byte) []byte`.
- Produces: Regression coverage for limit boundaries, malformed message rejection, and zero-allocation valid-header sanitization.

- [x] **Step 1: Write the failing tests**

```go
func TestParseEmailAcceptsHeaderAtConfiguredLimit(t *testing.T) {
	raw := "From: sender@example.com\\r\\n\\r\\nbody"
	msg, err := ParseEmail(bytes.NewReader([]byte(raw)), len("From: sender@example.com\\r\\n"))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}
	if msg.TextBody != "body" {
		t.Fatalf("TextBody = %q, want %q", msg.TextBody, "body")
	}
}

func TestParseEmailRejectsMessageWithoutHeaderBodySeparator(t *testing.T) {
	_, err := ParseEmail(bytes.NewReader([]byte("Subject: Test\\r\\nbody")), 65536)
	if err == nil || err.Error() != "message is missing the header/body separator" {
		t.Fatalf("ParseEmail() error = %v", err)
	}
}

func TestSanitizeMalformedHeaderLinesAvoidsAllocationsForValidHeader(t *testing.T) {
	header := []byte("From: sender@example.com\\r\\nSubject: Test\\r\\n")
	allocs := testing.AllocsPerRun(1000, func() {
		got := sanitizeMalformedHeaderLines(header)
		if !bytes.Equal(got, header) {
			t.Fatal("valid header was changed")
		}
	})
	if allocs != 0 {
		t.Fatalf("sanitizeMalformedHeaderLines() allocated %v times", allocs)
	}
}
```

- [x] **Step 2: Verify the tests fail for the intended regressions**

Run: `go test -run 'TestParseEmailAcceptsHeaderAtConfiguredLimit|TestParseEmailRejectsMessageWithoutHeaderBodySeparator|TestSanitizeMalformedHeaderLinesAvoidsAllocationsForValidHeader' -count=1 .`

Expected: the configured-limit test rejects the message, the missing-separator test receives no error, and the allocation test reports allocations.

### Task 2: Correct the bounded header reader and sanitize only malformed headers

**Files:**
- Modify: `parser.go:87-191`

**Interfaces:**
- Consumes: `readMailMessage`, `readRawMessageHeader`, and `sanitizeMalformedHeaderLines` from the existing parser pipeline.
- Produces: Header-boundary-aware reads, explicit missing-separator errors, and allocation-free valid-header sanitation.

- [x] **Step 1: Update the bounded reader and EOF handling**

```go
limitedHeaderReader := &io.LimitedReader{R: r, N: int64(headerLimit) + 2}
```

```go
if readErr == io.EOF {
	return nil, nil, fmt.Errorf("message is missing the header/body separator")
}
```

- [x] **Step 2: Replace string-based sanitation with byte-slice processing**

```go
func sanitizeMalformedHeaderLines(header []byte) []byte {
	var sanitized []byte
	previousLineValid := false

	for start := 0; start < len(header); {
		end := bytes.IndexByte(header[start:], '\\n')
		if end < 0 {
			end = len(header)
		} else {
			end += start + 1
		}
		line := header[start:end]
		isContinuation := len(line) > 0 && (line[0] == ' ' || line[0] == '\\t')
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
```

- [x] **Step 3: Run the focused regression tests**

Run: `go test -run 'TestParseEmailAcceptsHeaderAtConfiguredLimit|TestParseEmailRejectsMessageWithoutHeaderBodySeparator|TestSanitizeMalformedHeaderLinesAvoidsAllocationsForValidHeader|TestParseEmailToleratesMalformedSpamHeaderFragments|TestParseEmailDropsMalformedHeaderContinuations' -count=1 .`

Expected: PASS.

### Task 3: Format, validate, and commit the focused change

**Files:**
- Modify: `.gitignore`
- Modify: `parser.go`
- Modify: `parser_regression_test.go`
- Create: `docs/superpowers/plans/2026-07-15-mail-parser-boundaries.md`

**Interfaces:**
- Consumes: completed parser behavior from Tasks 1 and 2.
- Produces: a formatted, validated branch commit with the local worktree directory ignored.

- [x] **Step 1: Add the worktree directory to `.gitignore`**

```gitignore
.worktrees/
```

- [x] **Step 2: Format the Go code**

Run: `make`, then `gofmt -w parser.go parser_regression_test.go` because this repository has no Makefile.

Expected: `make` reports the missing Makefile; `gofmt` formats only the planned Go files.

- [x] **Step 3: Run validation**

Run: `go test ./... -count=1 && go vet ./... && git diff --check`

Expected: all package tests pass, `go vet` emits no diagnostics, and the diff has no whitespace errors.

- [x] **Step 4: Review the final diff and commit**

Run: `git diff -- parser.go parser_regression_test.go .gitignore docs/superpowers/plans/2026-07-15-mail-parser-boundaries.md && git status --short`

Expected: only the planned files are changed.

Run: `git add .gitignore parser.go parser_regression_test.go docs/superpowers/plans/2026-07-15-mail-parser-boundaries.md && git commit -m "fix: enforce mail header boundaries"`

Expected: one focused commit without agent co-author trailers.
