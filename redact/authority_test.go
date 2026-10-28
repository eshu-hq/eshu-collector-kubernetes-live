// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package redact

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorityReadsUserinfoFromDirectParse(t *testing.T) {
	t.Parallel()

	parsed, rewritten, err := Authority("https://user:pass@example.com/x")
	if err != nil {
		t.Fatalf("Authority() error = %v", err)
	}
	if rewritten {
		t.Fatal("rewritten = true, want false for a direct authority parse")
	}
	if parsed.User == nil {
		t.Fatal("parsed.User = nil, want the userinfo the URL spells")
	}
}

func TestAuthorityReparsesOpaqueBodiesShapedLikeAnAuthority(t *testing.T) {
	t.Parallel()

	// Without the "//" rewrite net/url reads scheme "svc" with the password
	// in Opaque and reports no credential at all.
	parsed, rewritten, err := Authority("svc:PASSWORD@h.internal:5432/tool")
	if err != nil {
		t.Fatalf("Authority() error = %v", err)
	}
	if !rewritten {
		t.Fatal("rewritten = false, want true for an opaque authority-shaped body")
	}
	if parsed.User == nil {
		t.Fatal("parsed.User = nil, want the password Authority re-parsed for")
	}
}

func TestAuthorityLeavesNonAuthorityOpaqueBodiesAlone(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"mcp:tool/name", "pkg:npm/lodash@4.17.21", "https://example.com/x"} {
		_, rewritten, err := Authority(value)
		if err != nil {
			t.Fatalf("Authority(%q) error = %v", value, err)
		}
		if rewritten {
			t.Fatalf("rewritten = true for %q, want the direct parse kept", value)
		}
	}
}

func TestAuthorityErrorsNeverRepeatTheValue(t *testing.T) {
	t.Parallel()

	const secret = "SECRET-HOST-7734"
	_, _, err := Authority("http://" + secret + ":badport/")
	if err == nil {
		t.Fatal("Authority() error = nil, want the bad port rejected")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error repeats the input host: %v", err)
	}
	if strings.Contains(err.Error(), "badport") {
		t.Fatalf("error repeats the input port: %v", err)
	}
}

func TestCarriesUserinfoFindsCredentialsInBothReadings(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"https://user:pass@example.com/x",
		"svc:PASSWORD@h.internal:5432/tool",
		"mailto:user@example.com",
	} {
		if !CarriesUserinfo(value) {
			t.Fatalf("CarriesUserinfo(%q) = false, want true", value)
		}
	}
}

func TestCarriesUserinfoClearsPlainValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"https://example.com/x",
		"mcp:tool/name",
		"pkg:npm/lodash@4.17.21",
	} {
		if CarriesUserinfo(value) {
			t.Fatalf("CarriesUserinfo(%q) = true, want false", value)
		}
	}
}

func TestCarriesUserinfoFailsClosedOnUnparseableValues(t *testing.T) {
	t.Parallel()

	if !CarriesUserinfo("http://example.com/\x7f") {
		t.Fatal("CarriesUserinfo(unparseable) = false, want fail-closed true")
	}
}

func TestOpaqueHasAuthorityReadsOnlyTheFirstSegment(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"":                false,
		"tool":            false,
		"PASSWORD@h:5432": true,
		"a@b/c":           true,
		"a/b@c":           false,
		"npm/lodash@4.17": false,
	}
	for opaque, want := range cases {
		if got := opaqueHasAuthority(opaque); got != want {
			t.Errorf("opaqueHasAuthority(%q) = %v, want %v", opaque, got, want)
		}
	}
}

func TestParseErrorReasonKeepsStaticMessages(t *testing.T) {
	t.Parallel()

	for _, msg := range []string{
		"missing protocol scheme",
		"empty url",
		"invalid URI for request",
		"first path segment in URL cannot contain colon",
		"net/url: invalid control character in URL",
		"net/url: invalid userinfo",
		"invalid IP-literal",
		"missing ']' in host",
	} {
		if got := ParseErrorReason(errors.New(msg)); got != msg {
			t.Errorf("ParseErrorReason(%q) = %q, want it verbatim", msg, got)
		}
	}
}

func TestParseErrorReasonStripsQuotedInput(t *testing.T) {
	t.Parallel()

	if got := ParseErrorReason(errors.New(`invalid port ":secret" after host`)); got != "invalid port after host" {
		t.Errorf("port reason = %q, want the fixed text", got)
	}
	if got := ParseErrorReason(errors.New(`invalid host: "secret-host"`)); got != "invalid host" {
		t.Errorf("host reason = %q, want the fixed text", got)
	}
	if got := ParseErrorReason(url.EscapeError("%zz")); got != "invalid URL escape" {
		t.Errorf("escape reason = %q, want the fixed text", got)
	}
	if got := ParseErrorReason(url.InvalidHostError("secrethost")); got != "invalid character in host name" {
		t.Errorf("host-char reason = %q, want the fixed text", got)
	}
}

func TestParseErrorReasonFailsClosedOnUnknownMessages(t *testing.T) {
	t.Parallel()

	if got := ParseErrorReason(errors.New("a message a future Go version adds")); got != "malformed URL" {
		t.Errorf("unknown reason = %q, want fail-closed malformed URL", got)
	}
}

func TestParseErrorReasonUnwrapsURLErrors(t *testing.T) {
	t.Parallel()

	inner := &url.Error{Op: "parse", URL: "http://secret/", Err: errors.New("empty url")}
	if got := ParseErrorReason(inner); got != "empty url" {
		t.Errorf("wrapped reason = %q, want the inner static message", got)
	}
}

func TestErrWithoutValueKeepsOperationWithoutInput(t *testing.T) {
	t.Parallel()

	// Built dynamically: a constant invalid URL trips SA1007, and the point
	// here is the runtime rebuild, not the parse.
	port := strings.TrimSpace("secretport")
	_, err := url.Parse("http://example.com:" + port + "/")
	if err == nil {
		t.Fatal("url.Parse() error = nil, want a bad-port failure to rebuild")
	}
	rebuilt := errWithoutValue(err)
	if strings.Contains(rebuilt.Error(), "secretport") {
		t.Fatalf("rebuilt error repeats the input port: %v", rebuilt)
	}
	if !strings.Contains(rebuilt.Error(), "parse") {
		t.Fatalf("rebuilt error drops the operation: %v", rebuilt)
	}
}

func TestErrWithoutValuePassesThroughNonURLErrors(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("boom")
	if errWithoutValue(sentinel) != sentinel {
		t.Fatal("errWithoutValue() rewrote a non-URL error")
	}
}
