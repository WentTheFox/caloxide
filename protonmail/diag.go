package protonmail

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// When Proton answers with something we did not expect, the log gets its status,
// headers and body, so the case can be understood and handled later. Those carry
// credentials and personal data, so what is logged is bounded and redacted: see
// redactBody and redactedHeaders.
const (
	// diagBodyMax is how much of a body is logged.
	diagBodyMax = 4096
	// diagStringMax is the longest JSON string value logged verbatim. Tokens, keys and
	// the PGP-armoured calendar cards are all longer; ids, codes and messages are not.
	diagStringMax = 80
)

// secretHeaders are never logged. Matching is case-insensitive.
var secretHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-pm-uid":            true, // identifies the session
}

// secretKeys are JSON fields whose value is blanked whatever its length.
var secretKeys = regexp.MustCompile(`(?i)"(AccessToken|RefreshToken|ServerProof|ClientProof|ClientEphemeral|ServerEphemeral|SrpSession|Token|HumanVerificationToken|TwoFactorCode|Password|KeySalt|Salt|Verifier|Modulus|PrivateKey|Passphrase|UID|Cookie|Authorization)"\s*:\s*"(?:[^"\\]|\\.)*"`)

var longString = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)

// redactBody shortens a response body for the log. JSON loses its secret fields and any
// long string; other bodies (an HTML error page, say) are only truncated.
func redactBody(body []byte) string {
	s := string(body)
	if json.Valid(body) {
		s = secretKeys.ReplaceAllString(s, `"$1":"[redacted]"`)
		s = longString.ReplaceAllStringFunc(s, func(m string) string {
			if n := len(m) - 2; n > diagStringMax {
				return `"[` + strconv.Itoa(n) + ` chars]"`
			}
			return m
		})
	}
	if len(s) > diagBodyMax {
		return s[:diagBodyMax] + fmt.Sprintf("...[%d more bytes]", len(s)-diagBodyMax)
	}
	return s
}

// redactedHeaders renders the headers sorted by name, secrets blanked.
func redactedHeaders(h http.Header) string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	var parts []string
	for _, name := range names {
		v := strings.Join(h[name], ", ")
		if secretHeaders[strings.ToLower(name)] {
			v = "[redacted]"
		}
		parts = append(parts, name+"="+v)
	}
	return strings.Join(parts, "; ")
}

// readBounded reads at most diagBodyMax+1 bytes of a body that is about to be dropped.
func readBounded(r io.Reader) []byte {
	b, _ := io.ReadAll(io.LimitReader(r, diagBodyMax+1))
	return b
}

// logUnexpected writes one log line describing a response we did not expect. Only the
// request path is logged, never its query string.
func logUnexpected(req *http.Request, resp *http.Response, body []byte, why string) {
	log.Printf("unexpected response: why=%q method=%s path=%s status=%d headers=%q body=%q",
		why, req.Method, req.URL.Path, resp.StatusCode, redactedHeaders(resp.Header), redactBody(body))
}

// unexpectedStatus says why an HTTP status deserves a closer look, or "" if it is part
// of the normal flow. 401 is the token refresh and 422 carries Proton's own error
// envelope (wrong password, human verification, ...), both handled and logged elsewhere.
func unexpectedStatus(status int) string {
	switch {
	case status >= 200 && status < 300, status == http.StatusUnauthorized, status == http.StatusUnprocessableEntity:
		return ""
	case status >= 500:
		return "server error"
	case status >= 300 && status < 400:
		return "redirect"
	default:
		return "unexpected status"
	}
}
