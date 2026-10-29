package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mathewcsims/protoxide/protonmail"
)

const realisticToken = "2R8-YlJOJEwkNaN7KQPevuu-:cW0tgjruefGlj2M9QlDMDGXWVfnqJj6UlORG2xP5kjAiV7aaaaaaaabbbbbbbbcccccccc"

// The workstation helper serves the same page as the running bridge and must accept
// what the real CAPTCHA logs: two HV lines, of which only the pm_captcha one is right.
func TestWorkstationHelperServesTheSharedPageAndAcceptsBothLines(t *testing.T) {
	urls := make(chan string, 1)
	old := openBrowser
	openBrowser = func(u string) { urls <- u }
	defer func() { openBrowser = old }()

	type result struct {
		token, kind string
		err         error
	}
	done := make(chan result, 1)
	go func() {
		tok, kind, err := solveHumanVerification(&protonmail.HumanVerificationDetails{
			HumanVerificationMethods: []string{"captcha"}, HumanVerificationToken: "ProtonChallenge"})
		done <- result{tok, kind, err}
	}()

	var base string
	select {
	case base = <-urls:
	case <-time.After(5 * time.Second):
		t.Fatal("the helper never opened the browser")
	}

	resp, err := http.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := string(page)
	for _, need := range []string{"prefers-color-scheme:dark", `<meta name="color-scheme" content="light dark">`, "pm_captcha", "Token=ProtonChallenge"} {
		if !strings.Contains(body, need) {
			t.Errorf("page lacks %q (it should be the shared, dark-mode-aware page)", need)
		}
	}
	if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Error("the helper page must carry the shared security headers")
	}
	nonce := between(body, `name="nonce" value="`, `"`)
	if nonce == "" {
		t.Fatal("no nonce on the page")
	}

	post := func(n, input string) (int, string) {
		r, err := http.PostForm(base, url.Values{"nonce": {n}, "input": {input}})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		return r.StatusCode, string(b)
	}

	if code, _ := post("not-the-nonce", realisticToken); code != 400 {
		t.Errorf("a wrong nonce must be refused, got %d", code)
	}
	first := `HV {"type":"proton_captcha","token":"` + strings.Repeat("ab12cd34", 8) + `","protoncaptcha":true} debugger eval code:1:68`
	if code, msg := post(nonce, first); code != 400 || !strings.Contains(msg, "pm_captcha") {
		t.Errorf("a lone proton_captcha line must be refused with guidance, got %d", code)
	}
	select {
	case r := <-done:
		t.Fatalf("the helper returned too early: %+v", r)
	default:
	}

	second := `HV {"type":"pm_captcha","token":"` + realisticToken + `"} debugger eval code:1:68`
	if code, _ := post(nonce, first+"\n"+second); code != 200 {
		t.Fatalf("pasting both lines must work, got %d", code)
	}
	select {
	case r := <-done:
		if r.err != nil || r.token != realisticToken || r.kind != "captcha" {
			t.Errorf("returned %q (%s), %v; want the pm_captcha token", r.token, r.kind, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the helper did not return the token")
	}
}

func TestWorkstationHelperRejectsUnsupportedMethods(t *testing.T) {
	_, _, err := solveHumanVerification(&protonmail.HumanVerificationDetails{HumanVerificationMethods: []string{"sms"}})
	if err == nil || !strings.Contains(err.Error(), "no supported verification method") {
		t.Errorf("got %v", err)
	}
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	if j := strings.Index(s, b); j >= 0 {
		return s[:j]
	}
	return ""
}
