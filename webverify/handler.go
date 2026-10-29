// Package webverify serves the page on which a person answers Proton's CAPTCHA for a
// running bridge, and the local control socket used to open it. The page exists only
// inside a verification window (see auth.Manager.OpenVerificationWindow): every other
// request, with any other token or none, gets a plain 404, so nothing reveals that
// the route exists.
package webverify

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/mathewcsims/protoxide/auth"
)

// PathPrefix is where the page lives: PathPrefix + <one-time token>.
const PathPrefix = "/verify/"

const maxFormBytes = 64 << 10

// Verifier is the part of auth.Manager the page needs.
type Verifier interface {
	VerificationWindowOpen(token string) bool
	BeginVerification(token string) (*auth.Challenge, error)
	CompleteVerification(token, nonce, input string) error
}

// Handler serves PathPrefix + token. Mount it for the PathPrefix subtree only.
func Handler(v Verifier) http.Handler { return &handler{v: v} }

type handler struct{ v Verifier }

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, PathPrefix)
	if token == r.URL.Path || token == "" || strings.Contains(token, "/") || !h.v.VerificationWindowOpen(token) {
		http.NotFound(w, r)
		return
	}
	cspNonce := setSecurityHeaders(w)

	switch r.Method {
	case http.MethodGet:
		h.show(w, r, token, cspNonce)
	case http.MethodPost:
		h.submit(w, r, token, cspNonce)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func setSecurityHeaders(w http.ResponseWriter) (cspNonce string) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the system RNG failing is not recoverable
	}
	cspNonce = base64.RawURLEncoding.EncodeToString(b)
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer") // the URL contains the one-time token
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+cspNonce+"'; style-src 'nonce-"+cspNonce+
		"'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("Content-Type", "text/html; charset=utf-8")
	return cspNonce
}

func (h *handler) show(w http.ResponseWriter, r *http.Request, token, cspNonce string) {
	ch, err := h.v.BeginVerification(token)
	switch {
	case errors.Is(err, auth.ErrNoWindow):
		http.NotFound(w, r)
	case errors.Is(err, auth.ErrNotWaiting):
		render(w, http.StatusOK, messageTmpl, message{CSP: cspNonce, Title: "Nothing to verify", Body: "The bridge is not waiting for human verification."})
	case err != nil:
		render(w, http.StatusBadGateway, messageTmpl, message{CSP: cspNonce, Title: "Could not start verification", Body: err.Error()})
	case ch.Done:
		render(w, http.StatusOK, messageTmpl, message{CSP: cspNonce, Title: "Logged in", Body: "Proton did not ask for a CAPTCHA this time and the bridge is logged in again. You can close this tab."})
	default:
		render(w, http.StatusOK, pageTmpl, page{CSP: cspNonce, Nonce: ch.Nonce, PopupURL: popupURL(ch.Token)})
	}
}

func (h *handler) submit(w http.ResponseWriter, r *http.Request, token, cspNonce string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		render(w, http.StatusRequestEntityTooLarge, messageTmpl, message{CSP: cspNonce, Title: "Request too large", Body: "That was not a verification token."})
		return
	}
	err := h.v.CompleteVerification(token, r.PostForm.Get("nonce"), r.PostForm.Get("input"))
	switch {
	case err == nil:
		render(w, http.StatusOK, messageTmpl, message{CSP: cspNonce, Title: "Verified", Body: "The bridge is logged in again. You can close this tab; nothing else needs restarting."})
	case errors.Is(err, auth.ErrNoWindow):
		http.NotFound(w, r)
	case errors.Is(err, auth.ErrNoToken), errors.Is(err, auth.ErrWrongMessage):
		render(w, http.StatusBadRequest, messageTmpl, message{CSP: cspNonce, Title: "No token found", Body: err.Error() + ". Use your browser's Back button and paste the whole console line again."})
	case errors.Is(err, auth.ErrChallengeExpired), errors.Is(err, auth.ErrVerificationRejected):
		render(w, http.StatusBadRequest, messageTmpl, message{CSP: cspNonce, Title: "Start again", Body: err.Error() + ". Reload this page (the same link) to get a fresh challenge."})
	default:
		render(w, http.StatusBadGateway, messageTmpl, message{CSP: cspNonce, Title: "Verification failed", Body: err.Error()})
	}
}

// The functions below let other front ends (the local helper that `protoxide auth`
// runs on a workstation) serve exactly the same page: one design, one security
// policy, one dark-mode implementation, one place to fix.

// PageData is what the challenge page needs.
type PageData struct {
	// Nonce ties the submitted form to this page; the caller verifies it.
	Nonce string
	// PopupURL is the CAPTCHA popup address, from PopupURL.
	PopupURL string
}

// PopupURL is Proton's CAPTCHA page for a human-verification challenge token.
func PopupURL(challengeToken string) string { return popupURL(challengeToken) }

// WriteChallenge writes the challenge page, with the standard security headers. The
// form posts back to the same URL with fields "nonce" and "input".
func WriteChallenge(w http.ResponseWriter, d PageData) {
	csp := setSecurityHeaders(w)
	render(w, http.StatusOK, pageTmpl, page{CSP: csp, Nonce: d.Nonce, PopupURL: d.PopupURL})
}

// WriteMessage writes a small status page in the same style.
func WriteMessage(w http.ResponseWriter, status int, title, body string) {
	csp := setSecurityHeaders(w)
	render(w, status, messageTmpl, message{CSP: csp, Title: title, Body: body})
}

// popupURL is Proton's CAPTCHA page for a challenge token. The page adds &Dark=true
// itself when the browser reports a dark colour scheme.
func popupURL(token string) string {
	return "https://verify-api.proton.me/core/v4/captcha?Token=" + url.QueryEscape(token) + "&ForceWebMessaging=1"
}

// Why the page cannot simply listen for the result: Proton's CAPTCHA reports with
// window.parent.postMessage({type:"pm_captcha", token:"<id>:<response>"}, '*'). That
// is written for an iframe; in a popup window.parent is the popup itself, not the
// window that opened it, and the page refuses to be framed by anyone but
// verify.proton.me (frame-ancestors). So the message can only be caught inside the
// popup, by a snippet pasted into its console. That snippet logs the message (the
// copy-paste fallback) and also relays the token to this page's window.opener, which
// accepts it only from the popup it opened.

type page struct {
	CSP, Nonce, PopupURL string
}

type message struct{ CSP, Title, Body string }

func render(w http.ResponseWriter, status int, t *template.Template, data any) {
	w.WriteHeader(status)
	if err := t.Execute(w, data); err != nil {
		fmt.Fprint(w, "error rendering page")
	}
}

// style follows the browser's colour scheme (prefers-color-scheme) with no script:
// colours are variables, the dark palette replaces them under the media query, and
// color-scheme lets the browser theme the native controls (buttons, scrollbars).
const style = `:root{color-scheme:light dark;--bg:#fff;--fg:#1a1a1a;--muted:#555;--code-bg:#eee;--field-bg:#fff;--border:#767676}
@media (prefers-color-scheme:dark){:root{--bg:#121212;--fg:#e6e6e6;--muted:#a6a6a6;--code-bg:#232323;--field-bg:#1c1c1c;--border:#8c8c8c}}
body{font-family:system-ui,sans-serif;max-width:640px;margin:2rem auto;padding:0 1rem;line-height:1.5;background:var(--bg);color:var(--fg)}
code,textarea,pre{font-family:ui-monospace,monospace;font-size:.85rem}
code{background:var(--code-bg);padding:.05rem .3rem;border-radius:3px}
textarea{width:100%;box-sizing:border-box;height:7rem;background:var(--field-bg);color:var(--fg);border:1px solid var(--border);border-radius:4px;padding:.4rem}
button{padding:.5rem .9rem;font-size:1rem;margin:.25rem .25rem .25rem 0}
pre{background:var(--code-bg);padding:.6rem;white-space:pre-wrap;word-break:break-all;border-radius:4px}
#status{color:var(--muted);min-height:1.5em}`

var messageTmpl = template.Must(template.New("message").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex"><meta name="color-scheme" content="light dark">
<title>{{.Title}}</title><style nonce="{{.CSP}}">` + style + `</style></head>
<body><h2>{{.Title}}</h2><p>{{.Body}}</p></body></html>`))

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex"><meta name="color-scheme" content="light dark">
<title>Verify with Proton</title><style nonce="{{.CSP}}">` + style + `</style></head>
<body>
<h2>Answer Proton's CAPTCHA</h2>
<p>The bridge is stopped until a person completes this. It takes about a minute.</p>
<ol>
<li><button id="open" type="button">Open the CAPTCHA</button> (a popup; allow it if asked).</li>
<li>In the popup press <b>F12</b>, open the <b>Console</b>, paste this and press Enter <i>before</i> solving
(browsers may ask you to type "allow pasting" first):
<button id="copy" type="button">Copy snippet</button>
<pre id="snippet"></pre></li>
<li>Solve the CAPTCHA. The token then appears in the box below by itself. If it does not, copy the
line starting with <code>HV</code> from the popup's console and paste it into the box. Two such lines appear;
the one needed has <code>"type":"pm_captcha"</code> (the second). Pasting both is fine, the right one is picked.</li>
<li>Press Submit:
<form method="post">
<input type="hidden" name="nonce" value="{{.Nonce}}">
<textarea id="input" name="input" required autocomplete="off" spellcheck="false" placeholder="token, or the whole HV line"></textarea>
<div id="status" role="status"></div>
<button type="submit">Submit</button>
</form></li>
</ol>
<script nonce="{{.CSP}}">
var popupURL = {{.PopupURL}};
var popup = null;
var snippet = "window.addEventListener('message',function(e){var d=e.data;console.log('HV',JSON.stringify(d));" +
  "if(d&&d.type==='pm_captcha'&&window.opener){window.opener.postMessage({pxHV:d.token}," + JSON.stringify(location.origin) + ")}})";
document.getElementById('snippet').textContent = snippet;

document.getElementById('open').addEventListener('click', function () {
  // Ask Proton's CAPTCHA for its dark theme when the browser prefers one.
  var dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  popup = window.open(popupURL + (dark ? '&Dark=true' : ''), 'hv', 'width=440,height=660');
});
document.getElementById('copy').addEventListener('click', function () {
  var btn = this;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(snippet).then(function () { btn.textContent = 'Copied'; });
  } else {
    var r = document.createRange(); r.selectNodeContents(document.getElementById('snippet'));
    var s = window.getSelection(); s.removeAllRanges(); s.addRange(r); btn.textContent = 'Selected: press Ctrl+C';
  }
});
// Accept the relayed token only from the popup this page opened, and only from Proton's
// CAPTCHA origin; anything else is ignored.
window.addEventListener('message', function (e) {
  var d = e.data;
  if (!popup || e.source !== popup || e.origin !== 'https://verify-api.proton.me') return;
  if (!d || typeof d.pxHV !== 'string' || d.pxHV.length > 12288) return;
  document.getElementById('input').value = d.pxHV;
  document.getElementById('status').textContent = 'Token received from the popup. Press Submit.';
});
</script>
</body></html>`))
