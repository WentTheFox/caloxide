package main

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/mathewcsims/protoxide/protonmail"
)

// solveHumanVerification opens Proton's official challenge in the browser for
// the account owner to complete by hand, then captures and returns the token
// the challenge produces. It never solves or bypasses the challenge itself.
func solveHumanVerification(hv *protonmail.HumanVerificationDetails) (token, tokenType string, err error) {
	hasCaptcha := false
	for _, m := range hv.HumanVerificationMethods {
		if m == "captcha" {
			hasCaptcha = true
		}
	}
	if !hasCaptcha {
		return "", "", fmt.Errorf("no supported verification method offered (got %v)", hv.HumanVerificationMethods)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}
	defer ln.Close()
	addr := ln.Addr().String()

	tokenCh := make(chan string, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(strings.Replace(helperPage, "{{TOKEN}}", hv.HumanVerificationToken, 1)))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		t := r.URL.Query().Get("token")
		if t == "" {
			t = r.FormValue("token")
		}
		if t == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}
		select {
		case tokenCh <- t:
		default:
		}
		fmt.Fprint(w, "Token received. You can close this tab and return to the terminal.")
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	url := "http://" + addr + "/"
	fmt.Println("\nProton requires you to complete a human-verification challenge.")
	fmt.Println("Opening it in your browser:", url)
	fmt.Println("If it doesn't open automatically, paste that URL into your browser.")
	openBrowser(url)

	select {
	case t := <-tokenCh:
		return t, "captcha", nil
	case <-time.After(5 * time.Minute):
		return "", "", fmt.Errorf("timed out waiting for human verification")
	}
}

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	args = append(args, url)
	_ = exec.Command(cmd, args...).Start()
}

const helperPage = `<!doctype html>
<html><head><meta charset="utf-8"><title>Proton verification</title>
<style>body{font-family:sans-serif;max-width:560px;margin:2rem auto;padding:0 1rem}
button{padding:.6rem 1rem;font-size:1rem;margin:.3rem 0}
pre{background:#f4f4f4;padding:.5rem;overflow:auto;max-height:160px;font-size:11px}
input{width:100%;padding:.5rem}code{background:#eee;padding:2px 4px;font-size:12px}</style>
</head><body>
<h3>Complete the Proton challenge</h3>
<ol>
<li>Click <b>Open challenge</b> (opens a Proton popup — allowed, unlike an embed).</li>
<li>Solve the CAPTCHA in that popup.</li>
<li>If this page doesn't advance on its own, use the console method below.</li>
</ol>
<button onclick="openHV()">Open challenge</button>
<h4>Console method (reliable capture)</h4>
<p>In the popup: open DevTools → Console, paste this <i>before</i> solving —
<br><code>window.addEventListener('message',e=>console.log('HV',JSON.stringify(e.data)))</code>
<br>— solve the CAPTCHA, then copy the token value that logs and paste it here:</p>
<form onsubmit="send(document.getElementById('t').value);return false">
<input id="t" placeholder="verification token"><button>Submit token</button></form>
<h4>Messages this page received</h4><pre id="log"></pre>
<script>
var HVURL="https://verify-api.proton.me/core/v4/captcha?Token={{TOKEN}}&ForceWebMessaging=1&Dark=true";
function openHV(){window.open(HVURL,'hv','width=440,height=660')}
function send(tok){if(!tok)return;fetch('/token?token='+encodeURIComponent(tok)).then(function(){document.body.innerHTML='<h3>Token submitted \u2014 return to the terminal.</h3>'})}
function log(x){var p=document.getElementById('log');p.textContent+=(typeof x==='string'?x:JSON.stringify(x))+'\n'}
window.addEventListener('message',function(e){
  log(e.data);
  try{var d=e.data;var tok=d&&(d.token||(d.payload&&d.payload.token)||(d.data&&d.data.token));if(tok){send(tok)}}catch(err){log(String(err))}
});
</script>
</body></html>`
