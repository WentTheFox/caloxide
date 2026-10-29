package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/mathewcsims/protoxide/auth"
	"github.com/mathewcsims/protoxide/protonmail"
	"github.com/mathewcsims/protoxide/webverify"
)

// openBrowser is a variable so tests do not launch a real browser.
var openBrowser = func(url string) {
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

// verificationTimeout is how long `protoxide auth` waits for the person.
const verificationTimeout = 5 * time.Minute

// solveHumanVerification serves, on a loopback port, the same CAPTCHA page the
// running bridge serves (package webverify): the account owner completes Proton's
// genuine challenge in their browser and the resulting token is returned so the login
// can be retried with it. It never solves or bypasses the challenge itself.
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

	nb := make([]byte, 24)
	if _, err := rand.Read(nb); err != nil {
		return "", "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nb)
	tokenCh := make(chan string, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			webverify.WriteChallenge(w, webverify.PageData{Nonce: nonce, PopupURL: webverify.PopupURL(hv.HumanVerificationToken)})
		case http.MethodPost:
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := r.ParseForm(); err != nil {
				webverify.WriteMessage(w, http.StatusRequestEntityTooLarge, "Request too large", "That was not a verification token.")
				return
			}
			// The nonce is what stops another web page from posting to this local port.
			if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("nonce")), []byte(nonce)) != 1 {
				webverify.WriteMessage(w, http.StatusBadRequest, "Start again", "This form is not from the current page. Reload it.")
				return
			}
			tok, err := auth.ParseVerificationInput(r.PostForm.Get("input"))
			if err != nil {
				body := err.Error()
				if errors.Is(err, auth.ErrNoToken) || errors.Is(err, auth.ErrWrongMessage) {
					body += ". Use your browser's Back button and paste the whole console line again."
				}
				webverify.WriteMessage(w, http.StatusBadRequest, "No token found", body)
				return
			}
			select {
			case tokenCh <- tok:
			default:
			}
			webverify.WriteMessage(w, http.StatusOK, "Token received", "You can close this tab and return to the terminal.")
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	defer srv.Close()

	url := "http://" + ln.Addr().String() + "/"
	fmt.Println("\nProton requires you to complete a human-verification challenge.")
	fmt.Println("Opening it in your browser:", url)
	fmt.Println("If it doesn't open automatically, paste that URL into your browser.")
	openBrowser(url)

	select {
	case t := <-tokenCh:
		return t, "captcha", nil
	case <-time.After(verificationTimeout):
		return "", "", fmt.Errorf("timed out waiting for human verification")
	}
}
