package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	imapserver "github.com/emersion/go-imap/server"
	"github.com/emersion/go-mbox"
	"github.com/emersion/go-smtp"
	"golang.org/x/term"

	"github.com/google/uuid"
	"github.com/mathewcsims/protoxide/auth"
	"github.com/mathewcsims/protoxide/caldav"
	"github.com/mathewcsims/protoxide/carddav"
	"github.com/mathewcsims/protoxide/config"
	"github.com/mathewcsims/protoxide/events"
	"github.com/mathewcsims/protoxide/exports"
	imapbackend "github.com/mathewcsims/protoxide/imap"
	"github.com/mathewcsims/protoxide/imports"
	"github.com/mathewcsims/protoxide/notify"
	"github.com/mathewcsims/protoxide/protonmail"
	smtpbackend "github.com/mathewcsims/protoxide/smtp"
	"github.com/mathewcsims/protoxide/totp"
	"github.com/mathewcsims/protoxide/webverify"
)

const (
	defaultAPIEndpoint = "https://mail.proton.me/api"
	torAPIEndpoint     = "https://mail.protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion/api"
	defaultAppVersion  = "Other"
)

var (
	debug       bool
	apiEndpoint string
	appVersion  string
	userAgent   string
	proxyURL    string
	tor         bool
)

func makeHTTPClientFromProxy(proxyArg string) (*http.Client, error) {
	fmtProxy := ""
	client := &http.Client{}
	if tor {
		un, err := uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		// Tor requires socks5. To keep the same format as without tor, we allow
		// the user to specify socks5:// in the proxy URL.
		// But we remove it
		if strings.HasPrefix(proxyArg, "socks5://") {
			proxyArg = strings.Replace(proxyArg, "socks5://", "", 1)
		}
		fmtProxy = fmt.Sprintf("socks5://caloxide_%s::@%s", un, proxyArg)

	} else {
		if !strings.Contains(proxyArg, "://") {
			// Assume socks5:// if no scheme is provided
			proxyArg = "socks5://" + proxyArg
		}
		fmtProxy = proxyArg // Don't hard code socks5://
	}

	proxy, err := url.Parse(fmtProxy)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		Proxy: http.ProxyURL(proxy),
	}

	client = &http.Client{Transport: tr}
	return client, nil
}
func newClient() *protonmail.Client {
	httpClient := &http.Client{}
	if proxyURL != "" {
		proxiedClient, err := makeHTTPClientFromProxy(proxyURL)
		if err != nil {
			log.Fatal("Error creating proxied http.Client: ", err)
		}

		httpClient = proxiedClient
	}
	return &protonmail.Client{
		RootURL:    apiEndpoint,
		AppVersion: appVersion,
		UserAgent:  userAgent,
		Debug:      debug,
		HTTPClient: httpClient,
		OnRateLimited: func(pause time.Duration) {
			notify.Send("warning", "rate-limited", "caloxide: Proton is rate limiting us",
				fmt.Sprintf("Proton asked for a pause of %s. Every request waits for it; inbound sync is delayed meanwhile. The response is in the log.", pause.Round(time.Second)))
		},
	}
}

// appVersionEnv sets the app version when no flag does. The name mirrors rclone's
// --protondrive-app-version option.
const appVersionEnv = "CALOXIDE_PROTONDRIVE_APP_VERSION"

// appVersionRE is what an app version may contain. It ends up in an HTTP header, so
// anything outside this set (spaces, control characters, newlines) is refused.
var appVersionRE = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,128}$`)

// resolveAppVersion applies the precedence flag > environment > default and validates
// the result. flagGiven says whether either flag name was passed on the command line.
func resolveAppVersion(flagGiven bool, flagValue, env string) (string, error) {
	v := flagValue
	if !flagGiven && env != "" {
		v = env
	}
	if !appVersionRE.MatchString(v) {
		return "", fmt.Errorf("invalid app version: use letters, digits and . _ @ + - only, up to 128 characters")
	}
	return v, nil
}

// startVerification prepares the one-time CAPTCHA page and the control socket that
// opens it. The page is a 404 unless `caloxide verify` opened a window, which in turn
// is refused unless a CAPTCHA is actually pending.
func startVerification(m *auth.Manager) http.Handler {
	if !m.ReloginEnabled() {
		return nil
	}
	publicURL := strings.TrimRight(config.Getenv("CALOXIDE_PUBLIC_URL"), "/")
	sock, err := config.Path("control.sock")
	if err != nil {
		log.Printf("verify: control socket unavailable: %v", err)
		return nil
	}
	if _, err := webverify.ServeControlWith(sock, publicURL, m.OpenVerificationWindow, caldav.StatusJSON); err != nil {
		log.Printf("verify: control socket unavailable: %v", err)
		return nil
	}
	log.Printf("verify: if Proton asks for a CAPTCHA, run `caloxide verify` (inside the container, if it runs in one) for a one-time link")
	return webverify.Handler(m)
}

// localTOTPSeed returns the 2FA seed to store with the session: from
// CALOXIDE_TOTP_SECRET, or a file named by CALOXIDE_TOTP_SECRET_FILE, else a hidden
// prompt that may be left empty (then a one-time code is typed instead and nothing is
// stored). The seed is kept only in the encrypted auth.json.
func localTOTPSeed() string {
	direct, file := config.Getenv("CALOXIDE_TOTP_SECRET"), config.Getenv("CALOXIDE_TOTP_SECRET_FILE")
	switch {
	case direct != "" && file != "":
		log.Fatal("CALOXIDE_TOTP_SECRET and CALOXIDE_TOTP_SECRET_FILE are both set; use one")
	case direct != "":
		return strings.TrimSpace(direct)
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			log.Fatal("CALOXIDE_TOTP_SECRET_FILE: could not read file")
		}
		return strings.TrimSpace(string(b))
	}
	b, err := askPass("2FA secret key (base32, hidden; optional - lets the bridge log in again by itself. Enter to type a one-time code instead)")
	if err != nil {
		log.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func askPass(prompt string) ([]byte, error) {
	f := os.Stdin
	if !term.IsTerminal(int(f.Fd())) {
		// This can happen if stdin is used for piping data
		// TODO: the following assumes Unix
		var err error
		if f, err = os.Open("/dev/tty"); err != nil {
			return nil, err
		}
		defer f.Close()
	}
	fmt.Fprintf(os.Stderr, "%v: ", prompt)
	b, err := term.ReadPassword(int(f.Fd()))
	if err == nil {
		fmt.Fprintf(os.Stderr, "\n")
	}
	return b, err
}

func askBridgePass() (string, error) {
	if v := os.Getenv("HYDROXIDE_BRIDGE_PASS"); v != "" {
		return v, nil
	}
	b, err := askPass("Bridge password")
	return string(b), err
}

func listenAndServeSMTP(addr string, debug bool, authManager *auth.Manager, tlsConfig *tls.Config) error {
	be := smtpbackend.New(authManager)
	s := smtp.NewServer(be)
	s.Addr = addr
	s.Domain = "localhost" // TODO: make this configurable
	s.AllowInsecureAuth = tlsConfig == nil
	s.TLSConfig = tlsConfig
	if debug {
		s.Debug = os.Stdout
	}

	if s.TLSConfig != nil {
		log.Println("SMTP server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS()
	}

	log.Println("SMTP server listening on", s.Addr)
	return s.ListenAndServe()
}

func listenAndServeIMAP(addr string, debug bool, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config) error {
	be := imapbackend.New(authManager, eventsManager)
	s := imapserver.New(be)
	s.Addr = addr
	s.AllowInsecureAuth = tlsConfig == nil
	s.TLSConfig = tlsConfig
	if debug {
		s.Debug = os.Stdout
	}

	if s.TLSConfig != nil {
		log.Println("IMAP server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS()
	}

	log.Println("IMAP server listening on", s.Addr)
	return s.ListenAndServe()
}

// verify, if not nil, serves the one-time CAPTCHA page under webverify.PathPrefix. It
// answers 404 unless a verification window is open.
// isBrowserProbe reports a request that looks like someone opening the address in a
// browser: a GET or HEAD, without credentials, for a path no calendar client uses. It
// gets a plain 404 and no Basic-auth challenge, so a browser shows no login dialog and
// the address does not advertise that there is something to log in to. CalDAV clients
// use the other methods (PROPFIND, REPORT, OPTIONS, ...) and the /caldav/ paths, which
// keep their challenge.
func isBrowserProbe(req *http.Request) bool {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}
	if _, _, ok := req.BasicAuth(); ok {
		return false
	}
	p := req.URL.Path
	return p != "/caldav" && !strings.HasPrefix(p, "/caldav/") && p != "/.well-known/caldav"
}

func listenAndServeCalDAV(addr string, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config, verify http.Handler) error {
	handlers := make(map[string]http.Handler)

	s := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			// A panic in a handler is otherwise swallowed by net/http (logged, then
			// the connection is dropped) and would go unnoticed. Recover, alert, and
			// return a 500 so the fault is visible.
			defer func() {
				if r := recover(); r != nil {
					log.Printf("CalDAV: recovered panic on %s %s: %v", req.Method, req.URL.Path, r)
					notify.Send("failure", "caldav-panic", "caloxide: CalDAV handler panic",
						fmt.Sprintf("%s %s panicked: %v", req.Method, req.URL.Path, r))
					resp.WriteHeader(http.StatusInternalServerError)
				}
			}()

			if verify != nil && strings.HasPrefix(req.URL.Path, webverify.PathPrefix) {
				verify.ServeHTTP(resp, req)
				return
			}

			if isBrowserProbe(req) {
				http.NotFound(resp, req)
				return
			}

			if debug {
				log.Printf("CalDAV <- %s %s", req.Method, req.URL.Path)
			}
			resp.Header().Set("WWW-Authenticate", "Basic")

			username, password, ok := req.BasicAuth()
			if !ok {
				log.Printf("CalDAV %s %s: no credentials", req.Method, req.URL.Path)
				resp.WriteHeader(http.StatusUnauthorized)
				io.WriteString(resp, "Credentials are required")
				return
			}

			c, privateKeys, err := authManager.Auth(username, password)
			if err != nil {
				if err == auth.ErrUnauthorized {
					// Most likely an expired/invalidated Proton session — the client's
					// password is fixed, so this appearing after it worked means re-auth
					// is needed. Debounced so a broken session doesn't flood.
					resp.WriteHeader(http.StatusUnauthorized)
					notify.Send("failure", "caldav-auth", "caloxide: CalDAV auth failed",
						fmt.Sprintf("Rejected %s for %q — the Proton session may have expired; run `caloxide auth %s`.", req.Method, username, username))
				} else {
					resp.WriteHeader(http.StatusInternalServerError)
					notify.Send("failure", "caldav-auth-err", "caloxide: CalDAV auth error",
						fmt.Sprintf("Error authenticating %q: %v", username, err))
				}
				io.WriteString(resp, err.Error())
				return
			}

			h, ok := handlers[username]
			if !ok {
				ch := make(chan *protonmail.Event)
				r := eventsManager.Register(c, username, ch, nil)
				h = caldav.NewHandler(c, privateKeys, username, ch)
				// Standby slows the account event loop too while nobody uses the server.
				caldav.WireCoreLoop(h, r.SetInterval, r.Poll)

				handlers[username] = h
			}

			h.ServeHTTP(resp, req)
		}),
	}

	log.Println("CalDAV server listening on", s.Addr)
	return s.ListenAndServe()
}

func listenAndServeCardDAV(addr string, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config) error {
	handlers := make(map[string]http.Handler)

	s := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			resp.Header().Set("WWW-Authenticate", "Basic")

			username, password, ok := req.BasicAuth()
			if !ok {
				resp.WriteHeader(http.StatusUnauthorized)
				io.WriteString(resp, "Credentials are required")
				return
			}

			c, privateKeys, err := authManager.Auth(username, password)
			if err != nil {
				if err == auth.ErrUnauthorized {
					resp.WriteHeader(http.StatusUnauthorized)
				} else {
					resp.WriteHeader(http.StatusInternalServerError)
				}
				io.WriteString(resp, err.Error())
				return
			}

			h, ok := handlers[username]
			if !ok {
				ch := make(chan *protonmail.Event)
				eventsManager.Register(c, username, ch, nil)
				h = carddav.NewHandler(c, privateKeys, ch)

				handlers[username] = h
			}

			h.ServeHTTP(resp, req)
		}),
	}

	if s.TLSConfig != nil {
		log.Println("CardDAV server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS("", "")
	}

	log.Println("CardDAV server listening on", s.Addr)
	return s.ListenAndServe()
}

func isMbox(br *bufio.Reader) (bool, error) {
	prefix := []byte("From ")
	b, err := br.Peek(len(prefix))
	if err != nil {
		return false, err
	}
	return bytes.Equal(b, prefix), nil
}

const usage = `usage: caloxide [options...] <command>
Commands:
	auth <username>		Login to ProtonMail via caloxide
	import-session <username>	Seed auth from an existing logged-in Proton web session (skips login/CAPTCHA)
	carddav			Run caloxide as a CardDAV server
	caldav			Run caloxide as a CalDAV server
	export-secret-keys <username> Export secret keys
	imap			Run caloxide as an IMAP server
	import-messages <username> [file]	Import messages
	export-messages [options...] <username>	Export messages
	sendmail <username> -- <args...>	sendmail(1) interface
	serve			Run all servers
	smtp			Run caloxide as an SMTP server
	status			View caloxide status
	verify			Ask the running server for a one-time link to answer Proton's CAPTCHA
	push-probe <username>	Connect to Proton's push channel and print what it sends (read-only)

Environment variables:
	HYDROXIDE_BRIDGE_PASS	Don't prompt for the bridge password, use this variable instead

`

func main() {
	flag.BoolVar(&debug, "debug", false, "Enable debug logs")
	flag.StringVar(&apiEndpoint, "api-endpoint", defaultAPIEndpoint, "ProtonMail API endpoint")
	flag.StringVar(&appVersion, "app-version", defaultAppVersion, "ProtonMail app version. Proton validates it and rejects unknown forms with error 5002 (external-calendar-<name>@x.y.z is rejected); the default is known to be accepted")
	// Same variable, rclone's option name (--protondrive-app-version). Go accepts one or
	// two leading dashes. Whichever is given last wins; CALOXIDE_PROTONDRIVE_APP_VERSION
	// applies only when neither is given.
	flag.StringVar(&appVersion, "protondrive-app-version", defaultAppVersion, "Alias of -app-version, named like rclone's option; also settable with "+appVersionEnv)
	flag.StringVar(&userAgent, "user-agent", "", "User-Agent sent to Proton (default: a Firefox-on-Linux string)")

	smtpHost := flag.String("smtp-host", "127.0.0.1", "Allowed SMTP email hostname on which caloxide listens, defaults to 127.0.0.1")
	smtpPort := flag.String("smtp-port", "1025", "SMTP port on which caloxide listens, defaults to 1025")
	disableSMTP := flag.Bool("disable-smtp", false, "Disable SMTP for caloxide serve")

	imapHost := flag.String("imap-host", "127.0.0.1", "Allowed IMAP email hostname on which caloxide listens, defaults to 127.0.0.1")
	imapPort := flag.String("imap-port", "1143", "IMAP port on which caloxide listens, defaults to 1143")
	disableIMAP := flag.Bool("disable-imap", false, "Disable IMAP for caloxide serve")

	carddavHost := flag.String("carddav-host", "127.0.0.1", "Allowed CardDAV email hostname on which caloxide listens, defaults to 127.0.0.1")
	carddavPort := flag.String("carddav-port", "8080", "CardDAV port on which caloxide listens, defaults to 8080")
	disableCardDAV := flag.Bool("disable-carddav", false, "Disable CardDAV for caloxide serve")

	caldavHost := flag.String("caldav-host", "127.0.0.1", "Allowed CalDAV email hostname on which caloxide listens, defaults to 127.0.0.1")
	caldavPort := flag.String("caldav-port", "8081", "CalDAV port on which caloxide listens, defaults to 8081")
	disableCalDAV := flag.Bool("disable-caldav", false, "Disable CalDAV for caloxide serve")

	tlsCert := flag.String("tls-cert", "", "Path to the certificate to use for incoming connections")
	tlsCertKey := flag.String("tls-key", "", "Path to the certificate key to use for incoming connections")
	tlsClientCA := flag.String("tls-client-ca", "", "If set, clients must provide a certificate signed by the given CA")

	configHome := flag.String("config-home", "", "Path to the directory where caloxide stores its configuration")
	flag.StringVar(&proxyURL, "proxy-url", "", "HTTP proxy URL (e.g. socks5://127.0.0.1:1080)")
	flag.BoolVar(&tor, "tor", false, "If set, connect to ProtonMail over Tor")

	authCmd := flag.NewFlagSet("auth", flag.ExitOnError)
	exportSecretKeysCmd := flag.NewFlagSet("export-secret-keys", flag.ExitOnError)
	importMessagesCmd := flag.NewFlagSet("import-messages", flag.ExitOnError)
	exportMessagesCmd := flag.NewFlagSet("export-messages", flag.ExitOnError)
	sendmailCmd := flag.NewFlagSet("sendmail", flag.ExitOnError)

	flag.Usage = func() {
		fmt.Print(usage)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	appVersionGiven := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "app-version" || f.Name == "protondrive-app-version" {
			appVersionGiven = true
		}
	})
	av, err := resolveAppVersion(appVersionGiven, appVersion, config.Getenv(appVersionEnv))
	if err != nil {
		log.Fatal(err)
	}
	appVersion = av

	if tor && proxyURL == "" {
		log.Fatal("Need -proxy to connect to ProtonMail over Tor")
	}

	if tor {
		log.Println("Connecting to ProtonMail over Tor")
		apiEndpoint = torAPIEndpoint
	}

	tlsConfig, err := config.TLS(*tlsCert, *tlsCertKey, *tlsClientCA)
	if err != nil {
		log.Fatal(err)
	}

	if *configHome != "" {
		config.SetConfigHome(*configHome)
	}

	cmd := flag.Arg(0)
	switch cmd {
	case "auth":
		authCmd.Parse(flag.Args()[1:])
		username := authCmd.Arg(0)
		if username == "" {
			log.Fatal("usage: caloxide auth <username>")
		}

		c := newClient()
		// Keep Proton's cookies from this login with the session, so later unattended
		// re-logins look like the same client rather than a brand-new one.
		jar := auth.NewCookieJar(c)

		var a *protonmail.Auth
		/*if cachedAuth, ok := auths[username]; ok {
			var err error
			a, err = c.AuthRefresh(a)
			if err != nil {
				// TODO: handle expired token error
				log.Fatal(err)
			}
		}*/

		var loginPassword string
		var totpSeed string // stored with the session only after Proton accepted a code made from it
		if a == nil {
			if pass, err := askPass("Password"); err != nil {
				log.Fatal(err)
			} else {
				loginPassword = string(pass)
			}

			var err error
			login := func() (*protonmail.Auth, error) {
				authInfo, err := c.AuthInfo(username)
				if err != nil {
					return nil, err
				}
				return c.Auth(username, loginPassword, authInfo)
			}

			a, err = login()
			if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == 9001 && apiErr.HV != nil {
				fmt.Printf("Human verification methods offered: %v\n", apiErr.HV.HumanVerificationMethods)
				token, tokenType, solveErr := solveHumanVerification(apiErr.HV)
				if solveErr != nil {
					log.Fatal(solveErr)
				}
				c.SetHumanVerification(token, tokenType)
				a, err = login()
				c.ClearHumanVerification()
			}
			if err != nil {
				log.Fatal(err)
			}
			if a.TwoFactor.Enabled != 0 {
				if a.TwoFactor.TOTP != 1 {
					log.Fatal("Only TOTP is supported as a 2FA method")
				}

				answered := false
				if seed := localTOTPSeed(); seed != "" {
					if code, cerr := totp.Code(seed, time.Now()); cerr != nil {
						fmt.Printf("That is not a valid 2FA secret (%v); enter a code manually.\n", cerr)
					} else if scope, aerr := c.AuthTOTP(code); aerr != nil {
						fmt.Printf("Proton rejected the code generated from that secret (%v), so it was not stored; check it and try again, or enter a code manually.\n", aerr)
					} else {
						fmt.Println("Answered the 2FA challenge with a code generated from the secret; it will be stored (encrypted) so the bridge can log in again by itself.")
						a.Scope = scope
						answered = true
						totpSeed = seed
					}
				}
				if !answered {
					scanner := bufio.NewScanner(os.Stdin)
					fmt.Printf("2FA TOTP code: ")
					scanner.Scan()
					code := scanner.Text()

					scope, err := c.AuthTOTP(code)
					if err != nil {
						log.Fatal(err)
					}
					a.Scope = scope
				}
			}
		}

		var mailboxPassword string
		if a.PasswordMode == protonmail.PasswordSingle {
			mailboxPassword = loginPassword
		}
		if mailboxPassword == "" {
			prompt := "Password"
			if a.PasswordMode == protonmail.PasswordTwo {
				prompt = "Mailbox password"
			}
			if pass, err := askPass(prompt); err != nil {
				log.Fatal(err)
			} else {
				mailboxPassword = string(pass)
			}
		}

		keySalts, err := c.ListKeySalts()
		if err != nil {
			log.Fatal(err)
		}

		_, err = c.Unlock(a, keySalts, mailboxPassword)
		if err != nil {
			log.Fatal(err)
		}

		secretKey, bridgePassword, err := auth.GeneratePassword()
		if err != nil {
			log.Fatal(err)
		}

		cookies, _ := jar.Export()
		err = auth.EncryptAndSave(&auth.CachedAuth{
			Auth:            *a,
			LoginPassword:   loginPassword,
			MailboxPassword: mailboxPassword,
			KeySalts:        keySalts,
			TOTPSecret:      totpSeed,
			Cookies:         cookies,
		}, username, secretKey)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Bridge password:", bridgePassword)
		fmt.Println("The password" + map[bool]string{true: ", the 2FA secret", false: ""}[totpSeed != ""] + " and the session are stored in auth.json, encrypted with the bridge password. Keep that safe: it is the only thing protecting them, and the server never stores it.")
	case "import-session":
		// Seed caloxide from a session that already exists in a logged-in Proton
		// web tab, instead of performing a fresh login. Avoids the interactive
		// login entirely by reusing credentials the browser already holds.
		username := flag.Arg(1)
		if username == "" {
			log.Fatal("usage: caloxide import-session <username>")
		}

		c := newClient()

		reader := bufio.NewReader(os.Stdin)
		readLine := func(prompt string) string {
			fmt.Print(prompt)
			s, _ := reader.ReadString('\n')
			return strings.TrimSpace(s)
		}

		fmt.Println("Paste session values captured from a logged-in Proton web session:")
		uid := readLine("  UID (x-pm-uid header): ")
		accessToken := readLine("  Access token (Authorization bearer value, no 'Bearer '): ")
		refreshToken := readLine("  Refresh token (optional; enables auto-renewal): ")
		if uid == "" || accessToken == "" {
			log.Fatal("UID and access token are both required")
		}

		mailboxPass, err := askPass("Mailbox password")
		if err != nil {
			log.Fatal(err)
		}
		mailboxPassword := string(mailboxPass)

		c.SetSession(uid, accessToken)

		// Verify the session is live and fetch the key salts we must persist.
		keySalts, err := c.ListKeySalts()
		if err != nil {
			log.Fatalf("session check failed (is the access token still current?): %v", err)
		}

		a := &protonmail.Auth{
			UID:          uid,
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			PasswordMode: protonmail.PasswordSingle,
		}

		if _, err := c.Unlock(a, keySalts, mailboxPassword); err != nil {
			log.Fatalf("failed to unlock keys with mailbox password: %v", err)
		}

		secretKey, bridgePassword, err := auth.GeneratePassword()
		if err != nil {
			log.Fatal(err)
		}
		if err := auth.EncryptAndSave(&auth.CachedAuth{
			Auth:            *a,
			MailboxPassword: mailboxPassword,
			KeySalts:        keySalts,
		}, username, secretKey); err != nil {
			log.Fatal(err)
		}

		fmt.Println("Session imported. Bridge password:", bridgePassword)
		if refreshToken == "" {
			fmt.Println("Note: no refresh token provided — the session will stop working when the access token expires, and you'll need to import again.")
		}
	case "verify":
		// Run inside the container (docker exec): asks the running bridge for a
		// one-time link to the CAPTCHA page. Refused unless a CAPTCHA is pending.
		sock, err := config.Path("control.sock")
		if err != nil {
			log.Fatal(err)
		}
		link, expires, err := webverify.RequestLink(sock)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Open this link in a browser within %s (it works once, for one verification):\n\n  %s\n",
			time.Until(expires).Round(time.Minute), link)
		if !strings.HasPrefix(link, "http") {
			fmt.Printf("\n(CALOXIDE_PUBLIC_URL is not set on the bridge, so put its address in front of %s)\n", webverify.PathPrefix)
		}
	case "push-probe":
		username := flag.Arg(1)
		if username == "" {
			log.Fatal("usage: caloxide push-probe <username>")
		}
		pushProbe(username, newClient)
	case "status":
		usernames, err := auth.ListUsernames()
		if err != nil {
			log.Fatal(err)
		}

		if len(usernames) == 0 {
			fmt.Printf("No logged in user.\n")
		} else {
			fmt.Printf("%v logged in user(s):\n", len(usernames))
			for _, u := range usernames {
				fmt.Printf("- %v\n", u)
			}
		}

		// What the running server is doing, if there is one to ask.
		fmt.Println()
		if sock, err := config.Path("control.sock"); err != nil {
			fmt.Printf("Server: %v\n", err)
		} else if raw, err := webverify.RequestStatus(sock); err != nil {
			fmt.Printf("Server: not reachable (%v)\n", err)
		} else {
			var st caldav.Status
			if err := json.Unmarshal(raw, &st); err != nil {
				fmt.Printf("Server: unreadable status (%v)\n", err)
			} else {
				fmt.Print(st.String())
			}
		}
	case "export-secret-keys":
		exportSecretKeysCmd.Parse(flag.Args()[1:])
		username := exportSecretKeysCmd.Arg(0)
		if username == "" {
			log.Fatal("usage: caloxide export-secret-keys <username>")
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		_, privateKeys, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		wc, err := armor.Encode(os.Stdout, openpgp.PrivateKeyType, nil)
		if err != nil {
			log.Fatal(err)
		}

		for _, key := range privateKeys {
			if err := key.SerializePrivate(wc, nil); err != nil {
				log.Fatal(err)
			}
		}

		if err := wc.Close(); err != nil {
			log.Fatal(err)
		}
	case "import-messages":
		importMessagesCmd.Parse(flag.Args()[1:])
		username := importMessagesCmd.Arg(0)
		archivePath := importMessagesCmd.Arg(1)
		if username == "" {
			log.Fatal("usage: caloxide import-messages <username> [file]")
		}

		f := os.Stdin
		if archivePath != "" {
			f, err = os.Open(archivePath)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		c, _, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		br := bufio.NewReader(f)
		if ok, err := isMbox(br); err != nil {
			log.Fatal(err)
		} else if ok {
			mr := mbox.NewReader(br)
			for {
				r, err := mr.NextMessage()
				if err == io.EOF {
					break
				} else if err != nil {
					log.Fatal(err)
				}
				if err := imports.ImportMessage(c, r); err != nil {
					log.Fatal(err)
				}
			}
		} else {
			if err := imports.ImportMessage(c, br); err != nil {
				log.Fatal(err)
			}
		}
	case "export-messages":
		// TODO: allow specifying multiple IDs
		var convID, msgID string
		exportMessagesCmd.StringVar(&convID, "conversation-id", "", "conversation ID")
		exportMessagesCmd.StringVar(&msgID, "message-id", "", "message ID")
		exportMessagesCmd.Parse(flag.Args()[1:])
		username := exportMessagesCmd.Arg(0)
		if (convID == "" && msgID == "") || username == "" {
			log.Fatal("usage: caloxide export-messages [-conversation-id <id>] [-message-id <id>] <username>")
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		c, privateKeys, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		mboxWriter := mbox.NewWriter(os.Stdout)

		if convID != "" {
			if err := exports.ExportConversationMbox(c, privateKeys, mboxWriter, convID); err != nil {
				log.Fatal(err)
			}
		}
		if msgID != "" {
			if err := exports.ExportMessageMbox(c, privateKeys, mboxWriter, msgID); err != nil {
				log.Fatal(err)
			}
		}

		if err := mboxWriter.Close(); err != nil {
			log.Fatal(err)
		}
	case "smtp":
		addr := *smtpHost + ":" + *smtpPort
		authManager := auth.NewManager(newClient)
		log.Fatal(listenAndServeSMTP(addr, debug, authManager, tlsConfig))
	case "imap":
		addr := *imapHost + ":" + *imapPort
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeIMAP(addr, debug, authManager, eventsManager, tlsConfig))
	case "caldav":
		addr := *caldavHost + ":" + *caldavPort
		caldav.Debug = debug
		authManager := auth.NewManager(newClient)
		// Unattended re-login from the credentials stored in auth.json: exponential
		// backoff, a cap on logins, and a full stop (with an alert) when Proton demands
		// a CAPTCHA, which `caloxide verify` then lets a person answer.
		authManager.EnableRelogin()
		eventsManager := events.NewManager()
		verifyHandler := startVerification(authManager)
		err := listenAndServeCalDAV(addr, authManager, eventsManager, tlsConfig, verifyHandler)
		// Only reached if the server stops. Alert before exiting so a restart
		// (e.g. by launchd) is visible rather than silent.
		notify.SendSync("failure", "caloxide: CalDAV server stopped",
			fmt.Sprintf("The CalDAV server exited: %v", err))
		log.Fatal(err)
	case "carddav":
		addr := *carddavHost + ":" + *carddavPort
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeCardDAV(addr, authManager, eventsManager, tlsConfig))
	case "serve":
		smtpAddr := *smtpHost + ":" + *smtpPort
		imapAddr := *imapHost + ":" + *imapPort
		carddavAddr := *carddavHost + ":" + *carddavPort
		caldavAddr := *caldavHost + ":" + *caldavPort

		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()

		// Standby only sees CalDAV requests; with other protocols running it would put
		// a busy IMAP or CardDAV session to sleep.
		if !*disableSMTP || !*disableIMAP || !*disableCardDAV {
			caldav.SetStandbyAllowed(false)
		}

		done := make(chan error, 3)
		if !*disableSMTP {
			go func() {
				done <- listenAndServeSMTP(smtpAddr, debug, authManager, tlsConfig)
			}()
		}
		if !*disableIMAP {
			go func() {
				done <- listenAndServeIMAP(imapAddr, debug, authManager, eventsManager, tlsConfig)
			}()
		}
		if !*disableCardDAV {
			go func() {
				done <- listenAndServeCardDAV(carddavAddr, authManager, eventsManager, tlsConfig)
			}()
		}
		if !*disableCalDAV {
			go func() {
				done <- listenAndServeCalDAV(caldavAddr, authManager, eventsManager, tlsConfig, nil)
			}()
		}
		log.Fatal(<-done)
	case "sendmail":
		username := flag.Arg(1)
		if username == "" || flag.Arg(2) != "--" {
			log.Fatal("usage: caloxide sendmail <username> -- <args...>")
		}

		// TODO: other sendmail flags
		var dotEOF bool
		sendmailCmd.BoolVar(&dotEOF, "i", false, "don't treat a line with only a . character as the end of input")
		sendmailCmd.Parse(flag.Args()[3:])
		rcpt := sendmailCmd.Args()

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		c, privateKeys, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		u, err := c.GetCurrentUser()
		if err != nil {
			log.Fatal(err)
		}

		addrs, err := c.ListAddresses()
		if err != nil {
			log.Fatal(err)
		}

		err = smtpbackend.SendMail(c, u, privateKeys, addrs, rcpt, os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Print(usage)
		if cmd != "help" {
			log.Fatal("Unrecognized command")
		}
	}
}
