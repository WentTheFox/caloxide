package credstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Names of the secrets read from the configured Infisical folder.
const (
	NameLoginPassword   = "PROTON_LOGIN_PASSWORD"
	NameMailboxPassword = "PROTON_MAILBOX_PASSWORD"
	NameTOTPSecret      = "PROTON_TOTP_SECRET"
)

const (
	requestTimeout  = 15 * time.Second
	maxResponseSize = 1 << 20 // 1 MiB; real responses are a few hundred bytes
)

// InfisicalConfig describes a read-only Universal Auth machine identity scoped to
// one project, environment and folder.
type InfisicalConfig struct {
	BaseURL      string // an https URL (plain http is accepted only for loopback)
	ClientID     string
	ClientSecret string
	ProjectID    string
	Environment  string
	SecretPath   string // folder, e.g. /protoxide; defaults to /
	HTTPClient   *http.Client
}

// Infisical is a Provider backed by the Infisical REST API (v3 raw secrets).
type Infisical struct {
	base   *url.URL
	cfg    InfisicalConfig
	client *http.Client
}

// NewInfisical validates cfg. It refuses plain http to anything but loopback, URLs
// that carry credentials, queries or fragments, and any missing required field.
func NewInfisical(cfg InfisicalConfig) (*Infisical, error) {
	for name, v := range map[string]string{
		"URL": cfg.BaseURL, "client id": cfg.ClientID, "client secret": cfg.ClientSecret,
		"project id": cfg.ProjectID, "environment": cfg.Environment,
	} {
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("infisical: %s is required", name)
		}
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("infisical: URL is not valid")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("infisical: URL must not contain credentials, a query or a fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, errors.New("infisical: plain http is only allowed for a loopback host; use https")
		}
	default:
		return nil, errors.New("infisical: URL scheme must be https")
	}
	if cfg.SecretPath == "" {
		cfg.SecretPath = "/"
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	// Work on a copy so the caller's client is not modified.
	c := *client
	c.Timeout = requestTimeout
	// Never follow a redirect: the credentials must only ever go to the configured host.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	u.Path = strings.TrimRight(u.Path, "/")
	return &Infisical{base: u, cfg: cfg, client: &c}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Get logs in with the machine identity and reads the secrets. The access token
// lives only for the duration of the call.
func (i *Infisical) Get(ctx context.Context) (Secrets, error) {
	token, err := i.login(ctx)
	if err != nil {
		return Secrets{}, err
	}
	var s Secrets
	if s.LoginPassword, err = i.secret(ctx, token, NameLoginPassword); err != nil {
		return Secrets{}, fmt.Errorf("reading %s: %w", NameLoginPassword, err)
	}
	// The other two are optional: absent means the account does not use them.
	if s.MailboxPassword, err = i.secret(ctx, token, NameMailboxPassword); err != nil && !errors.Is(err, ErrNotFound) {
		return Secrets{}, fmt.Errorf("reading %s: %w", NameMailboxPassword, err)
	}
	if s.TOTPSecret, err = i.secret(ctx, token, NameTOTPSecret); err != nil && !errors.Is(err, ErrNotFound) {
		return Secrets{}, fmt.Errorf("reading %s: %w", NameTOTPSecret, err)
	}
	return s, nil
}

func (i *Infisical) login(ctx context.Context) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"clientId": i.cfg.ClientID, "clientSecret": i.cfg.ClientSecret,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.endpoint("/api/v1/auth/universal-auth/login", nil), bytes.NewReader(body))
	if err != nil {
		return "", errors.New("infisical: could not build login request")
	}
	req.Header.Set("Content-Type", "application/json")
	var out struct {
		AccessToken string `json:"accessToken"`
		TokenType   string `json:"tokenType"`
	}
	if err := i.do(req, &out); err != nil {
		return "", fmt.Errorf("infisical login: %w", err)
	}
	if out.AccessToken == "" {
		return "", errors.New("infisical login: response had no access token")
	}
	return out.AccessToken, nil
}

func (i *Infisical) secret(ctx context.Context, token, name string) (string, error) {
	q := url.Values{}
	q.Set("workspaceId", i.cfg.ProjectID)
	q.Set("environment", i.cfg.Environment)
	q.Set("secretPath", i.cfg.SecretPath)
	q.Set("type", "shared")
	q.Set("viewSecretValue", "true")
	q.Set("expandSecretReferences", "false")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, i.endpoint("/api/v3/secrets/raw/"+url.PathEscape(name), q), nil)
	if err != nil {
		return "", errors.New("infisical: could not build request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	var out struct {
		Secret struct {
			Value  string `json:"secretValue"`
			Hidden bool   `json:"secretValueHidden"`
			Type   string `json:"type"`
		} `json:"secret"`
	}
	if err := i.do(req, &out); err != nil {
		return "", err
	}
	if out.Secret.Hidden {
		return "", errors.New("the identity may list this secret but not read its value")
	}
	if out.Secret.Type != "" && out.Secret.Type != "shared" {
		return "", errors.New("unexpected secret type")
	}
	if out.Secret.Value == "" {
		return "", fmt.Errorf("%w (value is empty)", ErrNotFound)
	}
	return out.Secret.Value, nil
}

func (i *Infisical) endpoint(path string, q url.Values) string {
	u := *i.base
	u.Path += path
	if q != nil {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// do performs req and decodes a JSON 200 response into out. Errors never contain
// the response body or request URL, only the status code or a transport reason.
func (i *Infisical) do(req *http.Request, out any) error {
	resp, err := i.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL from the message
		}
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseSize))
		return ErrNotFound
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return errors.New("refused to follow a redirect")
	case resp.StatusCode != http.StatusOK:
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseSize))
		return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	if len(data) > maxResponseSize {
		return errors.New("response too large")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("response was not the expected JSON")
	}
	return nil
}

// InfisicalFromEnv builds a provider from PROTOXIDE_INFISICAL_* environment
// variables. CLIENT_ID and CLIENT_SECRET may instead be given as ..._FILE (a path,
// for Docker secrets); setting both forms of one value is an error.
func InfisicalFromEnv() (*Infisical, error) {
	return infisicalFromEnv(os.Getenv, os.ReadFile)
}

func infisicalFromEnv(getenv func(string) string, readFile func(string) ([]byte, error)) (*Infisical, error) {
	value := func(name string) (string, error) {
		direct, file := getenv(name), getenv(name+"_FILE")
		if direct != "" && file != "" {
			return "", fmt.Errorf("%s and %s_FILE are both set; use one", name, name)
		}
		if file == "" {
			return direct, nil
		}
		b, err := readFile(file)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: could not read file", name)
		}
		return strings.TrimSpace(string(b)), nil
	}
	id, err := value("PROTOXIDE_INFISICAL_CLIENT_ID")
	if err != nil {
		return nil, err
	}
	secret, err := value("PROTOXIDE_INFISICAL_CLIENT_SECRET")
	if err != nil {
		return nil, err
	}
	return NewInfisical(InfisicalConfig{
		BaseURL:      getenv("PROTOXIDE_INFISICAL_URL"),
		ClientID:     id,
		ClientSecret: secret,
		ProjectID:    getenv("PROTOXIDE_INFISICAL_PROJECT_ID"),
		Environment:  getenv("PROTOXIDE_INFISICAL_ENV"),
		SecretPath:   getenv("PROTOXIDE_INFISICAL_PATH"),
	})
}
