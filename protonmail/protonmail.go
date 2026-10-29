// Package protonmail implements a ProtonMail API client.
package protonmail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"log"
)

const Version = 3

const headerAPIVersion = "X-Pm-Apiversion"

type resp struct {
	Code int
	*RawAPIError
	Details *HumanVerificationDetails `json:"Details"`
}

func (r *resp) Err() error {
	if err := r.RawAPIError; err != nil {
		return &APIError{
			Code:    r.Code,
			Message: err.Message,
			HV:      r.Details,
		}
	}
	return nil
}

type maybeError interface {
	Err() error
}

type RawAPIError struct {
	Message string `json:"Error"`
}

// HumanVerificationDetails is the challenge Proton returns with a 9001 error:
// which methods are offered and the token used to render the challenge.
type HumanVerificationDetails struct {
	HumanVerificationMethods []string `json:"HumanVerificationMethods"`
	HumanVerificationToken   string   `json:"HumanVerificationToken"`
}

type APIError struct {
	Code    int
	Message string
	// HV is set when the API rejected the request pending human verification.
	HV *HumanVerificationDetails
}

func (err *APIError) Error() string {
	return fmt.Sprintf("[%v] %v", err.Code, err.Message)
}

type Timestamp int64

func NewTimestamp(t time.Time) Timestamp {
	return Timestamp(t.Unix())
}

func (t Timestamp) Time() time.Time {
	return time.Unix(int64(t), 0)
}

// Client is a ProtonMail API client.
type Client struct {
	RootURL    string
	AppVersion string
	Debug      bool

	HTTPClient *http.Client
	ReAuth     func() error

	uid         string
	accessToken string
	keyRing     openpgp.EntityList

	hvToken string
	hvType  string
}

// Detached returns a client for the same API that never calls ReAuth. The
// re-authentication flow must use it: that flow makes authenticated calls of its
// own (Unlock), and on a 401 they would otherwise call ReAuth again from inside
// ReAuth, recursing until the stack overflows (or deadlocking on a lock).
func (c *Client) Detached() *Client {
	return &Client{RootURL: c.RootURL, AppVersion: c.AppVersion, Debug: c.Debug, HTTPClient: c.HTTPClient}
}

// AdoptSession takes over the authenticated session and unlocked keys of d, a
// client obtained from Detached that has finished authenticating.
func (c *Client) AdoptSession(d *Client) {
	c.uid, c.accessToken, c.keyRing = d.uid, d.accessToken, d.keyRing
}

// SetSession seeds the client with an existing authenticated session (a UID and
// access token obtained elsewhere), so API calls can be made without performing
// a fresh login. Used by the session-import path.
func (c *Client) SetSession(uid, accessToken string) {
	c.uid = uid
	c.accessToken = accessToken
}

// SetHumanVerification attaches a token the account owner obtained by completing
// Proton's challenge in their browser, so a request that returned 9001 can be
// retried. tokenType is the method completed, e.g. "captcha".
func (c *Client) SetHumanVerification(token, tokenType string) {
	c.hvToken = token
	c.hvType = tokenType
}

// ClearHumanVerification removes the one-shot verification token after use.
func (c *Client) ClearHumanVerification() {
	c.hvToken = ""
	c.hvType = ""
}

func (c *Client) setRequestAuthorization(req *http.Request) {
	if c.uid != "" && c.accessToken != "" {
		req.Header.Set("X-Pm-Uid", c.uid)
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
}

func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, c.RootURL+path, body)
	if err != nil {
		return nil, err
	}

	if c.Debug {
		log.Printf(">> %v %v\n", req.Method, req.URL.Path)
	}

	req.Header.Set("X-Pm-Appversion", c.AppVersion)
	req.Header.Set(headerAPIVersion, strconv.Itoa(Version))
	c.setRequestAuthorization(req)
	if c.hvToken != "" {
		req.Header.Set("X-Pm-Human-Verification-Token", c.hvToken)
		req.Header.Set("X-Pm-Human-Verification-Token-Type", c.hvType)
	}
	return req, nil
}

func (c *Client) newJSONRequest(method, path string, body interface{}) (*http.Request, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, err
	}
	b := buf.Bytes()

	req, err := c.newRequest(method, path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	if c.Debug {
		log.Print(string(b))
	}

	req.Header.Set("Content-Type", "application/json")
	req.GetBody = func() (io.ReadCloser, error) {
		return ioutil.NopCloser(bytes.NewReader(b)), nil
	}
	return req, nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0")

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return resp, err
	}

	// Check if access token has expired
	_, hasAuth := req.Header["Authorization"]
	canRetry := req.Body == nil || req.GetBody != nil
	if resp.StatusCode == http.StatusUnauthorized && hasAuth && c.ReAuth != nil && canRetry {
		resp.Body.Close()
		c.accessToken = ""
		if err := c.ReAuth(); err != nil {
			return resp, err
		}
		c.setRequestAuthorization(req) // Access token has changed
		if req.Body != nil {
			body, err := req.GetBody()
			if err != nil {
				return resp, err
			}
			req.Body = body
		}
		return c.do(req)
	}

	return resp, nil
}

func (c *Client) doJSON(req *http.Request, respData interface{}) error {
	req.Header.Set("Accept", "application/json")

	if respData == nil {
		respData = new(resp)
	}

	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(respData); err != nil {
		return err
	}

	if c.Debug {
		log.Printf("<< %v %v", req.Method, req.URL.Path)
		log.Printf("%#v", respData)
	}

	if maybeError, ok := respData.(maybeError); ok {
		if err := maybeError.Err(); err != nil {
			log.Printf("request failed: %v %v: %v", req.Method, req.URL.String(), err)
			return err
		}
	}
	return nil
}
