package tfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Request Validation

// ValidateCookie verifies that a cookie matches the expected format of:
// Cookie = hash(secret, cookie domain, email, expires)|expires|email
func ValidateCookie(r *http.Request, c *http.Cookie, config *Config) (string, error) {
	parts := strings.Split(c.Value, "|")

	if len(parts) != 3 {
		return "", errors.New("invalid cookie format")
	}

	mac, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("unable to decode cookie mac")
	}

	expectedSignature := cookieSignature(r, parts[2], parts[1], config)
	expected, err := base64.URLEncoding.DecodeString(expectedSignature)
	if err != nil {
		return "", errors.New("unable to generate mac")
	}

	// Valid token?
	if !hmac.Equal(mac, expected) {
		return "", errors.New("invalid cookie mac")
	}

	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", errors.New("unable to parse cookie expiry")
	}

	// Has it expired?
	if time.Unix(expires, 0).Before(time.Now()) {
		return "", errors.New("cookie has expired")
	}

	// Looks valid
	return parts[2], nil
}

// Utility methods

// Get the redirect base
func redirectBase(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")

	return fmt.Sprintf("%s://%s", proto, host)
}

// Return url
func returnUrl(r *http.Request) string {
	path := r.Header.Get("X-Forwarded-Uri")

	return fmt.Sprintf("%s%s", redirectBase(r), path)
}

// Get oauth redirect uri
func redirectUri(r *http.Request, config *Config) string {
	if use, _ := useAuthDomain(r, config); use {
		proto := r.Header.Get("X-Forwarded-Proto")
		return fmt.Sprintf("%s://%s%s", proto, config.AuthHost(), config.Path())
	}

	return fmt.Sprintf("%s%s", redirectBase(r), config.Path())
}

// Should we use auth host + what it is
func useAuthDomain(r *http.Request, config *Config) (bool, string) {
	if config.AuthHost() == "" {
		return false, ""
	}

	// Does the request match a given cookie domain?
	reqMatch, reqHost := matchCookieDomains(r.Header.Get("X-Forwarded-Host"), config)

	// Do any of the auth hosts match a cookie domain?
	authMatch, authHost := matchCookieDomains(config.AuthHost(), config)

	// We need both to match the same domain
	return reqMatch && authMatch && reqHost == authHost, reqHost
}

// Cookie methods

// MakeCookie creates an auth cookie
func MakeCookie(r *http.Request, email string, config *Config) *http.Cookie {
	expires := cookieExpiry(config)
	mac := cookieSignature(r, email, fmt.Sprintf("%d", expires.Unix()), config)
	value := fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), email)

	return &http.Cookie{
		Name:     config.CookieName(),
		Value:    value,
		Path:     "/",
		Domain:   cookieDomain(r, config),
		HttpOnly: true,
		Secure:   !config.InsecureCookie(),
		Expires:  expires,
	}
}

// ClearCookie clears the auth cookie
func ClearCookie(r *http.Request, config *Config) *http.Cookie {
	return &http.Cookie{
		Name:     config.CookieName(),
		Value:    "",
		Path:     "/",
		Domain:   cookieDomain(r, config),
		HttpOnly: true,
		Secure:   !config.InsecureCookie(),
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

func buildCSRFCookieName(nonce string, config *Config) string {
	return config.CSRFCookieName() + "_" + nonce[:6]
}

// MakeCSRFCookie makes a csrf cookie (used during login only)
//
// Note, CSRF cookies live shorter than auth cookies, a fixed 1h.
// That's because some CSRF cookies may belong to auth flows that don't complete
// and thus may not get cleared by ClearCookie.
func MakeCSRFCookie(r *http.Request, nonce string, config *Config) *http.Cookie {
	return &http.Cookie{
		Name:     buildCSRFCookieName(nonce, config),
		Value:    nonce,
		Path:     "/",
		Domain:   csrfCookieDomain(r, config),
		HttpOnly: true,
		Secure:   !config.InsecureCookie(),
		Expires:  time.Now().Local().Add(time.Hour * 1),
	}
}

// ClearCSRFCookie makes an expired csrf cookie to clear csrf cookie
func ClearCSRFCookie(r *http.Request, c *http.Cookie, config *Config) *http.Cookie {
	return &http.Cookie{
		Name:     c.Name,
		Value:    "",
		Path:     "/",
		Domain:   csrfCookieDomain(r, config),
		HttpOnly: true,
		Secure:   !config.InsecureCookie(),
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

// FindCSRFCookie extracts the CSRF cookie from the request based on state.
func FindCSRFCookie(r *http.Request, state string, config *Config) (c *http.Cookie, err error) {
	// Check for CSRF cookie
	return r.Cookie(buildCSRFCookieName(state, config))
}

// ValidateCSRFCookie validates the csrf cookie against state
func ValidateCSRFCookie(c *http.Cookie, state string) (valid bool, provider string, redirect string, err error) {
	if len(c.Value) != 32 {
		return false, "", "", errors.New("invalid csrf cookie value")
	}

	// Check nonce match
	if c.Value != state[:32] {
		return false, "", "", errors.New("csrf cookie does not match state")
	}

	// Extract provider
	params := state[33:]
	split := strings.Index(params, ":")
	if split == -1 {
		return false, "", "", errors.New("invalid csrf state format")
	}

	// Valid, return provider and redirect
	return true, params[:split], params[split+1:], nil
}

// MakeState generates a state value
func MakeState(r *http.Request, p *OIDC, nonce string) string {
	return fmt.Sprintf("%s:%s:%s", nonce, p.Name(), returnUrl(r))
}

// ValidateState checks whether the state is of right length.
func ValidateState(state string) error {
	if len(state) < 34 {
		return errors.New("invalid csrf state value")
	}
	return nil
}

// Nonce generates a random nonce
func Nonce() (string, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", nonce), nil
}

// Cookie domain
func cookieDomain(r *http.Request, config *Config) string {
	host := r.Header.Get("X-Forwarded-Host")

	// Check if any of the given cookie domains matches
	_, domain := matchCookieDomains(host, config)
	return domain
}

// Cookie domain
func csrfCookieDomain(r *http.Request, config *Config) string {
	var host string
	if use, domain := useAuthDomain(r, config); use {
		host = domain
	} else {
		host = r.Header.Get("X-Forwarded-Host")
	}

	// Remove port
	p := strings.Split(host, ":")
	return p[0]
}

// Return matching cookie domain if exists
func matchCookieDomains(domain string, config *Config) (bool, string) {
	// Remove port
	p := strings.Split(domain, ":")

	for _, d := range config.CookieDomains() {
		if d.Match(p[0]) {
			return true, d.Domain
		}
	}

	return false, p[0]
}

// Create cookie hmac
func cookieSignature(r *http.Request, email, expires string, config *Config) string {
	hash := hmac.New(sha256.New, []byte(config.Secret()))
	hash.Write([]byte(cookieDomain(r, config)))
	hash.Write([]byte(email))
	hash.Write([]byte(expires))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

// Get cookie expiry
func cookieExpiry(config *Config) time.Time {
	return time.Now().Local().Add(config.Lifetime())
}

// CookieDomain holds cookie domain info
type CookieDomain struct {
	Domain       string
	DomainLen    int
	SubDomain    string
	SubDomainLen int
}

// NewCookieDomain creates a new CookieDomain from the given domain string
func NewCookieDomain(domain string) *CookieDomain {
	return &CookieDomain{
		Domain:       domain,
		DomainLen:    len(domain),
		SubDomain:    fmt.Sprintf(".%s", domain),
		SubDomainLen: len(domain) + 1,
	}
}

// Match checks if the given host matches this CookieDomain
func (c *CookieDomain) Match(host string) bool {
	// Exact domain match?
	if host == c.Domain {
		return true
	}

	// Subdomain match?
	if len(host) >= c.SubDomainLen && host[len(host)-c.SubDomainLen:] == c.SubDomain {
		return true
	}

	return false
}

// UnmarshalFlag converts a string to a CookieDomain
func (c *CookieDomain) UnmarshalFlag(value string) error {
	*c = *NewCookieDomain(value)
	return nil
}

// MarshalFlag converts a CookieDomain to a string
func (c *CookieDomain) MarshalFlag() (string, error) {
	return c.Domain, nil
}

// CookieDomains provides legacy sypport for comma separated list of cookie domains
type CookieDomains []CookieDomain

// UnmarshalFlag converts a comma separated list of cookie domains to an array
// of CookieDomains
func (c *CookieDomains) UnmarshalFlag(value string) error {
	if len(value) > 0 {
		for _, d := range strings.Split(value, ",") {
			cookieDomain := NewCookieDomain(d)
			*c = append(*c, *cookieDomain)
		}
	}
	return nil
}

// MarshalFlag converts an array of CookieDomain to a comma seperated list
func (c *CookieDomains) MarshalFlag() (string, error) {
	var domains []string
	for _, d := range *c {
		domains = append(domains, d.Domain)
	}
	return strings.Join(domains, ","), nil
}
