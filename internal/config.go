package tfa

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

//var config *Config

// Config holds the runtime application config
type Config struct {
	v         *viper.Viper
	Providers Providers
}

// NewConfig creates a new global config, parsed from command arguments
func NewConfig() *Config {
	c := Config{
		v: viper.New(),
	}
	c.v.SetDefault("PORT", 4181)
	c.v.SetDefault("INSECURE_COOKIE", false)
	c.v.SetDefault("LOG_LEVEL", "error")
	c.v.SetDefault("LOG_FORMAT", "json")
	c.v.SetDefault("SCOPE", "openid profile")
	c.v.SetDefault("PROVIDERS_OIDC_ISSUER_URL", "")
	c.v.SetDefault("PROVIDERS_OIDC_CLIENT_ID", "")
	c.v.SetDefault("PROVIDERS_OIDC_CLIENT_SECRET", "")
	c.v.SetDefault("SECRET", "")
	c.v.SetDefault("COOKIE_NAME", "_forward_auth")
	c.v.SetDefault("CSRF_COOKIE_NAME", "_forward_auth_csrf")
	c.v.SetDefault("URL_PATH", "/_oauth")
	c.v.SetDefault("LIFETIME", 43200)
	c.v.SetDefault("AUTH_HOST", "")
	c.v.SetDefault("LOGOUT_REDIRECT", "")
	c.v.SetDefault("COOKIE_DOMAIN", "")
	c.v.AutomaticEnv()

	return &c
}

func (c *Config) Port() int64 {
	return c.v.GetInt64("PORT")
}

func (c *Config) InsecureCookie() bool {
	return c.v.GetBool("INSECURE_COOKIE")
}

func (c *Config) LogLevel() string {
	return c.v.GetString("LOG_LEVEL")
}

func (c *Config) Scope() string {
	return c.v.GetString("SCOPE")
}

func (c *Config) IssuerUrl() string {
	return c.v.GetString("PROVIDERS_OIDC_ISSUER_URL")
}

func (c *Config) ClientID() string {
	return c.v.GetString("PROVIDERS_OIDC_CLIENT_ID")
}

func (c *Config) ClientSecret() string {
	return c.v.GetString("PROVIDERS_OIDC_CLIENT_SECRET")
}

func (c *Config) Secret() string {
	return c.v.GetString("SECRET")
}

func (c *Config) LogFormat() string {
	return c.v.GetString("LOG_FORMAT")
}

func (c *Config) CookieName() string {
	return c.v.GetString("COOKIE_NAME")
}

func (c *Config) CSRFCookieName() string {
	return c.v.GetString("CSRF_COOKIE_NAME")
}

func (c *Config) Path() string {
	return c.v.GetString("URL_PATH")
}

func (c *Config) AuthHost() string {
	return c.v.GetString("AUTH_HOST")
}

func (c *Config) Lifetime() time.Duration {
	return time.Second * time.Duration(c.v.GetInt("LIFETIME"))

}

func (c *Config) Provider() *OIDC {
	var oidc = &c.Providers.OIDC
	oidc.Setup(c)
	return oidc
}

func (c *Config) LogoutRedirect() string {
	return c.v.GetString("LOGOUT_REDIRECT")
}

func (c *Config) CookieDomains() []*CookieDomain {
	domains := c.v.GetString("COOKIE_DOMAIN")
	parts := strings.Split(domains, ",")
	var cds []*CookieDomain
	for _, d := range parts {
		cds = append(cds, NewCookieDomain(d))
	}
	return cds
}
