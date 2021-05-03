package tfa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pnocera/oidc-forwardauth/internal/provider"
	"github.com/thomseddon/go-flags"
)

var config *Config

// Config holds the runtime application config
type Config struct {
	LogLevel  string `long:"log-level" env:"LOG_LEVEL" default:"warn" description:"Log level"`
	LogFormat string `long:"log-format"  env:"LOG_FORMAT" default:"text" description:"Log format"`

	AuthHost               string               `long:"auth-host" env:"AUTH_HOST" description:"Single host to use when returning from 3rd party auth"`
	Config                 func(s string) error `long:"config" env:"CONFIG" description:"Path to config file" json:"-"`
	CookieDomains          []CookieDomain       `long:"cookie-domain" env:"COOKIE_DOMAIN" env-delim:"," description:"Domain to set auth cookie on, can be set multiple times"`
	InsecureCookie         bool                 `long:"insecure-cookie" env:"INSECURE_COOKIE" description:"Use insecure cookies"`
	CookieName             string               `long:"cookie-name" env:"COOKIE_NAME" default:"_forward_auth" description:"Cookie Name"`
	CSRFCookieName         string               `long:"csrf-cookie-name" env:"CSRF_COOKIE_NAME" default:"_forward_auth_csrf" description:"CSRF Cookie Name"`
	DefaultAction          string               `long:"default-action" env:"DEFAULT_ACTION" default:"auth" description:"Default action"`
	DefaultProvider        string               `long:"default-provider" env:"DEFAULT_PROVIDER" default:"oidc" description:"Default provider"`
	Domains                CommaSeparatedList   `long:"domain" env:"DOMAIN" env-delim:"," description:"Only allow given email domains, can be set multiple times"`
	LifetimeString         int                  `long:"lifetime" env:"LIFETIME" default:"43200" description:"Lifetime in seconds"`
	LogoutRedirect         string               `long:"logout-redirect" env:"LOGOUT_REDIRECT" description:"URL to redirect to following logout"`
	MatchWhitelistOrDomain bool                 `long:"match-whitelist-or-domain" env:"MATCH_WHITELIST_OR_DOMAIN" description:"Allow users that match *either* whitelist or domain (enabled by default in v3)"`
	Path                   string               `long:"url-path" env:"URL_PATH" default:"/_oauth" description:"Callback URL Path"`
	SecretString           string               `long:"secret" env:"SECRET" description:"Secret used for signing (required)" json:"-"`
	Whitelist              CommaSeparatedList   `long:"whitelist" env:"WHITELIST" env-delim:"," description:"Only allow given email addresses, can be set multiple times"`
	Port                   int                  `long:"port" env:"PORT" default:"4181" description:"Port to listen on"`

	Providers provider.Providers `group:"providers" namespace:"providers" env-namespace:"PROVIDERS"`

	// Filled during transformations
	Secret   []byte `json:"-"`
	Lifetime time.Duration

	// Legacy
	CookieDomainsLegacy CookieDomains `long:"cookie-domains" env:"COOKIE_DOMAINS" description:"DEPRECATED - Use \"cookie-domain\""`
	CookieSecretLegacy  string        `long:"cookie-secret" env:"COOKIE_SECRET" description:"DEPRECATED - Use \"secret\""  json:"-"`
	CookieSecureLegacy  string        `long:"cookie-secure" env:"COOKIE_SECURE" description:"DEPRECATED - Use \"insecure-cookie\""`
	ClientIdLegacy      string        `long:"client-id" env:"CLIENT_ID" description:"DEPRECATED - Use \"providers.google.client-id\""`
	ClientSecretLegacy  string        `long:"client-secret" env:"CLIENT_SECRET" description:"DEPRECATED - Use \"providers.google.client-id\""  json:"-"`
	PromptLegacy        string        `long:"prompt" env:"PROMPT" description:"DEPRECATED - Use \"providers.google.prompt\""`
}

// NewGlobalConfig creates a new global config, parsed from command arguments
func NewGlobalConfig() *Config {
	var err error
	config, err = NewConfig(os.Args[1:])
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}

	return config
}

// TODO: move config parsing into new func "NewParsedConfig"

// NewConfig parses and validates provided configuration into a config object
func NewConfig(args []string) (*Config, error) {
	c := &Config{}

	err := c.parseFlags(args)
	if err != nil {
		return c, err
	}

	// TODO: as log flags have now been parsed maybe we should return here so
	// any further errors can be logged via logrus instead of printed?

	// TODO: Rename "Validate" method to "Setup" and move all below logic

	// Transformations
	if len(c.Path) > 0 && c.Path[0] != '/' {
		c.Path = "/" + c.Path
	}
	c.Secret = []byte(c.SecretString)
	c.Lifetime = time.Second * time.Duration(c.LifetimeString)

	return c, nil
}

func (c *Config) parseFlags(args []string) error {
	p := flags.NewParser(c, flags.Default|flags.IgnoreUnknown)

	i := flags.NewIniParser(p)
	c.Config = func(s string) error {
		// Try parsing at as an ini
		err := i.ParseFile(s)

		// If it fails with a syntax error, try converting legacy to ini
		if err != nil && strings.Contains(err.Error(), "malformed key=value") {
			converted, convertErr := convertLegacyToIni(s)
			if convertErr != nil {
				// If conversion fails, return the original error
				return err
			}

			fmt.Println("config format deprecated, please use ini format")
			return i.Parse(converted)
		}

		return err
	}

	_, err := p.ParseArgs(args)
	if err != nil {
		return handleFlagError(err)
	}

	return nil
}

func handleFlagError(err error) error {
	flagsErr, ok := err.(*flags.Error)
	if ok && flagsErr.Type == flags.ErrHelp {
		// Library has just printed cli help
		os.Exit(0)
	}

	return err
}

var legacyFileFormat = regexp.MustCompile(`(?m)^([a-z-]+) (.*)$`)

func convertLegacyToIni(name string) (io.Reader, error) {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(legacyFileFormat.ReplaceAll(b, []byte("$1=$2"))), nil
}

// Validate validates a config object
func (c *Config) Validate() {
	// Check for show stopper errors
	if len(c.Secret) == 0 {
		log.Fatal("\"secret\" option must be set")
	}

	// Setup default provider
	err := c.setupProvider(c.DefaultProvider)
	if err != nil {
		log.Fatal(err)
	}

}

func (c Config) String() string {
	jsonConf, _ := json.Marshal(c)
	return string(jsonConf)
}

// GetConfiguredProvider returns the provider of the given name, if it has been
// configured. Returns an error if the provider is unknown, or hasn't been configured
func (c *Config) GetConfiguredProvider(name string) (provider.Provider, error) {
	return &c.Providers.OIDC, nil
}

func (c *Config) setupProvider(name string) error {
	// Check provider exists
	p := &c.Providers.OIDC

	// Setup
	err := p.Setup()
	if err != nil {
		return err
	}

	return nil
}

// CommaSeparatedList provides legacy support for config values provided as csv
type CommaSeparatedList []string

// UnmarshalFlag converts a comma separated list to an array
func (c *CommaSeparatedList) UnmarshalFlag(value string) error {
	*c = append(*c, strings.Split(value, ",")...)
	return nil
}

// MarshalFlag converts an array back to a comma separated list
func (c *CommaSeparatedList) MarshalFlag() (string, error) {
	return strings.Join(*c, ","), nil
}
