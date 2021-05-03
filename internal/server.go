package tfa

import (
	"net/http"
	"net/url"

	"github.com/gorilla/mux"

	"github.com/sirupsen/logrus"
)

// Server contains router and handler methods
type Server struct {
	router *mux.Router
	config *Config
}

// NewServer creates a new server object and builds router
func NewServer(config *Config) *Server {
	s := &Server{
		config: config,
	}
	s.buildRoutes()
	return s
}

func (s *Server) buildRoutes() {

	s.router = mux.NewRouter()

	// Add callback handler
	s.router.Handle(s.config.Path(), s.AuthCallbackHandler())

	// Add logout handler
	s.router.Handle(s.config.Path()+"/logout", s.LogoutHandler())

	s.router.NewRoute().Handler(s.AuthHandler())

}

// RootHandler Overwrites the request method, host and URL with those from the
// forwarded request so it's correctly routed by mux
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")
	r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))

	// Pass to mux
	s.router.ServeHTTP(w, r)
}

// AllowHandler Allows requests
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, "Allow", rule, "Allowing request")
		w.WriteHeader(200)
	}
}

// AuthHandler Authenticates requests
func (s *Server) AuthHandler() http.HandlerFunc {
	p := s.config.Provider()

	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "Auth", "", "Authenticating request")

		// Get auth cookie
		c, err := r.Cookie(s.config.CookieName())
		if err != nil {
			s.authRedirect(logger, w, r, p)
			return
		}
		logger.WithField("cookie", c.Value).Warn("Cookie cookie")
		// Validate cookie
		email, err := ValidateCookie(r, c, s.config)
		if err != nil {
			if err.Error() == "Cookie has expired" {
				logger.Info("Cookie has expired")
				s.authRedirect(logger, w, r, p)
			} else {
				logger.WithField("error", err).Warn("Invalid cookie")
				http.Error(w, "Not authorized", http.StatusUnauthorized)
			}
			return
		}

		// Validate user
		// valid := ValidateEmail(email, rule)
		// if !valid {
		// 	logger.WithField("email", email).Warn("Invalid email")
		// 	http.Error(w, "Not authorized", http.StatusUnauthorized)
		// 	return
		// }

		// Valid request
		logger.Debug("Allowing valid request")
		w.Header().Set("X-Forwarded-User", email)
		w.WriteHeader(200)
	}
}

// AuthCallbackHandler Handles auth callback request
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "AuthCallback", "default", "Handling callback")

		// Check state
		state := r.URL.Query().Get("state")
		if err := ValidateState(state); err != nil {
			logger.WithFields(logrus.Fields{
				"error": err,
			}).Warn("Error validating state")
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// Check for CSRF cookie
		c, err := FindCSRFCookie(r, state, s.config)
		if err != nil {
			logger.Info("Missing csrf cookie")
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// Validate CSRF cookie against state
		valid, providerName, redirect, err := ValidateCSRFCookie(c, state)
		if !valid {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
			}).Warn("Error validating csrf cookie")
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// Get provider
		p := s.config.Provider()

		// Clear CSRF cookie
		http.SetCookie(w, ClearCSRFCookie(r, c, s.config))

		// Exchange code for token
		token, err := p.ExchangeCode(redirectUri(r, s.config), r.URL.Query().Get("code"))
		if err != nil {
			logger.WithField("error", err).Error("Code exchange failed with provider")
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}

		// Get user
		user, err := p.GetUser(token)
		if err != nil {
			logger.WithField("error", err).Error("Error getting user")
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}

		// Generate cookie
		http.SetCookie(w, MakeCookie(r, user.Email, s.config))
		logger.WithFields(logrus.Fields{
			"provider": providerName,
			"redirect": redirect,
			"user":     user.Email,
		}).Info("Successfully generated auth cookie, redirecting user.")

		// Redirect
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

// LogoutHandler logs a user out
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Clear cookie
		http.SetCookie(w, ClearCookie(r, s.config))

		logger := s.logger(r, "Logout", "default", "Handling logout")
		logger.Info("Logged out user")

		if s.config.LogoutRedirect() != "" {
			http.Redirect(w, r, s.config.LogoutRedirect(), http.StatusTemporaryRedirect)
		} else {
			http.Error(w, "You have been logged out", http.StatusUnauthorized)
		}
	}
}

func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, p *OIDC) {
	// Error indicates no cookie, generate nonce
	nonce, err := Nonce()
	if err != nil {
		logger.WithField("error", err).Error("Error generating nonce")
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	// Set the CSRF cookie
	csrf := MakeCSRFCookie(r, nonce, s.config)
	http.SetCookie(w, csrf)

	if !s.config.InsecureCookie() && r.Header.Get("X-Forwarded-Proto") != "https" {
		logger.Warn("You are using \"secure\" cookies for a request that was not " +
			"received via https. You should either redirect to https or pass the " +
			"\"insecure-cookie\" config option to permit cookies via http.")
	}

	// Forward them on
	loginURL := p.GetLoginURL(redirectUri(r, s.config), MakeState(r, p, nonce))
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)

	logger.WithFields(logrus.Fields{
		"csrf_cookie": csrf,
		"login_url":   loginURL,
	}).Debug("Set CSRF cookie and redirected to provider login url")
}

func (s *Server) logger(r *http.Request, handler, rule, msg string) *logrus.Entry {
	// Create logger
	logger := log.WithFields(logrus.Fields{
		"handler":   handler,
		"rule":      rule,
		"method":    r.Header.Get("X-Forwarded-Method"),
		"proto":     r.Header.Get("X-Forwarded-Proto"),
		"host":      r.Header.Get("X-Forwarded-Host"),
		"uri":       r.Header.Get("X-Forwarded-Uri"),
		"source_ip": r.Header.Get("X-Forwarded-For"),
	})

	// Log request
	logger.WithFields(logrus.Fields{
		"cookies": r.Cookies(),
	}).Debug(msg)

	return logger
}
