package go_simple_oauth2_middleware

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/bmatcuk/doublestar/v4"
	slog "github.com/go-eden/slf4go"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
	"io"
	"net/http"
	"net/url"
)

type Middleware struct {
	userDetailsService  UserDetailsService
	sessionStore        *sessions.FilesystemStore
	pathConfig          PathConfig
}

type PathConfig struct {
	UnauthenticatedPath string
	ForbiddenPathFormat string
	BeginAuthPathMap    map[string]string
	LogoutPath          string
	IgnoredPatterns     []string
	NonRedirectPatterns []string
}

const (
	cookieName                    = "goth"
	githubProviderName            = "github"
	googleProviderName            = "google"
	gothUserSessionKey            = "__gothUser__"
	savedRequestUriSessionKey     = "__savedRequestUri__"
	userNotFoundMessage           = "You are not authorized to access this system."
	userAccountDisabledMessage    = "You are not authorized to access this system."
	userAccountExpiredMessage     = "You are not authorized to access this system."
	userAccountLockedMessage      = "You are not authorized to access this system."
	userCredentialsExpiredMessage = "You are not authorized to access this system."
)

var (
	logger slog.Logger
)

func init() {
	logger = slog.GetLogger()
}

func NewMiddleware(userDetailsService UserDetailsService, sessionStore *sessions.FilesystemStore, pathConfig PathConfig) *Middleware {
	return &Middleware{
		userDetailsService: userDetailsService,
		sessionStore:       sessionStore,
		pathConfig:         pathConfig,
	}
}

func (middleware *Middleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for providerName, provider := range goth.GetProviders() {
			beginAuthPath, ok := middleware.pathConfig.BeginAuthPathMap[providerName]
			if ok {
				if r.URL.Path == beginAuthPath {
					middleware.beginAuthForProviderName(providerName, w, r)
					return
				}
			}
			if providerName == githubProviderName {
				githubProvider := provider.(*github.Provider)
				u, err := url.Parse(githubProvider.CallbackURL)
				if err != nil {
					logger.Fatalf("%v", err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				if r.URL.Path == u.Path {
					middleware.completeAuthForProviderName(providerName, w, r)
					return
				}
			} else if providerName == googleProviderName {
				googleProvider := provider.(*google.Provider)
				u, err := url.Parse(googleProvider.CallbackURL)
				if err != nil {
					logger.Fatalf("%v", err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				if r.URL.Path == u.Path {
					middleware.completeAuthForProviderName(providerName, w, r)
					return
				}
			}
		}
		if middleware.pathConfig.LogoutPath != "" {
			if r.URL.Path == middleware.pathConfig.LogoutPath {
				middleware.logout(w, r)
				return
			}
		}

		if matchUri(r.URL.Path, middleware.pathConfig.IgnoredPatterns) {
			// this is not a secured URI
			next.ServeHTTP(w, r)
			return
		}

		gothSession, err := middleware.getGothSession(githubProviderName, r)
		if err != nil {
			logger.Fatalf("%v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if gothSession == nil {
			middleware.unauthorized(w, r)
			return
		}

		gothUser, err := middleware.GetGothUser(r)
		if err != nil {
			logger.Fatalf("%v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if gothUser == nil {
			middleware.unauthorized(w, r)
			return
		}

		userDetails, exists, err := middleware.userDetailsService.GetUserDetails(gothUser)
		if err != nil {
			logger.Fatalf("%v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !exists {
			logger.Warnf("user %s does not exist", gothUser.NickName)
			middleware.forbidden(userNotFoundMessage, w, r)
			return
		}
		if userDetails.AccountDisabled {
			logger.Warnf("user %s account disabled", gothUser.NickName)
			middleware.forbidden(userAccountDisabledMessage, w, r)
			return
		}
		if userDetails.AccountExpired {
			logger.Warnf("user %s account expired", gothUser.NickName)
			middleware.forbidden(userAccountExpiredMessage, w, r)
			return
		}
		if userDetails.AccountLocked {
			logger.Warnf("user %s account locked", gothUser.NickName)
			middleware.forbidden(userAccountLockedMessage, w, r)
			return
		}
		if userDetails.CredentialsExpired {
			logger.Warnf("user %s credentials expired", gothUser.NickName)
			middleware.forbidden(userCredentialsExpiredMessage, w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (middleware *Middleware) beginAuthForProviderName(providerName string, w http.ResponseWriter, r *http.Request) {
	provider, err := goth.GetProvider(providerName)
	if err != nil {
		logger.Fatalf("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	state := r.URL.Query().Get("state")
	if len(state) == 0 {
		nonceBytes := make([]byte, 64)
		_, err := io.ReadFull(rand.Reader, nonceBytes)
		if err != nil {
			logger.Fatalf("%v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		state = base64.URLEncoding.EncodeToString(nonceBytes)
	}

	gothSession, err := provider.BeginAuth(state)
	if err != nil {
		logger.Fatalf("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authUrl, err := gothSession.GetAuthURL()
	if err != nil {
		logger.Fatalf("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = middleware.setGothSession(providerName, gothSession, w, r)
	if err != nil {
		logger.Fatalf("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authUrl, http.StatusTemporaryRedirect)
}

func (middleware *Middleware) completeAuthForProviderName(providerName string, w http.ResponseWriter, r *http.Request) {
	gothSession, err := middleware.getGothSession(providerName, r)
	if err != nil {
		logger.Fatalf("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rawAuthURL, err := gothSession.GetAuthURL()
	if err != nil {
		logger.Fatalf("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authURL, err := url.Parse(rawAuthURL)
	if err != nil {
		logger.Fatalf("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	params := r.URL.Query()
	reqState := params.Get("state")
	if params.Encode() == "" && r.Method == http.MethodPost {
		reqState = r.FormValue("state")
	}

	originalState := authURL.Query().Get("state")
	if originalState != "" && (originalState != reqState) {
		err = errors.New("state token mismatch")
		logger.Fatalf("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		logger.Fatalf("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	gothUser, err := provider.FetchUser(gothSession)
	if err != nil {
		params := r.URL.Query()
		if params.Encode() == "" && r.Method == "POST" {
			err = r.ParseForm()
			if err != nil {
				logger.Fatalf("%v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			params = r.Form
		}

		// get new token and retry fetch
		_, err = gothSession.Authorize(provider, params)
		if err != nil {
			logger.Fatalf("%v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = middleware.setGothSession(providerName, gothSession, w, r)
		if err != nil {
			logger.Fatalf("%v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		gothUser, err = provider.FetchUser(gothSession)
		if err != nil {
			logger.Fatalf("%v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	err = middleware.setGothUser(gothUser, w, r)
	if err != nil {
		logger.Fatalf("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, err := middleware.sessionStore.Get(r, cookieName)
	if err != nil {
		logger.Fatalf("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	redirectUrl := "/"
	savedRequestUri, ok := session.Values[savedRequestUriSessionKey]
	if ok {
		redirectUrl = savedRequestUri.(string)
	}

	http.Redirect(w, r, redirectUrl, http.StatusTemporaryRedirect)
}

func (middleware *Middleware) logout(w http.ResponseWriter, r *http.Request) {
	session, err := middleware.sessionStore.Get(r, cookieName)
	if err != nil {
		logger.Fatalf("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for key := range session.Values {
		delete(session.Values, key)
	}

	err = session.Save(r, w)
	if err != nil {
		logger.Fatalf("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (middleware *Middleware) unauthorized(w http.ResponseWriter, r *http.Request) {
	if matchUri(r.URL.Path, middleware.pathConfig.NonRedirectPatterns) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	} else {
		session, err := middleware.sessionStore.Get(r, cookieName)
		if err != nil {
			logger.Fatalf("%v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session.Values[savedRequestUriSessionKey] = r.RequestURI

		err = session.Save(r, w)
		if err != nil {
			logger.Fatalf("%v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, middleware.pathConfig.UnauthenticatedPath, http.StatusTemporaryRedirect)
	}
}

func (middleware *Middleware) forbidden(message string, w http.ResponseWriter, r *http.Request) {
	if matchUri(r.URL.Path, middleware.pathConfig.NonRedirectPatterns) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	} else {
		forbiddenUrl := fmt.Sprintf(middleware.pathConfig.ForbiddenPathFormat, url.QueryEscape(message))
		http.Redirect(w, r, forbiddenUrl, http.StatusTemporaryRedirect)
	}
}

func (middleware *Middleware) getGothSession(providerName string, r *http.Request) (goth.Session, error) {
	session, err := middleware.sessionStore.Get(r, cookieName)
	if err != nil {
		return nil, err
	}

	marshalledGothSession, ok := session.Values[providerName]
	if !ok {
		return nil, nil
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	gothSession, err := provider.UnmarshalSession(marshalledGothSession.(string))
	if err != nil {
		return nil, err
	}

	return gothSession, nil
}

func (middleware *Middleware) setGothSession(providerName string, gothSession goth.Session, w http.ResponseWriter, r *http.Request) error {
	session, err := middleware.sessionStore.Get(r, cookieName)
	if err != nil {
		return err
	}

	session.Values[providerName] = gothSession.Marshal()
	err = session.Save(r, w)
	if err != nil {
		return err
	}

	return nil
}

func (middleware *Middleware) GetGothUser(r *http.Request) (*goth.User, error) {
	session, err := middleware.sessionStore.Get(r, cookieName)
	if err != nil {
		return nil, err
	}

	value, ok := session.Values[gothUserSessionKey]
	if !ok {
		return nil, nil
	}

	gothUser := value.(goth.User)
	return &gothUser, nil
}

func (middleware *Middleware) setGothUser(gothUser goth.User, w http.ResponseWriter, r *http.Request) error {
	session, err := middleware.sessionStore.Get(r, cookieName)
	if err != nil {
		return err
	}

	session.Values[gothUserSessionKey] = gothUser
	err = session.Save(r, w)
	if err != nil {
		return err
	}

	return nil
}

func matchUri(uri string, uriPatterns []string) bool {
	for _, uriPattern := range uriPatterns {
		match, _ := doublestar.Match(uriPattern, uri)
		if match {
			return true
		}
	}
	return false
}
