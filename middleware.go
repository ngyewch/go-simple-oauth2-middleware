package go_simple_oauth2_middleware

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/auth0"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
	"io"
	"log/slog"
	"net/http"
	"net/url"
)

type Middleware struct {
	sessionStore *sessions.FilesystemStore
	pathConfig   PathConfig
	config       Config
	authorizers  []Authorizer
}

type PathConfig struct {
	UnauthenticatedPath string
	ForbiddenPathFormat string
	BeginAuthPathMap    map[string]string
	LogoutPath          string
	IgnoredPatterns     []string
	NonRedirectPatterns []string
}

type Config struct {
	SaveRequestUri               bool
	IncludeHostInSavedRequestUri bool
}

const (
	cookieName                = "goth"
	githubProviderName        = "github"
	googleProviderName        = "google"
	auth0ProviderName         = "auth0"
	gothUserSessionKey        = "__gothUser__"
	savedRequestUriSessionKey = "__savedRequestUri__"
	userNotAuthorizedMessage  = "You are not authorized to access this system."
)

// Deprecated: Use NewMiddlewareV2
func NewMiddleware(userDetailsService UserDetailsService, sessionStore *sessions.FilesystemStore, pathConfig PathConfig, config Config) *Middleware {
	return &Middleware{
		sessionStore: sessionStore,
		pathConfig:   pathConfig,
		config:       config,
		authorizers:  []Authorizer{NewDefaultUserAuthorizer(userDetailsService)},
	}
}

func NewMiddlewareV2(sessionStore *sessions.FilesystemStore, pathConfig PathConfig, config Config, authorizers ...Authorizer) *Middleware {
	return &Middleware{
		sessionStore: sessionStore,
		pathConfig:   pathConfig,
		config:       config,
		authorizers:  authorizers,
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
					slog.Error("internal server error",
						slog.Any("err", err),
					)
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
					slog.Error("internal server error",
						slog.Any("err", err),
					)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				if r.URL.Path == u.Path {
					middleware.completeAuthForProviderName(providerName, w, r)
					return
				}
			} else if providerName == auth0ProviderName {
				auth0Provider := provider.(*auth0.Provider)
				u, err := url.Parse(auth0Provider.CallbackURL)
				if err != nil {
					slog.Error("internal server error",
						slog.Any("err", err),
					)
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

		var gothSession goth.Session = nil
		for providerName, _ := range goth.GetProviders() {
			s, err := middleware.getGothSession(providerName, r)
			if err != nil {
				slog.Warn("could not get goth session",
					slog.Any("err", err),
				)
				//http.Error(w, err.Error(), http.StatusInternalServerError)
				//return
			}
			if s != nil {
				gothSession = s
				break
			}
		}

		if gothSession == nil {
			middleware.unauthorized(w, r)
			return
		}

		gothUser, err := middleware.GetGothUser(r)
		if err != nil {
			slog.Error("could not get goth user",
				slog.Any("err", err),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if gothUser == nil {
			middleware.unauthorized(w, r)
			return
		}

		var authorization *Authorization
		for _, authorizer := range middleware.authorizers {
			a, err := authorizer.Authorize(gothUser)
			if err == nil && a != nil {
				authorization = a
				break
			}
		}
		if authorization == nil {
			slog.Warn("user not authorized",
				slog.String("user", gothUser.NickName),
			)
			middleware.forbidden(userNotAuthorizedMessage, w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (middleware *Middleware) beginAuthForProviderName(providerName string, w http.ResponseWriter, r *http.Request) {
	provider, err := goth.GetProvider(providerName)
	if err != nil {
		slog.Error("internal server error",
			slog.Any("err", err),
		)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	state := r.URL.Query().Get("state")
	if len(state) == 0 {
		nonceBytes := make([]byte, 64)
		_, err := io.ReadFull(rand.Reader, nonceBytes)
		if err != nil {
			slog.Error("internal server error",
				slog.Any("err", err),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		state = base64.URLEncoding.EncodeToString(nonceBytes)
	}

	gothSession, err := provider.BeginAuth(state)
	if err != nil {
		slog.Error("internal server error",
			slog.Any("err", err),
		)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authUrl, err := gothSession.GetAuthURL()
	if err != nil {
		slog.Error("internal server error",
			slog.Any("err", err),
		)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = middleware.setGothSession(providerName, gothSession, w, r)
	if err != nil {
		slog.Error("internal server error",
			slog.Any("err", err),
		)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authUrl, http.StatusTemporaryRedirect)
}

func (middleware *Middleware) completeAuthForProviderName(providerName string, w http.ResponseWriter, r *http.Request) {
	gothSession, err := middleware.getGothSession(providerName, r)
	if err != nil {
		slog.Error("internal server error",
			slog.Any("err", err),
		)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rawAuthURL, err := gothSession.GetAuthURL()
	if err != nil {
		slog.Error("internal server error",
			slog.Any("err", err),
		)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authURL, err := url.Parse(rawAuthURL)
	if err != nil {
		slog.Error("internal server error",
			slog.Any("err", err),
		)
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
		slog.Error("internal server error",
			slog.Any("err", err),
		)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		slog.Error("internal server error",
			slog.Any("err", err),
		)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	gothUser, err := provider.FetchUser(gothSession)
	if err != nil {
		params := r.URL.Query()
		if params.Encode() == "" && r.Method == "POST" {
			err = r.ParseForm()
			if err != nil {
				slog.Error("internal server error",
					slog.Any("err", err),
				)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			params = r.Form
		}

		// get new token and retry fetch
		_, err = gothSession.Authorize(provider, params)
		if err != nil {
			slog.Error("internal server error",
				slog.Any("err", err),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = middleware.setGothSession(providerName, gothSession, w, r)
		if err != nil {
			slog.Error("internal server error",
				slog.Any("err", err),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		gothUser, err = provider.FetchUser(gothSession)
		if err != nil {
			slog.Error("internal server error",
				slog.Any("err", err),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	err = middleware.setGothUser(gothUser, w, r)
	if err != nil {
		slog.Error("internal server error",
			slog.Any("err", err),
		)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, err := middleware.sessionStore.Get(r, cookieName)
	if err != nil {
		slog.Error("internal server error",
			slog.Any("err", err),
		)
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
		slog.Error("internal server error",
			slog.Any("err", err),
		)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for key := range session.Values {
		delete(session.Values, key)
	}

	err = session.Save(r, w)
	if err != nil {
		slog.Error("internal server error",
			slog.Any("err", err),
		)
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
			slog.Warn("could not get session",
				slog.Any("err", err),
			)
			//http.Error(w, err.Error(), http.StatusInternalServerError)
			//return
		}

		if session == nil {
			session, err = middleware.sessionStore.New(r, cookieName)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if middleware.config.SaveRequestUri {
			if middleware.config.IncludeHostInSavedRequestUri {
				session.Values[savedRequestUriSessionKey] = "//" + r.Host + r.RequestURI
			} else {
				session.Values[savedRequestUriSessionKey] = r.RequestURI
			}
		}

		err = session.Save(r, w)
		if err != nil {
			slog.Error("internal server error",
				slog.Any("err", err),
			)
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

	gothUserBytes, ok := value.([]byte)
	if !ok {
		return nil, nil
	}

	var gothUser goth.User
	err = json.Unmarshal(gothUserBytes, &gothUser)
	if err != nil {
		return nil, err
	}

	return &gothUser, nil
}

func (middleware *Middleware) setGothUser(gothUser goth.User, w http.ResponseWriter, r *http.Request) error {
	session, err := middleware.sessionStore.Get(r, cookieName)
	if err != nil {
		return err
	}

	gothUserBytes, err := json.Marshal(gothUser)
	if err != nil {
		return err
	}

	session.Values[gothUserSessionKey] = gothUserBytes
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
