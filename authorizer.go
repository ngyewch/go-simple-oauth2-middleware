package go_simple_oauth2_middleware

import (
	"errors"
	"github.com/markbates/goth"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrAccountDisabled    = errors.New("account disabled")
	ErrAccountExpired     = errors.New("account expired")
	ErrAccountLocked      = errors.New("account locked")
	ErrCredentialsExpired = errors.New("credentials expired")
)

type Authorization struct {
	User        *goth.User `json:"user"`
	Authorities []string   `json:"authorities"`
}

type Authorizer interface {
	Authorize(user *goth.User) (*Authorization, error)
}
