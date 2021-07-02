package go_simple_oauth2_middleware

import "github.com/markbates/goth"

type UserDetailsService interface {
	GetUserDetails(user *goth.User) (*UserDetails, bool, error)
}

type UserDetails struct {
	UserID             string
	NickName           string
	Email              string
	Authorities        []string
	AccountDisabled    bool
	AccountExpired     bool
	AccountLocked      bool
	CredentialsExpired bool
}
