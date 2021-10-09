package go_simple_oauth2_middleware

import (
	"github.com/markbates/goth"
)

type DefaultUserAuthorizer struct {
	userDetailsService UserDetailsService
}

func NewDefaultUserAuthorizer(userDetailsService UserDetailsService) *DefaultUserAuthorizer {
	return &DefaultUserAuthorizer{
		userDetailsService: userDetailsService,
	}
}

func (authorizer *DefaultUserAuthorizer) Authorize(user *goth.User) (*Authorization, error) {
	userDetails, exists, err := authorizer.userDetailsService.GetUserDetails(user)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrUserNotFound
	}
	if userDetails.AccountDisabled {
		return nil, ErrAccountDisabled
	}
	if userDetails.AccountExpired {
		return nil, ErrAccountExpired
	}
	if userDetails.AccountLocked {
		return nil, ErrAccountLocked
	}
	if userDetails.CredentialsExpired {
		return nil, ErrCredentialsExpired
	}
	return &Authorization{
		User:        user,
		Authorities: make([]string, 0),
	}, nil
}
