package go_simple_oauth2_middleware

import (
	"github.com/markbates/goth"
)

type GithubOrgAuthorizer struct {
	orgEntries []*githubOrgEntry
}

type githubOrgEntry struct {
	name        string
	authorities []string
}

func NewGithubOrgAuthorizer() *GithubOrgAuthorizer {
	return &GithubOrgAuthorizer{
		orgEntries: make([]*githubOrgEntry, 0),
	}
}

func (authorizer *GithubOrgAuthorizer) AddOrg(name string, authorities []string) {
	authorizer.orgEntries = append(authorizer.orgEntries, &githubOrgEntry{
		name:        name,
		authorities: authorities,
	})
}

func (authorizer *GithubOrgAuthorizer) Authorize(user *goth.User) (*Authorization, error) {
	if user.Provider != githubProviderName {
		return nil, nil
	}
	userOrgs, err := GetGithubOrgs(user)
	if err != nil {
		return nil, err
	}
	if userOrgs == nil {
		return nil, nil
	}
	for _, userOrg := range userOrgs {
		for _, orgEntry := range authorizer.orgEntries {
			if orgEntry.name == userOrg.Login {
				return &Authorization{
					User:        user,
					Authorities: orgEntry.authorities,
				}, nil
			}
		}
	}
	return nil, nil
}
