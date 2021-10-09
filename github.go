package go_simple_oauth2_middleware

import (
	"encoding/json"
	"fmt"
	"github.com/markbates/goth"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

type GitHubOrg struct {
	Login            string `json:"login"`
	Id               int    `json:"id"`
	NodeId           string `json:"node_id"`
	Url              string `json:"url"`
	ReposUrl         string `json:"repos_url"`
	EventsUrl        string `json:"events_url"`
	HooksUrl         string `json:"hooks_url"`
	IssuesUrl        string `json:"issues_url"`
	MembersUrl       string `json:"members_url"`
	PublicMembersUrl string `json:"public_members_url"`
	AvatarUrl        string `json:"avatar_url"`
	Description      string `json:"description"`
}

func GetGithubOrgs(gothUser *goth.User) ([]GitHubOrg, error) {
	if gothUser.Provider != githubProviderName {
		return nil, nil
	}
	// https://developer.github.com/v3/orgs/#list-your-organizations
	client := &http.Client{}
	orgs := make([]GitHubOrg, 0)
	perPage := 100
	page := 1
	for {
		params := url.Values{
			"per_page": {strconv.Itoa(perPage)},
			"page":     {strconv.Itoa(page)},
		}

		endpoint := &url.URL{
			Scheme:   "https",
			Host:     "api.github.com",
			Path:     "/user/orgs",
			RawQuery: params.Encode(),
		}

		req, err := http.NewRequest("GET", endpoint.String(), nil)
		req.Header.Add("Accept", "application/vnd.github.v3+json")
		req.Header.Add("Authorization", fmt.Sprintf("token %s", gothUser.AccessToken))
		rsp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if rsp.StatusCode != http.StatusOK {
			break
		}
		rspBytes, err := io.ReadAll(rsp.Body)
		if err != nil {
			return nil, err
		}
		var orgsPage []GitHubOrg
		err = json.Unmarshal(rspBytes, &orgsPage)
		if err != nil {
			return nil, err
		}
		if len(orgsPage) == 0 {
			break
		}
		orgs = append(orgs, orgsPage...)
		page++
	}
	return orgs, nil
}
