package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-github/v50/github"
	"golang.org/x/oauth2"
)

type Client struct {
	client *github.Client
	config *oauth2.Config
}

func NewClient(clientID, clientSecret, redirectURI string) *Client {
	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes:       []string{"repo"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
	}

	return &Client{
		client: github.NewClient(nil),
		config: conf,
	}
}

func (c *Client) GetAuthURL(state string) string {
	return c.config.AuthCodeURL(state)
}

func (c *Client) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return c.config.Exchange(ctx, code)
}

func (c *Client) NewClientWithToken(token *oauth2.Token) *github.Client {
	return c.client.WithAuthToken(token.AccessToken)
}

func (c *Client) GetRepoContents(ctx context.Context, client *github.Client, owner, repo, path string) ([]*github.RepositoryContent, error) {
	_, dirContent, _, err := client.Repositories.GetContents(ctx, owner, repo, path, nil)
	return dirContent, err
}

func (c *Client) DownloadRepoArchive(ctx context.Context, client *github.Client, owner, repo, ref string) (*url.URL, error) {
	opts := &github.RepositoryContentGetOptions{
		Ref: ref,
	}
	archiveLink, _, err := client.Repositories.GetArchiveLink(ctx, owner, repo, github.Tarball, opts, true)
	return archiveLink, err
}

func (c *Client) ParseGitHubURL(repoURL string) (owner, repo string, err error) {
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL: %v", err)
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid GitHub repository URL")
	}

	return parts[0], parts[1], nil
}

// HandleGitHubCallback handles the OAuth callback from GitHub
func (c *Client) HandleGitHubCallback(w http.ResponseWriter, r *http.Request) (string, *oauth2.Token, error) {
	state := r.FormValue("state")
	code := r.FormValue("code")

	if state != r.URL.Query().Get("state") {
		return "", nil, fmt.Errorf("invalid state")
	}

	token, err := c.ExchangeCode(r.Context(), code)
	if err != nil {
		return "", nil, fmt.Errorf("could not exchange code for token: %v", err)
	}

	return state, token, nil
}