package github

import (
	"context"
	"fmt"
	"log"
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
	log.Printf("[GITHUB] Exchanging code: %s", code)

	client := &http.Client{
		Transport: &acceptHeaderTransport{},
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	token, err := c.config.Exchange(ctx, code)
	if err != nil {
		if oauthErr, ok := err.(*oauth2.RetrieveError); ok {
			log.Printf("[GITHUB ERROR] OAuth2 error: %s\nResponse: %s",
				oauthErr.Error(), string(oauthErr.Body))
		}
		return nil, err
	}

	log.Printf("[GITHUB] Token received - Type: %s, Expiry: %v, Scopes: %v",
		token.TokenType, token.Expiry, token.Extra("scope"))
	return token, nil
}

func (c *Client) NewClientWithToken(token *oauth2.Token) *github.Client {
	ts := oauth2.StaticTokenSource(token)
	tc := oauth2.NewClient(context.Background(), ts)
	return github.NewClient(tc)
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

func (c *Client) GetUserRepos(ctx context.Context, client *github.Client) ([]*github.Repository, error) {
	// List all repositories for the authenticated user
	repos, _, err := client.Repositories.List(ctx, "", &github.RepositoryListOptions{
		Sort: "updated",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	})
	return repos, err
}

// acceptHeaderTransport ensures the GitHub token exchange response is JSON
type acceptHeaderTransport struct{}

func (t *acceptHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Accept", "application/json")
	return http.DefaultTransport.RoundTrip(req)
}
