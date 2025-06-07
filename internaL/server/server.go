package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/AbdullahTarar/helm-guard-be/internal/config"
	"helm-scanner/internal/github"
	"helm-scanner/internal/helm"
)

type Server struct {
	router      *mux.Router
	config      *config.Config
	github      *github.Client
	helmScanner *helm.Scanner
	store       *sessions.CookieStore
}

func New(cfg *config.Config) (*Server, error) {
	// Initialize GitHub client
	ghClient := github.NewClient(
		cfg.GitHub.ClientID,
		cfg.GitHub.ClientSecret,
		cfg.GitHub.RedirectURI,
	)

	// Initialize Helm scanner
	helmScanner, err := helm.NewScanner(cfg.Helm.TempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Helm scanner: %v", err)
	}

	// Initialize session store
	store := sessions.NewCookieStore([]byte(cfg.Security.CookieSecret))

	// Create server
	srv := &Server{
		router:      mux.NewRouter(),
		config:      cfg,
		github:      ghClient,
		helmScanner: helmScanner,
		store:       store,
	}

	// Setup routes
	srv.routes()

	return srv, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}
func (s *Server) routes() {
    // Add CORS middleware
    s.router.Use(func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000") // Your frontend URL
            w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
            w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
            w.Header().Set("Access-Control-Allow-Credentials", "true")
            
            if r.Method == "OPTIONS" {
                w.WriteHeader(http.StatusOK)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    })

    // Your existing routes
    s.router.HandleFunc("/api/scan/public", s.handlePublicRepoScan).Methods("POST", "OPTIONS")
    s.router.HandleFunc("/api/github/auth", s.handleGitHubAuth).Methods("GET")
    s.router.HandleFunc("/api/github/callback", s.handleGitHubCallback).Methods("GET")
    s.router.HandleFunc("/api/scan/private", s.handlePrivateRepoScan).Methods("POST", "OPTIONS")
    s.router.HandleFunc("/api/scan/results/{id}", s.handleGetScanResults).Methods("GET")
}

func (s *Server) handlePublicRepoScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RepoURL string `json:"repoUrl"`
		Path    string `json:"path,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Parse GitHub URL
	owner, repo, err := s.github.ParseGitHubURL(req.RepoURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// For public repos, we can use the GitHub API without authentication
	// Construct the download URL for the latest release or master branch
	downloadURL := fmt.Sprintf("https://github.com/%s/%s/archive/refs/heads/main.tar.gz", owner, repo)

	// Download and extract the chart
	chartPath, err := s.helmScanner.DownloadAndExtractChart(r.Context(), downloadURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to download chart: %v", err), http.StatusInternalServerError)
		return
	}

	// If a specific path is provided, use that
	if req.Path != "" {
		chartPath = filepath.Join(chartPath, req.Path)
	}

	// Analyze the chart
	analysis, err := s.helmScanner.AnalyzeChart(chartPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to analyze chart: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate a result ID
	resultID := uuid.New().String()

	// Store the results (in a real app, you'd use a database)
	// For now, we'll just return them
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       resultID,
		"results":  analysis,
		"metadata": map[string]string{
			"repo": req.RepoURL,
			"path": req.Path,
		},
	})
}

func (s *Server) handleGitHubAuth(w http.ResponseWriter, r *http.Request) {
	// Generate a state token
	state := uuid.New().String()

	// Store the state in the session
	session, _ := s.store.Get(r, "helm-scanner-session")
	session.Values["state"] = state
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	// Redirect to GitHub auth URL
	authURL := s.github.GetAuthURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	// Verify the state
	session, _ := s.store.Get(r, "helm-scanner-session")
	storedState, ok := session.Values["state"].(string)
	if !ok {
		http.Error(w, "Invalid session state", http.StatusBadRequest)
		return
	}

	queryState := r.URL.Query().Get("state")
	if queryState != storedState {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	// Exchange the code for a token
	code := r.URL.Query().Get("code")
	token, err := s.github.ExchangeCode(r.Context(), code)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusInternalServerError)
		return
	}

	// Store the token in the session (in a real app, you'd associate this with a user)
	session.Values["github_token"] = token
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	// Redirect back to the frontend
	http.Redirect(w, r, "/?auth=success", http.StatusFound)
}

func (s *Server) handlePrivateRepoScan(w http.ResponseWriter, r *http.Request) {
	// Get the GitHub token from the session
	session, _ := s.store.Get(r, "helm-scanner-session")
	token, ok := session.Values["github_token"].(*oauth2.Token)
	if !ok {
		http.Error(w, "Not authenticated with GitHub", http.StatusUnauthorized)
		return
	}

	var req struct {
		RepoURL string `json:"repoUrl"`
		Path    string `json:"path,omitempty"`
		Ref     string `json:"ref,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Parse GitHub URL
	owner, repo, err := s.github.ParseGitHubURL(req.RepoURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create authenticated GitHub client
	ghClient := s.github.NewClientWithToken(token)

	// Get the download URL for the repo
	ref := req.Ref
	if ref == "" {
		ref = "main" // or "master" depending on the repo
	}

	downloadURL, err := s.github.DownloadRepoArchive(r.Context(), ghClient, owner, repo, ref)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get download URL: %v", err), http.StatusInternalServerError)
		return
	}

	// Download and extract the chart
	chartPath, err := s.helmScanner.DownloadAndExtractChart(r.Context(), downloadURL.String())
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to download chart: %v", err), http.StatusInternalServerError)
		return
	}

	// If a specific path is provided, use that
	if req.Path != "" {
		chartPath = filepath.Join(chartPath, req.Path)
	}

	// Analyze the chart
	analysis, err := s.helmScanner.AnalyzeChart(chartPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to analyze chart: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate a result ID
	resultID := uuid.New().String()

	// Return the results
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       resultID,
		"results":  analysis,
		"metadata": map[string]string{
			"repo": req.RepoURL,
			"path": req.Path,
			"ref":  ref,
		},
	})
}

func (s *Server) handleGetScanResults(w http.ResponseWriter, r *http.Request) {
	// In a real implementation, you would fetch results from a database
	// For now, we'll just return a not implemented response
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}