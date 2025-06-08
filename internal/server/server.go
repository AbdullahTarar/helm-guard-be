package server

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"

	"helm-guard-be/internal/config"
	"helm-guard-be/internal/github"
	"helm-guard-be/internal/helm"
)

func init() {
	// Required to store these types in sessions
	gob.Register(&oauth2.Token{})
	gob.Register(map[string]interface{}{})
}

type Server struct {
	router      *mux.Router
	config      *config.Config
	github      *github.Client
	helmScanner *helm.Scanner
	store       *sessions.CookieStore
}

func New(cfg *config.Config) (*Server, error) {
	// Create session store
	store := sessions.NewCookieStore([]byte(cfg.Security.CookieSecret))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 1, // 1 day
		HttpOnly: true,
		Secure:   false, // Set to true in production
		SameSite: http.SameSiteLaxMode,
	}

	// Initialize Helm scanner
	helmScanner, err := helm.NewScanner(cfg.Helm.TempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Helm scanner: %v", err)
	}

	// Initialize GitHub client
	ghClient := github.NewClient(cfg.GitHub.ClientID, cfg.GitHub.ClientSecret, cfg.GitHub.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GitHub client: %v", err)
	}

	// Create server
	srv := &Server{
		router:      mux.NewRouter(),
		config:      cfg,
		github:      ghClient,
		helmScanner: helmScanner,
		store:       store,
	}

	srv.routes()
	return srv, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) routes() {
    s.router.Use(func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
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

	s.router.HandleFunc("/api/scan/public", s.handlePublicRepoScan).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/api/github/auth", s.handleGitHubAuth).Methods("GET")
	s.router.HandleFunc("/api/github/callback", s.handleGitHubCallback).Methods("GET")
	s.router.HandleFunc("/api/scan/private", s.handlePrivateRepoScan).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/api/scan/results/{id}", s.handleGetScanResults).Methods("GET")
	s.router.HandleFunc("/api/github/repos", s.handleGetUserRepos).Methods("GET", "OPTIONS")
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

	owner, repo, err := s.github.ParseGitHubURL(req.RepoURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	downloadURL := fmt.Sprintf("https://github.com/%s/%s/archive/refs/heads/main.tar.gz", owner, repo)

	chartPath, err := s.helmScanner.DownloadAndExtractChart(r.Context(), downloadURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to download chart: %v", err), http.StatusInternalServerError)
		return
	}

	if req.Path != "" {
		chartPath = filepath.Join(chartPath, req.Path)
	}

	analysis, err := s.helmScanner.AnalyzeChart(chartPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to analyze chart: %v", err), http.StatusInternalServerError)
		return
	}

	resultID := uuid.New().String()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       resultID,
		"results":  analysis,
		"metadata": map[string]string{
			"repo": req.RepoURL,
			"path": req.Path,
		},
	})
}

func (s *Server) handleGetUserRepos(w http.ResponseWriter, r *http.Request) {
    session, err := s.store.Get(r, "helm-scanner-session")
    if err != nil {
        http.Error(w, "Session error", http.StatusUnauthorized)
        return
    }

    token, ok := session.Values["github_token"].(*oauth2.Token)
    if !ok {
        http.Error(w, "Not authenticated", http.StatusUnauthorized)
        return
    }

    ghClient := s.github.NewClientWithToken(token)
    repos, err := s.github.GetUserRepos(r.Context(), ghClient)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Simplify repo data for frontend
    var repoList []map[string]interface{}
    for _, repo := range repos {
        repoList = append(repoList, map[string]interface{}{
            "name":        repo.GetName(),
            "full_name":   repo.GetFullName(),
            "private":     repo.GetPrivate(),
            "html_url":    repo.GetHTMLURL(),
            "description": repo.GetDescription(),
        })
    }

    json.NewEncoder(w).Encode(repoList)
}


func (s *Server) handleGitHubAuth(w http.ResponseWriter, r *http.Request) {
	state := uuid.New().String()

	session, err := s.store.Get(r, "helm-scanner-session")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	session.Values["state"] = state
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	authURL := s.github.GetAuthURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	session, err := s.store.Get(r, "helm-scanner-session")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	storedState, ok := session.Values["state"].(string)
	if !ok || r.URL.Query().Get("state") != storedState {
		log.Println("Invalid or mismatched state")
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	token, err := s.github.ExchangeCode(r.Context(), code)
	if err != nil {
		log.Printf("Failed to exchange token: %v", err)
		http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusInternalServerError)
		return
	}

	session.Values["github_token"] = token
	session.Values["authenticated"] = true

	if err := session.Save(r, w); err != nil {
		log.Printf("Failed to save session: %v", err)
		http.Error(w, fmt.Sprintf("Failed to save session: %v", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "http://localhost:3000/?auth=success", http.StatusFound)
}

func (s *Server) handlePrivateRepoScan(w http.ResponseWriter, r *http.Request) {
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

	owner, repo, err := s.github.ParseGitHubURL(req.RepoURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ghClient := s.github.NewClientWithToken(token)

	ref := req.Ref
	if ref == "" {
		ref = "main"
	}

	downloadURL, err := s.github.DownloadRepoArchive(r.Context(), ghClient, owner, repo, ref)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get download URL: %v", err), http.StatusInternalServerError)
		return
	}

	chartPath, err := s.helmScanner.DownloadAndExtractChart(r.Context(), downloadURL.String())
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to download chart: %v", err), http.StatusInternalServerError)
		return
	}

	if req.Path != "" {
		chartPath = filepath.Join(chartPath, req.Path)
	}

	analysis, err := s.helmScanner.AnalyzeChart(chartPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to analyze chart: %v", err), http.StatusInternalServerError)
		return
	}

	resultID := uuid.New().String()

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
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}
