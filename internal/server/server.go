package server

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"helm-guard-be/internal/config"
	"helm-guard-be/internal/github"
	"helm-guard-be/internal/helm"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

func init() {
	// Required to store these types in sessions
	gob.Register(&oauth2.Token{})
	gob.Register(map[string]interface{}{})
}

type ScanResultStorage struct {
	mu    sync.RWMutex
	scans map[string]*helm.ScanResults
}

type Server struct {
	router      *mux.Router
	config      *config.Config
	github      *github.Client
	helmScanner *helm.Scanner
	store       *sessions.CookieStore
	scanStorage *ScanResultStorage
}

func New(cfg *config.Config) (*Server, error) {
	// Create session store
	store := sessions.NewCookieStore([]byte(cfg.Security.CookieSecret))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 1, // 1 day
		HttpOnly: true,
		Secure:   true, // Set to true in production
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
		scanStorage: &ScanResultStorage{
			scans: make(map[string]*helm.ScanResults),
		},
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
			origin := r.Header.Get("Origin")
			log.Printf("[CORS] Request from origin: %s", origin)

			// Allow your frontend domains
			allowedOrigins := []string{
				s.config.Server.FrontendURL,
				"https://helm-guard-fe.vercel.app", // Add your Vercel domain
			}

			for _, allowed := range allowedOrigins {
				if origin == allowed {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}

			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	})

	// // Add session debugging middleware
	// s.router.Use(func(next http.Handler) http.Handler {
	//     return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//         if strings.Contains(r.URL.Path, "/api/") {
	//             session, err := s.store.Get(r, "helm-scanner-session")
	//             if err != nil {
	//                 log.Printf("[SESSION DEBUG] Failed to get session for %s: %v", r.URL.Path, err)
	//             } else {
	//                 log.Printf("[SESSION DEBUG] %s - IsNew: %v, Auth: %v, HasToken: %v",
	//                     r.URL.Path,
	//                     session.IsNew,
	//                     session.Values["authenticated"],
	//                     session.Values["github_token"] != nil)
	//             }
	//         }
	//         next.ServeHTTP(w, r)
	//     })
	// })

	// Your existing routes...
	s.router.HandleFunc("/api/scan/public", s.handlePublicRepoScan).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/api/github/auth", s.handleGitHubAuth).Methods("GET")
	s.router.HandleFunc("/api/github/callback", s.handleGitHubCallback).Methods("GET")
	s.router.HandleFunc("/api/scan/private", s.handlePrivateRepoScan).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/api/scan/results/{id}", s.handleGetScanResults).Methods("GET")
	s.router.HandleFunc("/api/github/repos", s.handleGetUserRepos).Methods("GET", "OPTIONS")
	s.router.HandleFunc("/api/auth/status", s.handleAuthStatus).Methods("GET")
}

func (s *Server) handlePublicRepoScan(w http.ResponseWriter, r *http.Request) {
	// Start with logging
	log.Println("[DEBUG] Starting public repo scan handler")
	startTime := time.Now()

	// 1. Request body parsing
	var req struct {
		RepoURL string `json:"repoUrl"`
		Path    string `json:"path,omitempty"`
		Ref     string `json:"ref,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[ERROR] Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	log.Printf("[DEBUG] Processing repo: %s", req.RepoURL)

	// 2. GitHub URL parsing
	owner, repo, err := s.github.ParseGitHubURL(req.RepoURL)
	if err != nil {
		log.Printf("[ERROR] Failed to parse GitHub URL: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("[DEBUG] Extracted owner: %s, repo: %s", owner, repo)

	// 3. Set default ref if not provided
	ref := req.Ref
	if ref == "" {
		ref = "main"
	}
	log.Printf("[DEBUG] Using ref: %s", ref)

	// 4. Try multiple branch names (main, master, default)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var downloadURL string
	branchesToTry := []string{ref}

	// If ref is "main", also try "master" as fallback
	if ref == "main" {
		branchesToTry = append(branchesToTry, "master")
	}

	// 5. Verify repository exists and get default branch
	log.Println("[DEBUG] Checking repository access...")

	// Create a simple HTTP client to check repo existence
	checkURL := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	resp, err := http.Get(checkURL)
	if err != nil {
		log.Printf("[ERROR] Failed to check repository: %v", err)
		http.Error(w, "Failed to access repository", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		log.Printf("[ERROR] Repository not found: %s/%s", owner, repo)
		http.Error(w, "Repository not found or is private", http.StatusNotFound)
		return
	} else if resp.StatusCode != 200 {
		log.Printf("[ERROR] GitHub API returned status %d", resp.StatusCode)
		http.Error(w, "Failed to verify repository", http.StatusBadRequest)
		return
	}

	// Parse the response to get default branch
	var repoInfo struct {
		DefaultBranch string `json:"default_branch"`
		Private       bool   `json:"private"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&repoInfo); err != nil {
		log.Printf("[WARNING] Failed to parse repo info, continuing with default branch: %v", err)
	} else {
		log.Printf("[DEBUG] Repository default branch: %s, private: %v", repoInfo.DefaultBranch, repoInfo.Private)

		if repoInfo.Private {
			log.Printf("[ERROR] Repository is private: %s/%s", owner, repo)
			http.Error(w, "Repository is private. Please use the private repository option.", http.StatusForbidden)
			return
		}

		// Use the actual default branch if ref was "main"
		if ref == "main" && repoInfo.DefaultBranch != "" {
			branchesToTry = []string{repoInfo.DefaultBranch, "main", "master"}
		}
	}

	// 6. Try to find a working branch
	for _, branch := range branchesToTry {
		testURL := fmt.Sprintf("https://github.com/%s/%s/archive/refs/heads/%s.tar.gz", owner, repo, branch)
		log.Printf("[DEBUG] Trying branch: %s", branch)

		// Test if the branch exists by making a HEAD request
		headReq, err := http.NewRequestWithContext(ctx, "HEAD", testURL, nil)
		if err != nil {
			continue
		}

		headResp, err := http.DefaultClient.Do(headReq)
		if err != nil {
			log.Printf("[DEBUG] Branch %s not accessible: %v", branch, err)
			continue
		}
		headResp.Body.Close()

		if headResp.StatusCode == 200 {
			downloadURL = testURL
			ref = branch
			log.Printf("[DEBUG] Using branch: %s", branch)
			break
		}
		log.Printf("[DEBUG] Branch %s returned status %d", branch, headResp.StatusCode)
	}

	if downloadURL == "" {
		log.Printf("[ERROR] No accessible branch found for %s/%s", owner, repo)
		http.Error(w, "No accessible branch found (tried: main, master)", http.StatusNotFound)
		return
	}

	log.Printf("[DEBUG] Download URL: %s", downloadURL)

	// 7. Create scan ID and initialize scan record
	scanID := uuid.New().String()
	now := time.Now()

	// Initialize with status fields
	s.scanStorage.mu.Lock()
	s.scanStorage.scans[scanID] = &helm.ScanResults{
		Repository: helm.Repository{
			Name:     repo,
			URL:      req.RepoURL,
			Branch:   ref,
			ScanDate: now,
		},
		Status:    "processing",
		StartedAt: now,
	}
	s.scanStorage.mu.Unlock()

	log.Printf("[DEBUG] Scan %s initialized", scanID)

	// 8. Start async processing
	go func() {
		log.Printf("[DEBUG] Starting async processing for scan %s", scanID)

		// Download and extract chart
		chartPath, err := s.helmScanner.DownloadAndExtractChart(context.Background(), downloadURL)
		if err != nil {
			log.Printf("[ERROR] Failed to download/extract chart for scan %s: %v", scanID, err)
			s.updateScanStatus(scanID, "failed", fmt.Sprintf("Failed to download chart: %v", err))
			return
		}
		log.Printf("[DEBUG] Chart downloaded to: %s", chartPath)

		// Adjust path if specified
		if req.Path != "" {
			chartPath = filepath.Join(chartPath, req.Path)
			log.Printf("[DEBUG] Using custom path: %s", chartPath)
		}

		// Check for Chart.yaml
		chartYamlPath := filepath.Join(chartPath, "Chart.yaml")
		if _, err := os.Stat(chartYamlPath); os.IsNotExist(err) {
			log.Printf("[ERROR] No Chart.yaml found in: %s", chartPath)
			s.updateScanStatus(scanID, "failed", "Repository does not contain a Helm chart")
			return
		}
		log.Println("[DEBUG] Chart.yaml found")

		// Analyze chart
		results, err := s.helmScanner.AnalyzeChartComprehensive(chartPath, req.RepoURL)

		s.scanStorage.mu.Lock()
		defer s.scanStorage.mu.Unlock()

		if scan, exists := s.scanStorage.scans[scanID]; exists {
			if err != nil {
				log.Printf("[ERROR] Failed to analyze chart for scan %s: %v", scanID, err)
				scan.Status = "failed"
				scan.ErrorMessage = err.Error()
				scan.CompletedAt = time.Now()
			} else {
				log.Printf("[DEBUG] Chart analysis completed for scan %s", scanID)
				// Update the existing scan object instead of replacing it
				scan.Repository = results.Repository
				scan.Summary = results.Summary
				scan.Charts = results.Charts
				scan.SecurityFindings = results.SecurityFindings
				scan.Resources = results.Resources
				scan.BestPractices = results.BestPractices
				scan.Status = "completed"
				scan.CompletedAt = time.Now()
			}
		}

		log.Printf("[DEBUG] Scan %s completed in %v", scanID, time.Since(startTime))
	}()

	// 9. Return immediate response
	response := map[string]interface{}{
		"id":       scanID,
		"status":   "processing",
		"message":  "Scan started successfully",
		"scanDate": now.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[ERROR] Failed to encode response: %v", err)
		http.Error(w, "Failed to generate response", http.StatusInternalServerError)
	}
}

// Helper function to update scan status
func (s *Server) updateScanStatus(scanID, status, errorMessage string) {
	s.scanStorage.mu.Lock()
	defer s.scanStorage.mu.Unlock()

	if scan, exists := s.scanStorage.scans[scanID]; exists {
		scan.Status = status
		if errorMessage != "" {
			scan.ErrorMessage = errorMessage
		}
		scan.CompletedAt = time.Now()
	}
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
	log.Printf("[AUTH] Starting OAuth flow with state: %s", state) // <-- Add this

	session, err := s.store.Get(r, "helm-scanner-session")
	if err != nil {
		log.Printf("[AUTH ERROR] Session get failed: %v", err) // <-- Add this
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	session.Values["state"] = state
	if err := session.Save(r, w); err != nil {
		log.Printf("[AUTH ERROR] Session save failed: %v", err) // <-- Add this
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	authURL := s.github.GetAuthURL(state)
	log.Printf("[AUTH] Redirecting to GitHub: %s", authURL) // <-- Add this
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	log.Printf("[AUTH] Received callback. Query params: %v", r.URL.Query()) // <-- Add this

	session, err := s.store.Get(r, "helm-scanner-session")
	if err != nil {
		log.Printf("[AUTH ERROR] Session get failed: %v", err) // <-- Add this
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	storedState, ok := session.Values["state"].(string)
	if !ok {
		log.Println("[AUTH ERROR] No state found in session") // <-- Add this
		http.Error(w, "State missing", http.StatusBadRequest)
		return
	}

	receivedState := r.URL.Query().Get("state")
	if receivedState != storedState {
		log.Printf("[AUTH ERROR] State mismatch. Stored: %s, Received: %s", storedState, receivedState) // <-- Add this
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	log.Printf("[AUTH] Exchanging code for token. Code: %s", code) // <-- Add this

	token, err := s.github.ExchangeCode(r.Context(), code)
	if err != nil {
		log.Printf("[AUTH ERROR] Token exchange failed: %v", err) // <-- Add this
		http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[AUTH] Token received. Expires at: %v", token.Expiry) // <-- Add this
	session.Values["github_token"] = token
	session.Values["authenticated"] = true

	if err := session.Save(r, w); err != nil {
		log.Printf("[AUTH ERROR] Session save failed: %v", err) // <-- Add this
		http.Error(w, fmt.Sprintf("Failed to save session: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[AUTH] Authentication successful. Redirecting to: %s", s.config.Server.FrontendURL+"/repositories") // <-- Add this
	http.Redirect(w, r, s.config.Server.FrontendURL+"/repositories", http.StatusFound)
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	session, err := s.store.Get(r, "helm-scanner-session")
	if err != nil {
		log.Printf("[AUTH ERROR] Session get failed: %v", err) // <-- Add this
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	authenticated, _ := session.Values["authenticated"].(bool)
	log.Printf("[AUTH] Auth status check. Authenticated: %v", authenticated) // <-- Add this

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"authenticated": authenticated,
	})
}

func (s *Server) handlePrivateRepoScan(w http.ResponseWriter, r *http.Request) {
	// Start with logging
	log.Println("[DEBUG] Starting private repo scan handler")
	startTime := time.Now()

	// 1. Session and token validation
	session, err := s.store.Get(r, "helm-scanner-session")
	if err != nil {
		log.Printf("[ERROR] Session error: %v", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	token, ok := session.Values["github_token"].(*oauth2.Token)
	if !ok || token == nil {
		log.Println("[ERROR] Missing or invalid GitHub token in session")
		http.Error(w, "Not authenticated with GitHub", http.StatusUnauthorized)
		return
	}
	log.Println("[DEBUG] Valid GitHub token found")

	// 2. Request body parsing
	var req struct {
		RepoURL string `json:"repoUrl"`
		Path    string `json:"path,omitempty"`
		Ref     string `json:"ref,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[ERROR] Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	log.Printf("[DEBUG] Processing repo: %s", req.RepoURL)

	// 3. GitHub URL parsing
	owner, repo, err := s.github.ParseGitHubURL(req.RepoURL)
	if err != nil {
		log.Printf("[ERROR] Failed to parse GitHub URL: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("[DEBUG] Extracted owner: %s, repo: %s", owner, repo)

	// 4. GitHub client setup
	ghClient := s.github.NewClientWithToken(token)
	log.Println("[DEBUG] GitHub client created")

	// 5. Set default ref if not provided
	ref := req.Ref
	if ref == "" {
		ref = "main"
	}
	log.Printf("[DEBUG] Using ref: %s", ref)

	// 6. Verify repository access first
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	log.Println("[DEBUG] Checking repository access...")
	repoInfo, _, err := ghClient.Repositories.Get(ctx, owner, repo)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch repository info: %v", err)
		http.Error(w, "Failed to access repository: "+err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("[DEBUG] Repository verified. Default branch: %s", repoInfo.GetDefaultBranch())

	// 7. Get archive download URL
	log.Println("[DEBUG] Getting archive download URL...")
	downloadURL, err := s.github.DownloadRepoArchive(ctx, ghClient, owner, repo, ref)
	if err != nil {
		log.Printf("[ERROR] Failed to get download URL: %v", err)
		http.Error(w, "Failed to get repository archive: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[DEBUG] Download URL: %s", downloadURL.String())

	// 8. Download and extract chart
	log.Println("[DEBUG] Downloading and extracting chart...")
	chartPath, err := s.helmScanner.DownloadAndExtractChart(ctx, downloadURL.String())
	if err != nil {
		log.Printf("[ERROR] Failed to download/extract chart: %v", err)
		http.Error(w, "Failed to process repository: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[DEBUG] Chart downloaded to: %s", chartPath)

	// 9. Check for Chart.yaml
	chartYamlPath := filepath.Join(chartPath, "Chart.yaml")
	if _, err := os.Stat(chartYamlPath); os.IsNotExist(err) {
		log.Printf("[ERROR] No Chart.yaml found in: %s", chartPath)
		http.Error(w, "Repository does not contain a Helm chart", http.StatusBadRequest)
		return
	}
	log.Println("[DEBUG] Chart.yaml found")

	// 10. Analyze chart
	log.Println("[DEBUG] Analyzing chart...")
	results, err := s.helmScanner.AnalyzeChartComprehensive(chartPath, req.RepoURL)
	if err != nil {
		log.Printf("[ERROR] Failed to analyze chart: %v", err)
		http.Error(w, fmt.Sprintf("Failed to analyze chart: %v", err), http.StatusInternalServerError)
		return
	}
	log.Println("[DEBUG] Chart analysis completed")

	// 11. Prepare response
	resultID := uuid.New().String()
	s.scanStorage.mu.Lock()
	s.scanStorage.scans[resultID] = results
	s.scanStorage.mu.Unlock()

	response := map[string]interface{}{
		"id":      resultID,
		"status":  "completed",
		"message": "Scan completed successfully",
	}
	log.Printf("[DEBUG] Scan completed in %v", time.Since(startTime))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[ERROR] Failed to encode response: %v", err)
		http.Error(w, "Failed to generate response", http.StatusInternalServerError)
	}
}
func (s *Server) handleGetScanResults(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	s.scanStorage.mu.RLock()
	results, exists := s.scanStorage.scans[id]
	s.scanStorage.mu.RUnlock()

	if !exists {
		http.Error(w, "Scan results not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		log.Printf("[ERROR] Failed to encode results: %v", err)
		http.Error(w, "Failed to retrieve results", http.StatusInternalServerError)
	}
}

//adding a comment
