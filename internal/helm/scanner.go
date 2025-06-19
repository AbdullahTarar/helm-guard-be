package helm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"log"
	"os"
	"path/filepath"
	"strings"
	"archive/tar"
	"compress/gzip"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/engine"
)

type Scanner struct {
	tempDir string
}

func NewScanner(tempDir string) (*Scanner, error) {
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, errors.Wrap(err, "failed to create temp directory")
	}
	return &Scanner{tempDir: tempDir}, nil
}

type ChartAnalysis struct {
	Resources    []Resource      `json:"resources"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Metadata     chart.Metadata `json:"metadata"`
}

type Resource struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace,omitempty"`
}

type Vulnerability struct {
	Type        string `json:"type"`
	RuleID      string `json:"ruleId"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Path        string `json:"path"`
}

func findChartDir(baseDir string) (string, error) {
	var chartDir string
	log.Printf("Searching for Chart.yaml under %s", baseDir)
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		log.Printf("Checking directory: %s", path)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return nil
		}
		if _, err := os.Stat(filepath.Join(path, "Chart.yaml")); err == nil {
			chartDir = path
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if chartDir == "" {
		return "", fmt.Errorf("no Chart.yaml found")
	}
	return chartDir, nil
}

func (s *Scanner) AnalyzeChart(chartPath string) (*ChartAnalysis, error) {
	log.Printf("[DEBUG] Searching for Chart.yaml under %s", chartPath)

	// Step 1: Locate Chart.yaml
	actualChartPath, err := findChartDir(chartPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to locate Chart.yaml")
	}

	// Step 2: Load the chart
	chart, err := loader.Load(actualChartPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load chart")
	}

	// Step 3: Coalesce values (includes merging values.yaml and defaults)
	vals, err := chartutil.CoalesceValues(chart, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to coalesce chart values")
	}

	// Step 4: Ensure required values to avoid nil pointer
	if _, ok := vals["fullnameOverride"]; !ok {
		vals["fullnameOverride"] = ""
		log.Printf("[DEBUG] Injected missing 'fullnameOverride' = \"\"")
	}
	if _, ok := vals["nameOverride"]; !ok {
		vals["nameOverride"] = ""
		log.Printf("[DEBUG] Injected missing 'nameOverride' = \"\"")
	}

	// Debug: Print final values
	if valuesYAML, err := yaml.Marshal(vals); err == nil {
		log.Printf("[DEBUG] Final values:\n%s", string(valuesYAML))
	}

	// Step 5: Render templates using Helm engine
	renderer := engine.Engine{}
	rendered, err := renderer.Render(chart, chartutil.Values(vals))
	if err != nil {
		return nil, errors.Wrap(err, "failed to render templates")
	}
	log.Printf("[DEBUG] Rendered %d files", len(rendered))

	// Step 6: Analyze rendered resources
	var resources []Resource
	var vulnerabilities []Vulnerability

	for path, content := range rendered {
		log.Printf("[DEBUG] Processing rendered file: %s", path)

		if strings.TrimSpace(content) == "" {
			log.Printf("[DEBUG] Skipped empty content: %s", path)
			continue
		}

		decoder := yaml.NewDecoder(strings.NewReader(content))
		for {
			var resource Resource
			if err := decoder.Decode(&resource); err != nil {
				if err == io.EOF {
					break
				}
				log.Printf("[WARN] Failed to decode resource in %s: %v", path, err)
				continue
			}

			if resource.APIVersion != "" && resource.Kind != "" {
				resources = append(resources, resource)
				log.Printf("[DEBUG] Found resource: Kind=%s, APIVersion=%s", resource.Kind, resource.APIVersion)
			}
		}

		// Security check for hardcoded passwords
		if strings.Contains(content, "password: ") {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "security",
				RuleID:      "SEC002",
				Severity:    "critical",
				Description: "Hardcoded password detected",
				Path:        path,
			})
			log.Printf("[VULN] Hardcoded password found in %s", path)
		}
	}

	// Step 7: Run additional checks
	log.Printf("[DEBUG] Running additional vulnerability checks...")
	vulnerabilities = append(vulnerabilities, s.checkResourceVulnerabilities(chart, resources)...)

	// Step 8: Final output
	log.Printf("[DEBUG] Analysis complete — Resources: %d, Vulnerabilities: %d", len(resources), len(vulnerabilities))

	return &ChartAnalysis{
		Resources:       resources,
		Vulnerabilities: vulnerabilities,
		Metadata:        *chart.Metadata,
	}, nil
}

func mergeValues(dest, src map[string]interface{}) {
    for k, v := range src {
        if _, exists := dest[k]; !exists {
            // Key doesn't exist in dest - simple copy
            dest[k] = v
        } else {
            // Handle nested maps
            if destMap, ok := dest[k].(map[string]interface{}); ok {
                if srcMap, ok := v.(map[string]interface{}); ok {
                    mergeValues(destMap, srcMap)
                    continue
                }
            }
            // Overwrite with source value
            dest[k] = v
        }
    }
}


// Renamed to be more specific
func (s *Scanner) checkResourceVulnerabilities(chart *chart.Chart, resources []Resource) []Vulnerability {
    var vulnerabilities []Vulnerability

    // Check chart metadata
    if chart.Metadata.Deprecated {
        vulnerabilities = append(vulnerabilities, Vulnerability{
            Type:        "metadata",
            RuleID:      "DEP001",
            Severity:    "warning",
            Description: "This chart is marked as deprecated",
            Path:        "Chart.yaml",
        })
    }

    // Check resource-specific issues
    for _, resource := range resources {
        if resource.Kind == "Pod" {
            vulnerabilities = append(vulnerabilities, Vulnerability{
                Type:        "security",
                RuleID:      "SEC001",
                Severity:    "high",
                Description: "Direct Pod definitions are discouraged",
                Path:        resource.Kind + "/" + resource.Name,
            })
        }

        if resource.APIVersion == "extensions/v1beta1" || 
           resource.APIVersion == "apps/v1beta1" || 
           resource.APIVersion == "apps/v1beta2" {
            vulnerabilities = append(vulnerabilities, Vulnerability{
                Type:        "deprecation",
                RuleID:      "DEP002",
                Severity:    "medium",
                Description: fmt.Sprintf("API version %s is deprecated", resource.APIVersion),
                Path:        resource.Kind + "/" + resource.Name,
            })
        }
    }
    
    return vulnerabilities
}
func (s *Scanner) DownloadAndExtractChart(ctx context.Context, downloadURL string) (string, error) {
	chartDir, err := os.MkdirTemp(s.tempDir, "chart-")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp directory")
	}

	resp, err := http.Get(downloadURL)
	if err != nil {
		return "", errors.Wrap(err, "failed to download chart")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download chart: %s", resp.Status)
	}

	tmpFile := filepath.Join(chartDir, "chart.tgz")
	out, err := os.Create(tmpFile)
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp file")
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return "", errors.Wrap(err, "failed to save chart")
	}

	if err := extractTarGz(tmpFile, chartDir); err != nil {
		return "", errors.Wrap(err, "failed to extract chart")
	}

	// 🔍 Recursively search entire extracted tree for Chart.yaml
	actualChartDir, err := findChartDir(chartDir)
	if err != nil {
		return "", errors.Wrap(err, "failed to locate Chart.yaml in extracted contents")
	}
	return actualChartDir, nil
}




func extractTarGz(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tarReader := tar.NewReader(gzr)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // end of archive
		}
		if err != nil {
			return err
		}

		// Clean and prepare the file path
		target := filepath.Join(dst, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			outFile, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		}
	}
	return nil
}