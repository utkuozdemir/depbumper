package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Masterminds/sprig/v3"
	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("input dir is required as first arg")
	}

	inputDir := os.Args[1]

	pkgfileBytes, err := os.ReadFile(filepath.Join(inputDir, "Pkgfile"))
	if err != nil {
		return fmt.Errorf("error reading Pkgfile: %w", err)
	}

	pkgfileStr := string(pkgfileBytes)

	var pkgfile map[string]any

	if err = yaml.Unmarshal(pkgfileBytes, &pkgfile); err != nil {
		return fmt.Errorf("error parsing Pkgfile: %w", err)
	}

	pkgfileVars, ok := pkgfile["vars"].(map[string]any)
	if !ok {
		return fmt.Errorf("error parsing Pkgfile: vars is not a map")
	}

	var urls []string

	if err := filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.Name() == "pkg.yaml" {
			appURLs, err := getAppURLs(path)
			if err != nil {
				log.Printf("could not get app url from %s: %v", path, err)

				return nil
			}

			urls = append(urls, appURLs...)
		}

		return nil
	}); err != nil {
		return err
	}

	downloadDir := filepath.Join(inputDir, ".depbumper_downloads")

	replaceMap := make(map[string]string)

	for _, url := range urls {
		versionOrRefVar := extractVersionVar(url)
		if versionOrRefVar == "" {
			versionOrRefVar = extractRefVar(url)
		}

		if versionOrRefVar == "" {
			log.Printf("skip %s: no version or ref var found\n", url)

			continue
		}

		appName := extractAppName(versionOrRefVar)
		if appName == "" {
			log.Printf("skip %s: no app name found\n", url)

			continue
		}

		versionOrRef, err := extractVariableValueFromPkgfile(pkgfileStr, versionOrRefVar)
		if err != nil {
			log.Printf("skip %s: could not extract version or ref value: %v\n", url, err)

			continue
		}

		templatedURL, err := templateURL(url, versionOrRefVar, versionOrRef)
		if err != nil {
			log.Printf("skip %s: could not template url: %v\n", url, err)

			continue
		}

		filePath, err := downloadFile(downloadDir, appName, versionOrRef, templatedURL)
		if err != nil {
			log.Printf("skip %s: could not download file: %v\n", url, err)

			continue
		}

		s256, err := sha256sum(filePath)
		if err != nil {
			log.Printf("skip %s: could not get sha256sum: %v\n", url, err)

			continue
		}

		s256Key := fmt.Sprintf("%s_sha256", appName)

		existingS256, ok := pkgfileVars[s256Key].(string)
		if !ok {
			log.Printf("skip %s: could not get existing sha256sum: %v\n", url, err)

			continue
		}

		if s256 == existingS256 {
			log.Printf("app is up to date, continue: %s\n", appName)

			continue
		}

		replaceMap[existingS256] = s256

		s512, err := sha512sum(filePath)
		if err != nil {
			log.Printf("skip %s: could not get sha512sum: %v\n", url, err)

			continue
		}

		s512Key := fmt.Sprintf("%s_sha512", appName)

		existingS512, ok := pkgfileVars[s512Key].(string)
		if !ok {
			log.Printf("skip %s: could not get existing sha512sum: %v\n", url, err)

			continue
		}

		replaceMap[existingS512] = s512
	}

	log.Printf("---------")

	log.Printf("will do %d replacements\n", len(replaceMap))

	replacements := make([]string, 0, len(replaceMap)*2)
	for str, replacement := range replaceMap {
		replacements = append(replacements, str, replacement)
	}

	newPkgFileStr := strings.NewReplacer(replacements...).Replace(pkgfileStr)

	if err := os.WriteFile(filepath.Join(inputDir, "Pkgfile"), []byte(newPkgFileStr), 0); err != nil {
		return fmt.Errorf("error writing Pkgfile: %w", err)
	}

	return nil
}

func sha256sum(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}

	defer file.Close()

	hash := sha256.New()

	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func sha512sum(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}

	defer file.Close()

	hash := sha512.New()

	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// download file, overwrite if necessary
func downloadFile(downloadDir, appName, versionStr, url string) (string, error) {
	filename := fmt.Sprintf("%s--%s--%s", appName, versionStr, filepath.Base(url))

	if err := os.MkdirAll(downloadDir, 0o755); err != nil {
		return "", err
	}

	// if file exists and has non-zero size, skip
	if fi, err := os.Stat(filepath.Join(downloadDir, filename)); err == nil && fi.Size() > 0 {
		log.Printf("file exists, skipping download: %s\n", filename)

		return filepath.Join(downloadDir, filename), nil
	}

	out, err := os.Create(filepath.Join(downloadDir, filename))
	if err != nil {
		return "", err
	}

	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "", err
	}

	return filepath.Join(downloadDir, filename), nil
}

func templateURL(url string, varName, varValue string) (string, error) {
	parsed, err := template.New("url").Funcs(sprig.FuncMap()).Parse(url)
	if err != nil {
		return "", err
	}

	var sb strings.Builder

	if err := parsed.Execute(&sb, map[string]string{
		varName: varValue,
	}); err != nil {
		return "", err
	}

	return sb.String(), nil
}

func extractVariableValueFromPkgfile(pkgFileRaw string, varName string) (string, error) {
	versionRegex, err := regexp.Compile(fmt.Sprintf(`\s+%s: ([^\s]+)`, varName))
	if err != nil {
		return "", err
	}

	versionMatch := versionRegex.FindStringSubmatch(pkgFileRaw)
	if len(versionMatch) != 2 {
		return "", fmt.Errorf("could not find version in Pkgfile")
	}

	return versionMatch[1], nil
}

func getAppURLs(pkgYAMLPath string) ([]string, error) {
	pkgYAMLBytes, err := os.ReadFile(pkgYAMLPath)
	if err != nil {
		return nil, err
	}

	var pkgYAML map[string]any

	if err = yaml.Unmarshal(pkgYAMLBytes, &pkgYAML); err != nil {
		return nil, err
	}

	steps, ok := pkgYAML["steps"].([]any)
	if !ok {
		return nil, fmt.Errorf("steps is not a list")
	}

	var urls []string

	for _, step := range steps {
		stepObj, ok := step.(map[string]any)
		if !ok {
			log.Printf("step is not a map")

			continue
		}

		sources, ok := stepObj["sources"].([]any)
		if !ok {
			log.Printf("sources is not a list")

			continue
		}

		for _, source := range sources {
			sourceObj, ok := source.(map[string]any)
			if !ok {
				log.Printf("source is not a map")

				continue
			}

			url, ok := sourceObj["url"].(string)
			if !ok {
				log.Printf("url is not a string")

				continue
			}

			urls = append(urls, url)
		}
	}

	return urls, nil
}

var versionRegex = regexp.MustCompile(`\.([a-zA-Z0-9_]+_version) `)

func extractVersionVar(url string) string {
	matches := versionRegex.FindStringSubmatch(url)
	if len(matches) != 2 {
		return ""
	}

	return matches[1]
}

var refRegex = regexp.MustCompile(`\.([a-zA-Z0-9_]+_ref) `)

func extractRefVar(url string) string {
	matches := refRegex.FindStringSubmatch(url)
	if len(matches) != 2 {
		return ""
	}

	return matches[1]
}

func extractAppName(versionOrRefVar string) string {
	lastUnderscore := strings.LastIndex(versionOrRefVar, "_")

	if lastUnderscore != -1 {
		return versionOrRefVar[:lastUnderscore]
	}

	return ""
}
