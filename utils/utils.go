package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type Context struct {
	Config map[string]interface{}
}

func CreateContext() *Context {
	ctx := &Context{Config: make(map[string]interface{})}
	GetConfigFromEnvVariables(ctx)
	GetConfigFromFiles(ctx)
	return ctx
}

func GetConfigFromEnvVariables(ctx *Context) {
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key, value := parts[0], parts[1]
		if strings.HasPrefix(key, "TRIVY_PROCESSOR_") {
			camelKey := toCamelCase(strings.TrimPrefix(key, "TRIVY_PROCESSOR_"))
			fmt.Printf("Environment variable %s found and used in context as %s\n", key, camelKey)
			ctx.Config[camelKey] = value
		}
	}
}

func GetConfigFromFiles(ctx *Context) {
	files, err := os.ReadDir("/etc/trivy-processor")
	if err == nil {
		for _, file := range files {
			fileName := file.Name()
			envVarName := "TRIVY_PROCESSOR_" + strings.ToUpper(fileName)
			camelKey := toCamelCase(strings.TrimPrefix(envVarName, "TRIVY_PROCESSOR_"))
			content, err := os.ReadFile("/etc/trivy-processor/" + fileName)
			if err == nil {
				if _, exists := ctx.Config[camelKey]; exists {
					fmt.Printf("Warning: Key %s already exists in context. Overwriting with value from file.\n", camelKey)
				}
				fmt.Printf("File %s found and used in context as %s\n", fileName, camelKey)
				ctx.Config[camelKey] = string(content)
			}
		}
	}
}

func toCamelCase(s string) string {
	words := strings.Split(s, "_")
	result := ""
	for _, word := range words {
		result += cases.Title(language.Und).String(word)
	}
	return result
}

func GenerateUniqueID(info string) string {
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic("failed to generate random bytes")
	}
	data := hex.EncodeToString(randomBytes) + info
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:8]
}

type loggingRoundTripper struct {
	rt     http.RoundTripper
	logger echo.Logger
}

func (lrt *loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	lrt.logger.Infof("Request URL: %s", req.URL)

	if req.Body != nil {
		bodyBytes, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Reset the body
		truncatedBody := string(bodyBytes)
		if len(truncatedBody) > 100 {
			truncatedBody = truncatedBody[:100] + "..."
		}
		lrt.logger.Infof("Request Body: %s", truncatedBody)
	}

	resp, err := lrt.rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	lrt.logger.Infof("Response Status: %s", resp.Status)

	if resp.Body != nil {
		bodyBytes, _ := io.ReadAll(resp.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Reset the body
		truncatedBody := string(bodyBytes)
		if len(truncatedBody) > 100 {
			truncatedBody = truncatedBody[:100] + "..."
		}
		lrt.logger.Infof("Response Body: %s", truncatedBody)
	}

	return resp, nil
}

func NewLoggingHTTPClient(logger echo.Logger) *http.Client {
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &loggingRoundTripper{rt: http.DefaultTransport, logger: logger},
	}
}
