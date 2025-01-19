package utils

import (
	"fmt"
	"os"
	"strings"

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
