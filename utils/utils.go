package utils

import (
	"fmt"
	"os"
	"strings"
	"unicode"
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
	var result []rune
	upperNext := false
	for i, r := range s {
		if r == '_' {
			upperNext = true
		} else {
			if upperNext {
				result = append(result, unicode.ToUpper(r))
				upperNext = false
			} else {
				if i == 0 {
					result = append(result, unicode.ToLower(r))
				} else {
					result = append(result, r)
				}
			}
		}
	}
	return string(result)
}
