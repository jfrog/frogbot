package schema

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v2"
)

func TestFrogbotSchema(t *testing.T) {
	// Load frogbot schema
	schema, err := os.ReadFile("frogbot-schema.json")
	assert.NoError(t, err)
	schemaLoader := gojsonschema.NewBytesLoader(schema)

	// Validate config in the docs
	validateYamlSchema(t, schemaLoader, filepath.Join("..", "docs", "templates", ".frogbot", "frogbot-config.yml"), "")

	// Validate all frogbot configs in commands/testdata/config
	validateYamlsInDirectory(t, filepath.Join("..", "commands", "testdata", "config"), schemaLoader)
}

func TestBadFrogbotSchemas(t *testing.T) {
	// Load frogbot schema
	schema, err := os.ReadFile("frogbot-schema.json")
	assert.NoError(t, err)
	schemaLoader := gojsonschema.NewBytesLoader(schema)

	// Validate all bad frogbot configs in schema/testdata/
	testCases := []struct {
		testName    string
		errorString string
	}{
		{"additional-prop", "Additional property additionalProp is not allowed"},
		{"no-array", "Expected: array, given: object"},
		{"no-git", "git is required"},
		{"no-repo", "repoName is required"},
		{"empty-repo", "Expected: string, given: null"},
	}
	for _, testCase := range testCases {
		validateYamlSchema(t, schemaLoader, filepath.Join("testdata", testCase.testName+".yml"), testCase.errorString)
	}
}

func TestJFrogPipelinesTemplates(t *testing.T) {
	schemaLoader := downloadFromSchemaStore(t, "jfrog-pipelines.json")
	validateYamlsInDirectory(t, filepath.Join("..", "docs", "templates", "jfrog-pipelines"), schemaLoader)
}

func TestGitHubActionsTemplates(t *testing.T) {
	schemaLoader := downloadFromSchemaStore(t, "github-workflow.json")
	validateYamlsInDirectory(t, filepath.Join("..", "docs", "templates", "github-actions"), schemaLoader)
}

// Download a Yaml schema from https://json.schemastore.org.
// t      - Testing object
// schema - The schema file to download
func downloadFromSchemaStore(t *testing.T, schema string) gojsonschema.JSONLoader {
	response, err := http.Get("https://json.schemastore.org/" + schema)
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, response.Body.Close())
	}()
	// Check server response
	assert.Equal(t, http.StatusOK, response.StatusCode, response.Status)
	schemaBytes, err := io.ReadAll(response.Body)
	assert.NoError(t, err)

	return gojsonschema.NewBytesLoader(schemaBytes)
}

// Validate all yml files in the given directory against the input schema
// t            - Testing object
// schemaLoader - Frogbot config schema
// path	         - Yaml directory path
func validateYamlsInDirectory(t *testing.T, path string, schemaLoader gojsonschema.JSONLoader) {
	err := filepath.Walk(path, func(frogbotConfigFilePath string, info os.FileInfo, err error) error {
		assert.NoError(t, err)
		if strings.HasSuffix(info.Name(), "yml") {
			validateYamlSchema(t, schemaLoader, frogbotConfigFilePath, "")
		}
		return nil
	})
	assert.NoError(t, err)
}

// Validate a Yaml file against the input Yaml schema
// t            - Testing object
// schemaLoader - Frogbot config schema
// yamlFilePath - Yaml file path
// expectError  - Expected error or an empty string if error is not expected
func validateYamlSchema(t *testing.T, schemaLoader gojsonschema.JSONLoader, yamlFilePath, expectError string) {
	t.Run(filepath.Base(yamlFilePath), func(t *testing.T) {
		// Read frogbot config
		yamlFile, err := os.ReadFile(yamlFilePath)
		assert.NoError(t, err)

		// Unmarshal frogbot config
		var frogbotConfigYaml interface{}
		err = yaml.Unmarshal(yamlFile, &frogbotConfigYaml)
		assert.NoError(t, err)

		// Convert the Yaml config to JSON config to help the json parser validate it.
		// The reason we don't do the convert by as follows:
		// YAML -> Unmarshall -> Go Struct -> Marshal -> JSON
		// is because the config's struct includes only YAML annotations.
		frogbotConfigJson := convertYamlToJson(frogbotConfigYaml)

		// Load and validate frogbot config
		documentLoader := gojsonschema.NewGoLoader(frogbotConfigJson)
		result, err := gojsonschema.Validate(schemaLoader, documentLoader)
		assert.NoError(t, err)
		if expectError != "" {
			assert.False(t, result.Valid())
			assert.Contains(t, result.Errors()[0].String(), expectError)
		} else {
			assert.True(t, result.Valid(), result.Errors())
		}
	})
}

// Recursively convert yaml interface to JSON interface
func convertYamlToJson(yamlValue interface{}) interface{} {
	switch yamlMapping := yamlValue.(type) {
	case map[interface{}]interface{}:
		jsonMapping := map[string]interface{}{}
		for key, value := range yamlMapping {
			if key == true {
				// "on" is considered a true value for the Yaml Unmarshaler. To work around it, we set the true to be "on".
				key = "on"
			}
			jsonMapping[fmt.Sprint(key)] = convertYamlToJson(value)
		}
		return jsonMapping
	case []interface{}:
		for i, value := range yamlMapping {
			yamlMapping[i] = convertYamlToJson(value)
		}
	}
	return yamlValue
}
