package schema

import (
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
	err = filepath.Walk(filepath.Join("..", "commands", "testdata", "config"), func(frogbotConfigFilePath string, info os.FileInfo, err error) error {
		assert.NoError(t, err)
		if !info.IsDir() {
			validateYamlSchema(t, schemaLoader, frogbotConfigFilePath, "")
		}
		return nil
	})
	assert.NoError(t, err)
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

	// Validate all JFrog Pipelines templates in docs/templates/jfrog-pipelines
	err := filepath.Walk(filepath.Join("..", "docs", "templates", "jfrog-pipelines"), func(yamlFilePath string, info os.FileInfo, err error) error {
		assert.NoError(t, err)
		if !info.IsDir() {
			validateYamlSchema(t, schemaLoader, yamlFilePath, "")
		}
		return nil
	})
	assert.NoError(t, err)
}

func TestGitHubActionsTemplates(t *testing.T) {
	schemaLoader := downloadFromSchemaStore(t, "github-workflow.json")

	// Validate all GitHub Actions templates in docs/templates/github-actions
	err := filepath.Walk(filepath.Join("..", "docs", "templates", "github-actions"), func(yamlFilePath string, info os.FileInfo, err error) error {
		assert.NoError(t, err)
		if !info.IsDir() && strings.HasSuffix(info.Name(), "yml") {
			validateYamlSchema(t, schemaLoader, yamlFilePath, "")
		}
		return nil
	})
	assert.NoError(t, err)
}

func downloadFromSchemaStore(t *testing.T, schema string) gojsonschema.JSONLoader {
	response, err := http.Get("https://json.schemastore.org/" + schema)
	assert.NoError(t, err)
	defer response.Body.Close()
	// Check server response
	assert.Equal(t, http.StatusOK, response.StatusCode, response.Status)
	schemaBytes, err := io.ReadAll(response.Body)
	assert.NoError(t, err)

	return gojsonschema.NewBytesLoader(schemaBytes)
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
			jsonMapping[key.(string)] = convertYamlToJson(value)
		}
		return jsonMapping
	case []interface{}:
		for i, value := range yamlMapping {
			yamlMapping[i] = convertYamlToJson(value)
		}
	}
	return yamlValue
}
