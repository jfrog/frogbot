package schema

import (
	"os"
	"path/filepath"
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
	validateSchema(t, schemaLoader, filepath.Join("..", "docs", "templates", ".frogbot", "frogbot-config.yml"), "")

	// Validate all frogbot configs in commands/testdata/config
	err = filepath.Walk(filepath.Join("..", "commands", "testdata", "config"), func(frogbotConfigFilePath string, info os.FileInfo, err error) error {
		assert.NoError(t, err)
		if !info.IsDir() {
			validateSchema(t, schemaLoader, frogbotConfigFilePath, "")
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
		validateSchema(t, schemaLoader, filepath.Join("testdata", testCase.testName+".yml"), testCase.errorString)
	}
}

// Validate frogbot config against the frogbot schema
func validateSchema(t *testing.T, schemaLoader gojsonschema.JSONLoader, frogbotConfigFilePath, expectError string) {
	t.Run(filepath.Base(frogbotConfigFilePath), func(t *testing.T) {
		// Read frogbot config
		frogbotConfigFile, err := os.ReadFile(frogbotConfigFilePath)
		assert.NoError(t, err)

		// Unmarshal frogbot config
		var frogbotConfigYaml interface{}
		err = yaml.Unmarshal(frogbotConfigFile, &frogbotConfigYaml)
		assert.NoError(t, err)

		// Convert the Yaml schema to JSON schema to help the json parser to validate it
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
