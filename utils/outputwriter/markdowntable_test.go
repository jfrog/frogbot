package outputwriter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)


func TestMarkdownTableContent(t *testing.T) {
	testCases := []struct {
		name    string
		columns []string
		rows    [][]string
	}{
		{
			name:    "Empty",
			columns: []string{},
			rows:    [][]string{},
		},
		{
			name:    "No rows",
			columns: []string{"col1"},
			rows:    [][]string{},
		},
		{
			name:    "Same number of columns",
			columns: []string{"col1", "col2", "col3"},
			rows: [][]string{
				{"row1col1", "row1col2", "row1col3"},
				{"row2col1", "row2col2", "row2col3"},
				{"row3col1", "row3col2", "row3col3"},
			},
		},
		{
			name:    "Different number of columns",
			columns: []string{"col1", "col2", "col3"},
			rows: [][]string{
				{"row1col1", "row1col2", ""},
				{"row2col1", "row2col2"},
				{"row3col1", "", "row3col3", "row3col4"},
				{"row4col1"},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			table := NewMarkdownTable(tc.columns...)
			for _, row := range tc.rows {
				table.AddRow(row...)
			}
			assert.Len(t, table.rows, len(tc.rows))
			for i, row := range table.rows {
				assertRow(t, row, tc.rows[i], len(tc.columns))
			}
		})
	}
}

func assertRow(t *testing.T, actual []string, expected []string, expectedNumberColumns int) {
	assert.Len(t, actual, expectedNumberColumns)
	for i, cell := range actual {
		if i < len(expected) {
			assert.Equal(t, expected[i], cell)
		} else {
			assert.Equal(t, "", cell)
		}
	}
}

func TestMarkdownTableBuild(t *testing.T) {
	testCases := []struct {
		name           string
		expectedOutput string
		columns        []string
		rows           [][]string
	}{
		{
			name:           "Empty",
			columns:        []string{},
			rows:           [][]string{},
			expectedOutput: "",
		},
		{
			name:           "No rows",
			columns:        []string{"col1"},
			rows:           [][]string{},
			expectedOutput: "| col1                |\n" + tableRowFirstColumnSeparator,
		},
		{
			name:    "Same number of columns",
			columns: []string{"col1", "col2"},
			rows: [][]string{
				{"row1col1", "row1col2"},
				{"row2col1", "row2col2"},
				{"row3col1", "row3col2"},
			},
			expectedOutput: "| col1                | col2                  |\n" + tableRowFirstColumnSeparator + tableRowColumnSeparator + `
| row1col1 | row1col2 |
| row2col1 | row2col2 |
| row3col1 | row3col2 |`,
		},
		{
			name:    "Different number of columns",
			columns: []string{"col1", "col2", "col3"},
			rows: [][]string{
				{"row1col1", "row1col2", ""},
				{"row2col1", "row2col2"},
				{},
				{"row3col1", "", "row3col3", "row3col4"},
				{"row4col1"},
				{"row5col1", "row5col2", "row5col3"},
			},
			expectedOutput: "| col1                | col2                  | col3                  |\n" + tableRowFirstColumnSeparator + tableRowColumnSeparator + tableRowColumnSeparator + `
| row1col1 | row1col2 | - |
| row2col1 | row2col2 | - |
| row3col1 | - | row3col3 |
| row4col1 | - | - |
| row5col1 | row5col2 | row5col3 |`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			table := NewMarkdownTable(tc.columns...)
			for _, row := range tc.rows {
				table.AddRow(row...)
			}

			assert.Equal(t, tc.expectedOutput, table.Build())
		})
	}
}

func TestMultipleValuesInColumnRow(t *testing.T) {
	testCases := []struct {
		name           string
		expectedOutput string
		columns        []string
		rows           [][]CellData
		writer   OutputWriter
	}{
		{
			name:           "Empty",
			columns:        []string{},
			rows:           [][]string{},
			expectedOutput: "",
		},
		{
			name:           "No rows",
			columns:        []string{"col1"},
			rows:           [][]string{},
			expectedOutput: "| col1                |\n" + tableRowFirstColumnSeparator,
		},
		{
			name:    "Same number of columns",
			columns: []string{"col1", "col2"},
			rows: [][]string{
				{"row1col1", "row1col2"},
				{"row2col1", "row2col2"},
				{"row3col1", "row3col2"},
			},
			expectedOutput: "| col1                | col2                  |\n" + tableRowFirstColumnSeparator + tableRowColumnSeparator + `
| row1col1 | row1col2 |
| row2col1 | row2col2 |
| row3col1 | row3col2 |`,
		},
		{
			name:    "Multi value column",
			columns: []string{"col1", "col2"},
			rows: [][]string{
				{"row1col1", "row1col2"},
				{"row2col1", "row2col2"},
				{"row3col1", "row3col2"},
			},
			expectedOutput: "| col1                | col2                  |\n" + tableRowFirstColumnSeparator + tableRowColumnSeparator + `
| row1col1 | row1col2 |
| row2col1 | row2col2 |
| row3col1 | row3col2 |`,
		},
		{
			name:    "Different number of columns",
			columns: []string{"col1", "col2", "col3"},
			rows: [][]string{
				{"row1col1", "row1col2", ""},
				{"row2col1", "row2col2"},
				{},
				{"row3col1", "", "row3col3", "row3col4"},
				{"row4col1"},
				{"row5col1", "row5col2", "row5col3"},
			},
			expectedOutput: "| col1                | col2                  | col3                  |\n" + tableRowFirstColumnSeparator + tableRowColumnSeparator + tableRowColumnSeparator + `
| row1col1 | row1col2 | - |
| row2col1 | row2col2 | - |
| row3col1 | - | row3col3 |
| row4col1 | - | - |
| row5col1 | row5col2 | row5col3 |`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			table := NewMarkdownTable(tc.columns...)
			for _, row := range tc.rows {
				table.AddRow(row...)
			}

			assert.Equal(t, tc.expectedOutput, table.Build())
		})
	}
}