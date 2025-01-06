package outputwriter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarkdownTableContent(t *testing.T) {
	testCases := []struct {
		name           string
		columns        []string
		rows           [][]string
		expectedOutput [][]CellData
	}{
		{
			name:           "Empty",
			columns:        []string{},
			rows:           [][]string{},
			expectedOutput: [][]CellData{},
		},
		{
			name:           "No rows",
			columns:        []string{"col1"},
			rows:           [][]string{},
			expectedOutput: [][]CellData{},
		},
		{
			name:    "Same number of columns",
			columns: []string{"col1", "col2", "col3"},
			rows: [][]string{
				{"row1col1", "row1col2", "row1col3"},
				{"row2col1", "row2col2", "row2col3"},
				{"row3col1", "row3col2", "row3col3"},
			},
			expectedOutput: [][]CellData{
				{{"row1col1"}, {"row1col2"}, {"row1col3"}},
				{{"row2col1"}, {"row2col2"}, {"row2col3"}},
				{{"row3col1"}, {"row3col2"}, {"row3col3"}},
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
			expectedOutput: [][]CellData{
				{{"row1col1"}, {"row1col2"}, {""}},
				{{"row2col1"}, {"row2col2"}, {""}},
				{{"row3col1"}, {""}, {"row3col3"}},
				{{"row4col1"}, {""}, {""}},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			table := NewMarkdownTable(tc.columns...)
			for _, row := range tc.rows {
				table.AddRow(row...)
			}
			assert.Len(t, table.rows, len(tc.expectedOutput))
			for i, row := range table.rows {
				assertRow(t, row, tc.expectedOutput[i], len(tc.columns))
			}
		})
	}
}

func assertRow(t *testing.T, actual []CellData, expected []CellData, expectedNumberColumns int) {
	assert.Len(t, actual, expectedNumberColumns)
	for i, cell := range actual {
		assert.Len(t, cell, len(expected[i]))
		for j, value := range cell {
			assert.Equal(t, expected[i][j], value)
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
			expectedOutput: "| col1                |\n" + centeredFirstColumnSeparator,
		},
		{
			name:    "Same number of columns",
			columns: []string{"col1", "col2"},
			rows: [][]string{
				{"row1col1", "row1col2"},
				{"row2col1", "row2col2"},
				{"row3col1", "row3col2"},
			},
			expectedOutput: "| col1                | col2                  |\n" + centeredFirstColumnSeparator + centeredColumnSeparator + `
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
			expectedOutput: "| col1                | col2                  | col3                  |\n" + centeredFirstColumnSeparator + centeredColumnSeparator + centeredColumnSeparator + `
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

func TestHideEmptyColumnsInTable(t *testing.T) {
	columns := []*MarkdownColumn{
		{Name: "col1", OmitEmpty: true},
		{Name: "col2", OmitEmpty: true, Centered: true},
		{Name: "col3", OmitEmpty: false, DefaultValue: "-"},
		{Name: "col4", OmitEmpty: true},
	}
	testCases := []struct {
		name           string
		rows           [][]string
		expectedOutput string
	}{
		{
			name: "Defined as hidden but not empty",
			rows: [][]string{
				{"row1col1", "row1col2", "", "row1col4"},
				{"row2col1", "row2col2", "", "row2col4"},
			},
			expectedOutput: "| col1                | col2                  | col3                  | col4                  |\n" + defaultFirstColumnSeparator + centeredColumnSeparator + defaultColumnSeparator + defaultColumnSeparator + `
| row1col1 | row1col2 | - | row1col4 |
| row2col1 | row2col2 | - | row2col4 |`,
		},
		{
			name: "Defined as hidden and some empty",
			rows: [][]string{
				{"row1col1", "", "row1col3", ""},
				{"row2col1", "", "", ""},
			},
			expectedOutput: "| col1                | col3                  |\n" + defaultFirstColumnSeparator + defaultColumnSeparator + `
| row1col1 | row1col3 |
| row2col1 | - |`,
		},
		{
			name: "Defined as hidden and all empty",
			rows: [][]string{
				{"", "", "row1col3", ""},
				{"", "", "", ""},
			},
			expectedOutput: "| col3                |\n" + defaultFirstColumnSeparator + `
| row1col3 |
| - |`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			table := NewMarkdownTableWithColumns(columns...)
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
		columns        []MarkdownColumn
		rows           [][]CellData
	}{
		{
			name:    "Empty on multi value column",
			columns: []MarkdownColumn{{Name: "col1", ColumnType: MultiRowColumn}, {Name: "col2"}, {Name: "col3"}},
			rows: [][]CellData{
				{{""}, {"row1col2"}, {"row1col3"}},
			},
			expectedOutput: "| col1                | col2                  | col3                  |\n" + centeredFirstColumnSeparator + centeredColumnSeparator + centeredColumnSeparator + `
| - | row1col2 | row1col3 |`,
		},
		{
			name:    "One value on multi value column",
			columns: []MarkdownColumn{{Name: "col1"}, {Name: "col2"}, {Name: "col3", ColumnType: MultiRowColumn}},
			rows: [][]CellData{
				{{"row1col1"}, {"row1col2"}, {"row1col3"}},
				{{"row2col1"}, {"row2col2"}, {"row2col3"}},
			},
			expectedOutput: "| col1                | col2                  | col3                  |\n" + centeredFirstColumnSeparator + centeredColumnSeparator + centeredColumnSeparator + `
| row1col1 | row1col2 | row1col3 |
| row2col1 | row2col2 | row2col3 |`,
		},
		{
			name:    "Multiple values on separator delimited column",
			columns: []MarkdownColumn{{Name: "col1"}, {Name: "col2"}, {Name: "col3"}},
			rows: [][]CellData{
				{{"row1col1"}, {""}, {"row1col3"}},
				{{"row2col1"}, {"row2col2"}, {"row2col3val1", "row2col3val2"}},
				{{"row3col1"}, {"row3col2val1", "row3col2val2", "row3col2val3"}, {"row3col3"}},
			},
			expectedOutput: "| col1                | col2                  | col3                  |\n" + centeredFirstColumnSeparator + centeredColumnSeparator + centeredColumnSeparator + `
| row1col1 | - | row1col3 |
| row2col1 | row2col2 | row2col3val1, row2col3val2 |
| row3col1 | row3col2val1, row3col2val2, row3col2val3 | row3col3 |`,
		},
		{
			name:    "Multiple values on multi row column",
			columns: []MarkdownColumn{{Name: "col1"}, {Name: "col2", ColumnType: MultiRowColumn}, {Name: "col3"}},
			rows: [][]CellData{
				{{"row1col1"}, {""}, {"row1col3"}},
				{{"row2col1"}, {"row2col2"}, {"row2col3val1", "row2col3val2"}},
				{{"row3col1"}, {"row3col2val1", "row3col2val2", "row3col2val3"}, {"row3col3"}},
			},
			expectedOutput: "| col1                | col2                  | col3                  |\n" + centeredFirstColumnSeparator + centeredColumnSeparator + centeredColumnSeparator + `
| row1col1 | - | row1col3 |
| row2col1 | row2col2 | row2col3val1, row2col3val2 |
| row3col1 | row3col2val1 | row3col3 |
|   | row3col2val2 |   |
|   | row3col2val3 |   |`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			columns := []string{}
			for _, column := range tc.columns {
				columns = append(columns, column.Name)
			}
			table := NewMarkdownTable(columns...)
			for _, column := range tc.columns {
				if column.ColumnType == MultiRowColumn {
					table.GetColumnInfo(column.Name).ColumnType = MultiRowColumn
				}
			}
			for _, row := range tc.rows {
				table.AddRowWithCellData(row...)
			}
			assert.Equal(t, tc.expectedOutput, table.Build())
		})
	}
}
