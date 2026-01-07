package outputwriter

import (
	"fmt"
	"strings"
)

const (
	cellDefaultValue = "-"

	firstCellPlaceholder = "| %s                |"
	cellPlaceholder      = " %s                  |"

	centeredFirstColumnSeparator = "| :---------------------: |"
	centeredColumnSeparator      = " :-----------------------------------: |"

	defaultFirstColumnSeparator = "| --------------------- |"
	defaultColumnSeparator      = " ----------------------------------- |"

	// (Default value for columns) If more than one value exists in a cell, the values will be separated by the delimiter.
	SeparatorDelimited MarkdownColumnType = "single"
	// If more than one value exists in a cell, for each value a new row will be created.
	// The first row will contain the other columns values, and the rest of the rows will contain the values of the multi value column only.
	// Only works if exists up to one MultiRowColumn in the table.
	MultiRowColumn MarkdownColumnType = "multi"
)

// Create a markdown table using the provided columns and rows, and construct a markdown string with the table's content.
// Each cell in the table can contain no values (represented as column default value), single or multiple values (separated by the table delimiter).
type MarkdownTableBuilder struct {
	columns   []*MarkdownColumn
	delimiter string
	rows      [][]CellData
}

type MarkdownColumnType string

type MarkdownColumn struct {
	Name         string
	Centered     bool
	OmitEmpty    bool
	ColumnType   MarkdownColumnType
	DefaultValue string
	// Internal flag to determine if the column should be hidden
	shouldHideColumn bool
}

// CellData represents the data of a cell in the markdown table. Each cell can contain multiple values.
type CellData []string

func NewCellData(values ...string) CellData {
	if len(values) == 0 {
		// In markdown table, empty cell = cell with no values = cell with one empty value
		return CellData{""}
	}
	return values
}

// Create a markdown table builder with the provided columns.
func NewMarkdownTable(columns ...string) *MarkdownTableBuilder {
	columnsInfo := []*MarkdownColumn{}
	for _, column := range columns {
		columnsInfo = append(columnsInfo, NewMarkdownTableSingleValueColumn(column, cellDefaultValue, true))
	}
	return NewMarkdownTableWithColumns(columnsInfo...)
}

// Create a markdown table builder with the provided number of columns.
func NewNoHeaderMarkdownTable(nColumns int, firstColumnCentered bool) *MarkdownTableBuilder {
	columnsInfo := []*MarkdownColumn{}
	for i := 0; i < nColumns; i++ {
		columnsInfo = append(columnsInfo, NewMarkdownTableSingleValueColumn("", cellDefaultValue, i != 0 || firstColumnCentered))
	}
	return NewMarkdownTableWithColumns(columnsInfo...)
}

func NewMarkdownTableWithColumns(columnsInfo ...*MarkdownColumn) *MarkdownTableBuilder {
	return &MarkdownTableBuilder{columns: columnsInfo, delimiter: simpleSeparator}
}

func NewMarkdownTableSingleValueColumn(name, defaultValue string, centered bool) *MarkdownColumn {
	return &MarkdownColumn{Name: name, ColumnType: SeparatorDelimited, DefaultValue: defaultValue, Centered: centered}
}

// Set the delimiter that will be used to separate multiple values in a cell.
func (t *MarkdownTableBuilder) SetDelimiter(delimiter string) *MarkdownTableBuilder {
	t.delimiter = delimiter
	return t
}

func (t *MarkdownTableBuilder) HasContent() bool {
	return len(t.rows) > 0
}

// Get the column information output controller by the provided name.
func (t *MarkdownTableBuilder) GetColumnInfo(name string) *MarkdownColumn {
	for _, column := range t.columns {
		if column.Name == name {
			return column
		}
	}
	return nil
}

// Add a row to the markdown table, each value will be added to the corresponding column.
// Use to add row with single value columns only.
func (t *MarkdownTableBuilder) AddRow(values ...string) *MarkdownTableBuilder {
	if len(values) == 0 {
		return t
	}
	cellData := []CellData{}
	for _, value := range values {
		cellData = append(cellData, NewCellData(value))
	}
	return t.AddRowWithCellData(cellData...)
}

// Add a row to the markdown table, each value will be added to the corresponding column.
// Use to add row with multiple value columns.
func (t *MarkdownTableBuilder) AddRowWithCellData(values ...CellData) *MarkdownTableBuilder {
	if len(values) == 0 {
		return t
	}
	nColumns := len(t.columns)
	row := make([]CellData, nColumns)

	for c := 0; c < nColumns; c++ {
		if c < len(values) {
			row[c] = values[c]
		} else {
			row[c] = NewCellData()
		}
	}

	t.rows = append(t.rows, row)
	return t
}

func (t *MarkdownTableBuilder) Build() string {
	if len(t.columns) == 0 {
		return ""
	}
	var tableBuilder strings.Builder
	// Calculate Hidden columns
	for c := range t.columns {
		// Reset shouldHideColumn flag to the defined value in the column
		// If the column OmitEmpty flag is set, the column will be hidden if all the values in the column are empty
		t.columns[c].shouldHideColumn = t.columns[c].OmitEmpty
	}
	for _, row := range t.rows {
		for c, cell := range row {
			// In table, empty cell = cell with no values = cell with one empty value
			// So we want don't want to hide the column if at least one cell has a value in it
			t.columns[c].shouldHideColumn = t.columns[c].shouldHideColumn && (len(cell) == 0 || (len(cell) == 1 && cell[0] == ""))
		}
	}
	// Header
	isFirstCol := true
	for _, column := range t.columns {
		if column.shouldHideColumn {
			continue
		}
		if isFirstCol {
			tableBuilder.WriteString(fmt.Sprintf(firstCellPlaceholder, column.Name))
		} else {
			tableBuilder.WriteString(fmt.Sprintf(cellPlaceholder, column.Name))
		}
		isFirstCol = false
	}
	tableBuilder.WriteString("\n")
	// Separator
	isFirstCol = true
	for _, column := range t.columns {
		if column.shouldHideColumn {
			continue
		}
		if isFirstCol {
			columnSeparator := defaultFirstColumnSeparator
			if column.Centered {
				columnSeparator = centeredFirstColumnSeparator
			}
			tableBuilder.WriteString(columnSeparator)
		} else {
			columnSeparator := defaultColumnSeparator
			if column.Centered {
				columnSeparator = centeredColumnSeparator
			}
			tableBuilder.WriteString(columnSeparator)
		}
		isFirstCol = false
	}
	// Content
	for _, row := range t.rows {
		tableBuilder.WriteString(t.getRowContent(row))
	}
	return tableBuilder.String()
}

func (t *MarkdownTableBuilder) getRowContent(row []CellData) string {
	if columnIndex, multiValueColumn := t.getMultiValueColumn(); multiValueColumn != nil && len(row[columnIndex]) > 1 {
		return t.getMultiValueRowsContent(row, columnIndex)
	}
	return t.getSeparatorDelimitedRowContent(row)
}

func (t *MarkdownTableBuilder) getMultiValueColumn() (int, *MarkdownColumn) {
	for i, column := range t.columns {
		if column.ColumnType == MultiRowColumn {
			return i, column
		}
	}
	return -1, nil
}

func (t *MarkdownTableBuilder) getMultiValueRowsContent(row []CellData, multiValueColumnIndex int) string {
	var rowBuilder strings.Builder
	firstRow := true
	for _, value := range row[multiValueColumnIndex] {
		// Add row for each value in the multi values column
		if len(value) == 0 {
			continue
		}
		content := []string{}
		for column, cell := range row {
			if t.columns[column].shouldHideColumn {
				continue
			}
			if column == multiValueColumnIndex {
				// Multi values column separated by different rows, add the specific value for this row
				content = append(content, value)
			} else {
				if firstRow {
					// First row contains the other columns values as well
					content = append(content, t.getCellContent(cell, t.columns[column].DefaultValue))
				} else {
					// Rest of the rows contains only the multi values column value
					content = append(content, " ")
				}
			}
		}
		firstRow = false
		rowBuilder.WriteString(buildRowContent(content...))
	}
	return rowBuilder.String()
}

func (t *MarkdownTableBuilder) getSeparatorDelimitedRowContent(row []CellData) string {
	content := []string{}
	for column, columnInfo := range t.columns {
		if columnInfo.shouldHideColumn {
			continue
		}
		content = append(content, t.getCellContent(row[column], columnInfo.DefaultValue))
	}
	return buildRowContent(content...)
}

func buildRowContent(content ...string) string {
	if len(content) == 0 {
		return ""
	}
	var rowBuilder strings.Builder
	rowBuilder.WriteString("\n")
	for c, cell := range content {
		if c == 0 {
			rowBuilder.WriteString(fmt.Sprintf("| %s |", cell))
		} else {
			rowBuilder.WriteString(fmt.Sprintf(" %s |", cell))
		}
	}
	return rowBuilder.String()
}

func (t *MarkdownTableBuilder) getCellContent(data CellData, defaultValue string) string {
	if len(data) == 0 {
		return defaultValue
	}
	var cellBuilder strings.Builder
	for _, value := range data {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		cellBuilder.WriteString(fmt.Sprintf("%s%s", value, t.delimiter))
	}
	value := strings.TrimSuffix(cellBuilder.String(), t.delimiter)
	if value == "" {
		return defaultValue
	}
	return value
}
