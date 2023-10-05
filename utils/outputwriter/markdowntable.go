package outputwriter

import (
	"fmt"
	"strings"
)

const (
	tableRowFirstColumnSeparator = "| :---------------------: |"
	tableRowColumnSeparator      = " :-----------------------------------: |"
	cellFirstCellPlaceholder     = "| %s                |"
	cellCellPlaceholder          = " %s                  |"
	cellDefaultValue             = "-"

	// (Default value for columns) If more than one value exists in a cell, the values will be separated by the delimiter.
	SeparatorDelimited MarkdownColumnType = "single"
	// If more than one value exists in a cell, for each value a new row will be created.
	// The first row will contain the other columns values, and the rest of the rows will contain the values of the multi value column only.
	// Only works if exists up to one MultiRowColumn in the table.
	MultiRowColumn MarkdownColumnType = "multi"
)

type MarkdownTable struct {
	columns   []*MarkdownColumn
	delimiter string
	rows      [][]CellData
}

type MarkdownColumnType string

type MarkdownColumn struct {
	Name         string
	BuildType    MarkdownColumnType
	DefaultValue string
}

type CellData []string

func NewCellData(values ...string) CellData {
	if len(values) == 0 {
		return CellData{""}
	}
	return values
}

func NewMarkdownTable(columns ...string) *MarkdownTable {
	columnsInfo := []*MarkdownColumn{}
	for _, column := range columns {
		columnsInfo = append(columnsInfo, &MarkdownColumn{Name: column, BuildType: SeparatorDelimited, DefaultValue: cellDefaultValue})
	}
	return &MarkdownTable{columns: columnsInfo, delimiter: simpleSeparator}
}

func (t *MarkdownTable) SetDelimiter(delimiter string) *MarkdownTable {
	t.delimiter = delimiter
	return t
}

func (t *MarkdownTable) GetColumnInfo(name string) *MarkdownColumn {
	for _, column := range t.columns {
		if column.Name == name {
			return column
		}
	}
	return nil
}

func (t *MarkdownTable) AddRow(values ...string) *MarkdownTable {
	if len(values) == 0 {
		return t
	}
	cellData := []CellData{}
	for _, value := range values {
		cellData = append(cellData, NewCellData(value))
	}
	return t.AddRowWithCellData(cellData...)
}

func (t *MarkdownTable) AddRowWithCellData(values ...CellData) *MarkdownTable {
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

func (t *MarkdownTable) Build() string {
	if len(t.columns) == 0 {
		return ""
	}
	var tableBuilder strings.Builder
	// Header
	for c, column := range t.columns {
		if c == 0 {
			tableBuilder.WriteString(fmt.Sprintf(cellFirstCellPlaceholder, column.Name))
		} else {
			tableBuilder.WriteString(fmt.Sprintf(cellCellPlaceholder, column.Name))
		}
	}
	tableBuilder.WriteString("\n")
	// Separator
	for c := range t.columns {
		if c == 0 {
			tableBuilder.WriteString(tableRowFirstColumnSeparator)
		} else {
			tableBuilder.WriteString(tableRowColumnSeparator)
		}
	}
	// Content
	for _, row := range t.rows {
		tableBuilder.WriteString(t.getRowContent(row))
	}
	return tableBuilder.String()
}

func (t *MarkdownTable) getRowContent(row []CellData) string {
	if columnIndex, multiValueColumn := t.getMultiValueColumn(); multiValueColumn != nil && len(row[columnIndex]) > 1 {
		return t.getMultiValueRowsContent(row, columnIndex, *multiValueColumn)
	}
	return t.getSeparatorDelimitedRowContent(row)
}

func (t *MarkdownTable) getMultiValueColumn() (int, *MarkdownColumn) {
	for i, column := range t.columns {
		if column.BuildType == MultiRowColumn {
			return i, column
		}
	}
	return -1, nil
}

func (t *MarkdownTable) getMultiValueRowsContent(row []CellData, multiValueColumnIndex int, multiValueColumn MarkdownColumn) string {
	var rowBuilder strings.Builder
	firstRow := true
	for _, value := range row[multiValueColumnIndex] {
		// Add row for each value in the multi values column
		if len(value) == 0 {
			continue
		}
		content := []string{}
		for column, cell := range row {
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

func (t *MarkdownTable) getSeparatorDelimitedRowContent(row []CellData) string {
	content := []string{}
	for column, columnInfo := range t.columns {
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

func (t *MarkdownTable) getCellContent(data CellData, defaultValue string) string {
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
