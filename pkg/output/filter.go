// Copyright (c) 2026 CrowdStrike, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package output

import (
	"sort"
	"strconv"
	"strings"
)

// FilterAndSort applies client-side grep and sort-by to a slice of items,
// using the TableDefinition's RowFunc to extract column values.
// The original slice is not modified; a new slice is returned.
func FilterAndSort[T any](items []T, def *TableDefinition, opts *FilterOptions) []T {
	if def == nil || opts == nil {
		return items
	}

	result := items

	// Grep: keep rows where any column contains the pattern (case-insensitive)
	if opts.Grep != "" {
		pattern := strings.ToLower(opts.Grep)
		filtered := make([]T, 0, len(result))
		for _, item := range result {
			cols := def.RowFunc(item)
			for _, col := range cols {
				if strings.Contains(strings.ToLower(col), pattern) {
					filtered = append(filtered, item)
					break
				}
			}
		}
		result = filtered
	}

	// Sort-by: sort by a named column, prefix "-" for descending
	if opts.SortBy != "" {
		colName := opts.SortBy
		descending := false
		if strings.HasPrefix(colName, "-") {
			descending = true
			colName = colName[1:]
		}
		colName = strings.ToLower(strings.TrimSpace(colName))

		// Find the column index
		colIdx := -1
		for i, h := range def.Headers {
			if strings.ToLower(h) == colName {
				colIdx = i
				break
			}
		}

		if colIdx >= 0 {
			sorted := make([]T, len(result))
			copy(sorted, result)
			sort.SliceStable(sorted, func(i, j int) bool {
				ci := def.RowFunc(sorted[i])
				cj := def.RowFunc(sorted[j])
				vi, vj := "", ""
				if colIdx < len(ci) {
					vi = ci[colIdx]
				}
				if colIdx < len(cj) {
					vj = cj[colIdx]
				}
				// Try numeric comparison first; fall back to string
				fi, errI := strconv.ParseFloat(vi, 64)
				fj, errJ := strconv.ParseFloat(vj, 64)
				if errI == nil && errJ == nil {
					if descending {
						return fi > fj
					}
					return fi < fj
				}
				if descending {
					return vi > vj
				}
				return vi < vj
			})
			result = sorted
		}
	}

	return result
}
