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
	"fmt"
	"io"
	"reflect"
	"strings"
	"text/tabwriter"
)

type tablePrinter struct {
	def  *TableDefinition
	opts *TableOptions
}

func (p *tablePrinter) Print(w io.Writer, data any) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	defer tw.Flush()

	if p.def == nil {
		return nil
	}

	// Determine which column indices to show
	activeIdx := columnIndices(p.def.Headers, p.opts.Columns)
	maxWidth := p.opts.MaxColWidth

	printRow := func(cols []string) {
		selected := make([]string, 0, len(activeIdx))
		for _, i := range activeIdx {
			val := ""
			if i < len(cols) {
				val = cols[i]
			}
			if !p.opts.NoTruncate {
				val = truncate(val, maxWidth)
			}
			selected = append(selected, val)
		}
		fmt.Fprintln(tw, strings.Join(selected, "\t"))
	}

	if !p.opts.NoHeaders && len(activeIdx) > 0 {
		headerCols := make([]string, 0, len(activeIdx))
		for _, i := range activeIdx {
			headerCols = append(headerCols, p.def.Headers[i])
		}
		fmt.Fprintln(tw, strings.Join(headerCols, "\t"))
	}

	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Slice {
		printRow(p.def.RowFunc(data))
		return nil
	}

	for i := 0; i < v.Len(); i++ {
		printRow(p.def.RowFunc(v.Index(i).Interface()))
	}
	return nil
}
