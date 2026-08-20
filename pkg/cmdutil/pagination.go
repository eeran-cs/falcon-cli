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

package cmdutil

// Int64Ptr returns a pointer to the given int64 value.
func Int64Ptr(v int64) *int64 { return &v }

// Int32Ptr returns a pointer to the given int32 value.
func Int32Ptr(v int32) *int32 { return &v }

// Ptr returns a pointer to the given value.
func Ptr[T any](v T) *T { return &v }

// Deref dereferences a pointer, returning the zero value if nil.
func Deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}

// StringPtr returns a pointer to the given string value, or nil if empty.
func StringPtr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// StringPtrOrNil is an alias for StringPtr — returns nil for the empty string.
func StringPtrOrNil(v string) *string { return StringPtr(v) }
