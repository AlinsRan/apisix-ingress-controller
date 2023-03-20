// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
package utils

func TruncateString(s string, max int) string {
	if max > len(s) || max < 0 {
		return s
	}
	return s[:max]
}

// Difference returns elements only in a
// Duplicated elements are considered as same element
func Difference(a, b []string) []string {
	bMap := make(map[string]struct{}, len(b))
	for _, elem := range b {
		bMap[elem] = struct{}{}
	}
	var onlyInA []string
	for _, elem := range a {
		if _, found := bMap[elem]; !found {
			onlyInA = append(onlyInA, elem)
		}
	}
	return onlyInA
}

func Equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	return len(Difference(a, b)) == 0 && len(Difference(b, a)) == 0
}

func ReverseString(s string) string {
	buf := make([]byte, len(s))
	for i, b := range []byte(s) {
		idx := len(s) - 1 - i
		buf[idx] = b
	}
	return string(buf)
}
