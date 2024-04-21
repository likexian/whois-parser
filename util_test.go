/*
 * Copyright 2014-2024 Li Kexian
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Go module for domain whois information parsing
 * https://www.likexian.com/
 */

package whoisparser

import (
	"testing"

	"github.com/likexian/gokit/assert"
)

// https://github.com/golang/go/wiki/TableDrivenTests
func TestParseDateString(t *testing.T) {
	t.Parallel() // marks TLog as capable of running in parallel with other tests
	tests := []struct {
		date string
	}{
		{"09-Mar-2023"},
		{"31-Jul-2022"},
		{"2022-12-12T11:01:02Z"},
		{"2022-12-03"},
		{"2022. 12. 01."},
		{"2022-12-12 11:40:12"},
		{"2022.12.12 11:40:12"},
		{"28/06/2022 23:59:59"},
		{"24.10.2022"},
		{"2022-06-29 14:08:21+03"},
		{"31.8.2025 00:00:00"},
		{"01-10-2025"},
		{"20-Apr-2023 03:28:40"},
		{"2022-12-08 14:00:00 CLST"},
		{"December  2 2022"},
		{"Mon Jan  2 2006"},
		{"02/28/2025"},
		{"2001/03/22"},
		{"April 10 2023"},
		{"2025-Dec-11"},
		{"2025-Dec-11."},
		{"2024-06-05 00:00:00 (UTC+8)"},
		{"20221101 00:10:24"},
	}

	for _, tt := range tests {
		tt := tt // NOTE: https://github.com/golang/go/wiki/CommonMistakes#using-goroutines-on-loop-iterator-variables
		t.Run(tt.date, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other
			_, err := parseDateString(tt.date)
			assert.Nil(t, err)
		})
	}
}
