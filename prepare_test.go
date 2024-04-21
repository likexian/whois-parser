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
	"fmt"
	"strings"
	"testing"

	"github.com/likexian/gokit/assert"
	"github.com/likexian/gokit/xfile"
)

func TestPrepare(t *testing.T) {
	dirs, err := xfile.ListDir(noterrorDir, xfile.TypeFile, -1)
	assert.Nil(t, err)

	for _, v := range dirs {
		if v.Name == "README.md" {
			continue
		}

		domain := strings.Split(v.Name, "_")[1]
		extension := ""
		if strings.Contains(v.Name, ".") {
			extension = domain[strings.LastIndex(domain, ".")+1:]
		}

		if assert.IsContains([]string{"pre", "out"}, extension) {
			continue
		}

		whoisRaw, err := xfile.ReadText(noterrorDir + "/" + v.Name)
		assert.Nil(t, err)

		whoisPrepare, prepared := Prepare(whoisRaw, extension)
		if prepared {
			prePrepare := ""
			whoisPrepare = strings.TrimSpace(whoisPrepare)

			preFile := fmt.Sprintf(noterrorDir+"/%s.pre", v.Name)
			if xfile.Exists(preFile) {
				prePrepare, err = xfile.ReadText(preFile)
				assert.Nil(t, err)
			}

			err = xfile.WriteText(preFile, whoisPrepare)
			assert.Nil(t, err)

			if prePrepare != "" {
				assert.Equal(t, whoisPrepare, prePrepare)
			}
		}
	}
}
