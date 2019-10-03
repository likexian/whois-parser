/*
 * Copyright 2014-2019 Li Kexian
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
 * Go module for domain whois info parse
 * https://www.likexian.com/
 */

package whoisparser

import (
	"strings"
	"testing"

	"github.com/likexian/gokit/assert"
	"github.com/likexian/gokit/xfile"
)

func TestPrepare(t *testing.T) {
	tests := []string{
		"admin.it",
		"git.fr",
		"git.pm",
		"git.re",
		"git.tf",
		"git.wf",
		"git.yt",
		"github.it",
		"google.ch",
		"google.fr",
		"google.pm",
		"google.re",
		"google.tf",
		"google.wf",
		"google.yt",
		"ovh.fr",
		"switch.ch",
		"git.ru",
		"google.ru",
		"git.jp",
		"google.jp",
	}

	for _, v := range tests {
		whoisRaw, err := xfile.ReadText("./examples/" + v)
		assert.Nil(t, err)
		whoisPre, err := xfile.ReadText("./examples/" + v + ".pre")
		assert.Nil(t, err)
		result := Prepare(whoisRaw)
		assert.Equal(t, strings.TrimSpace(result), strings.TrimSpace(whoisPre))
	}
}
