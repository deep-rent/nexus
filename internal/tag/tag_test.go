// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tag_test

import (
	"maps"
	"reflect"
	"testing"

	"github.com/deep-rent/nexus/internal/tag"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		give string
		want string
	}{
		{`json,omitempty,default:value`, "json"},
		{`xml`, "xml"},
		{`db:name,type:text`, "db:name"},
		{``, ""},
		{`,opt1,opt2`, ""},
		{`custom,config:'a,b',max:10`, "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.give, func(t *testing.T) {
			t.Parallel()
			if got := tag.Parse(tt.give).Name; got != tt.want {
				t.Errorf("Parse(%q).Name = %q; want %q", tt.give, got, tt.want)
			}
		})
	}
}

func TestTag_Opts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts string
		want map[string]string
	}{
		{
			"empty",
			"",
			map[string]string{},
		},
		{
			"flags",
			"opt1,opt2,opt3",
			map[string]string{
				"opt1": "",
				"opt2": "",
				"opt3": "",
			},
		},
		{
			"key value pairs",
			"key1:val1,key2:val2",
			map[string]string{
				"key1": "val1",
				"key2": "val2",
			},
		},
		{
			"mixed",
			"flag1,key:value,flag2",
			map[string]string{
				"flag1": "",
				"key":   "value",
				"flag2": "",
			},
		},
		{
			"quoted comma single",
			`list:'a,b,c',flag`,
			map[string]string{
				"list": "a,b,c",
				"flag": "",
			},
		},
		{
			"quoted comma double",
			`message:"hello, world",flag`,
			map[string]string{
				"message": "hello, world",
				"flag":    "",
			},
		},
		{
			"quoted colon",
			`url:"http://example.com:8080",key2:val2`,
			map[string]string{
				"url":  "http://example.com:8080",
				"key2": "val2",
			},
		},
		{
			"whitespace",
			"  flag_a ,  key_b : value_c , flag_d  ",
			map[string]string{
				"flag_a": "",
				"key_b":  " value_c ",
				"flag_d": "",
			},
		},
		{
			"quoted spaces",
			`key:"val with spaces"`,
			map[string]string{
				"key": "val with spaces",
			},
		},
		{
			"repeated flags",
			`f1,f2:`,
			map[string]string{
				"f1": "",
				"f2": "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := "dummy"
			if tt.opts != "" {
				s += "," + tt.opts
			}

			p := tag.Parse(s)
			got := maps.Collect(p.Opts())
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse(%q).Opts() = %v; want %v", s, got, tt.want)
			}
		})
	}
}
