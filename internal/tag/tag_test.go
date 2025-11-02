package tag_test

import (
	"maps"
	"testing"

	"github.com/deep-rent/nexus/internal/tag"
	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input    string
		wantName string
	}{
		{`json,omitempty,default:value`, "json"},
		{`xml`, "xml"},
		{`db:name,type:text`, "db:name"},
		{``, ""},
		{`,opt1,opt2`, ""},
		{`custom,config:'a,b',max:10`, "custom"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			p := tag.Parse(tc.input)
			assert.Equal(t, tc.wantName, p.Name)
		})
	}
}

func TestTag_Opts(t *testing.T) {
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
			"quoted_comma_double",
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := "dummy"
			if tc.opts != "" {
				s += "," + tc.opts
			}

			p := tag.Parse(s)
			m := maps.Collect(p.Opts())
			assert.Equal(t, tc.want, m)
		})
	}
}
