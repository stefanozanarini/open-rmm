package store

import "testing"

func TestJSONBText(t *testing.T) {
	for in, want := range map[string]string{
		`{"a":"x"}`:           `{"a":"x"}`,
		`{"a":"x\u0000y"}`:    `{"a":"xy"}`,
		`{"a":"\\u0000"}`:     `{"a":"\\u0000"}`,
		`{"a":"\\\u0000z\n"}`: `{"a":"\\z\n"}`,
	} {
		if got := jsonbText([]byte(in)); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
