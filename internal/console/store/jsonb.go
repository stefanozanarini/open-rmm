package store

import "strings"

// jsonbText is a module result as PostgreSQL jsonb accepts it: jsonb has no
// NUL character, which a module may copy from the registry or a file
// ("\u0000" in the JSON text), and refuses the whole document. Escaped
// NULs are dropped; an escaped backslash followed by u0000 is text and stays.
func jsonbText(b []byte) string {
	s := string(b)
	if !strings.Contains(s, `\u0000`) {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			if strings.HasPrefix(s[i:], `\u0000`) {
				i += 5
				continue
			}
			out.WriteByte(s[i])
			out.WriteByte(s[i+1])
			i++
			continue
		}
		out.WriteByte(s[i])
	}
	return out.String()
}
