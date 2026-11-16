package target

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// The placeholders a command line may hold, by role. Each is written {name}
// and is replaced, at each start, by the value the harness gives it; {{ and
// }} stand for a literal { and }.
//
// For a relay: {claim}, the address the relay serves its claim endpoint on,
// and {token}, its claim token. For a collector that claims: {claim}, the
// claim address it is started against; {token}, the claim token it sends;
// {out}, its output location; {context}, the build context's directory;
// {script}, the build script's file; and {capture}, the capture mode. A
// read-back may hold {out}, and its command {dir}, the directory it writes
// the layout into.
var (
	relayPlaceholders     = []string{"claim", "token"}
	collectorPlaceholders = []string{"claim", "token", "out", "context", "script", "capture"}
)

// Arg is one element of a command line: a word, or an optional group of
// words that is given only when every placeholder in it has a value.
type Arg struct {
	Words    []string
	Optional bool
}

// Argv is a command line in a target file: an array whose elements are
// strings, each a word, or arrays of strings, each an optional group.
type Argv []Arg

// UnmarshalTOML decodes an Argv from its TOML array.
func (a *Argv) UnmarshalTOML(v any) error {
	list, ok := v.([]any)
	if !ok {
		return fmt.Errorf("a command line is an array of strings and of arrays of strings, not %T", v)
	}
	out := make(Argv, 0, len(list))
	for i, e := range list {
		switch e := e.(type) {
		case string:
			out = append(out, Arg{Words: []string{e}})
		case []any:
			g := Arg{Optional: true}
			for _, w := range e {
				s, ok := w.(string)
				if !ok {
					return fmt.Errorf("element %d of a command line: an optional group holds strings only, not %T", i+1, w)
				}
				g.Words = append(g.Words, s)
			}
			out = append(out, g)
		default:
			return fmt.Errorf("element %d of a command line is a %T; it is a string or an array of strings", i+1, e)
		}
	}
	*a = out
	return nil
}

// parse splits s into literal text and placeholder names: the result
// alternates text, name, text, ..., starting and ending with text.
func parse(s string) ([]string, error) {
	parts := []string{""}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '{' && i+1 < len(s) && s[i+1] == '{', c == '}' && i+1 < len(s) && s[i+1] == '}':
			parts[len(parts)-1] += string(c)
			i++
		case c == '{':
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return nil, fmt.Errorf("%q has a { with no }; write {{ for a literal {", s)
			}
			name := s[i+1 : i+end]
			if name == "" || strings.Trim(name, "abcdefghijklmnopqrstuvwxyz_") != "" {
				return nil, fmt.Errorf("%q holds {%s}, which is not a placeholder name", s, name)
			}
			parts = append(parts, name, "")
			i += end
		case c == '}':
			return nil, fmt.Errorf("%q has a } with no {; write }} for a literal }", s)
		default:
			parts[len(parts)-1] += string(c)
		}
	}
	return parts, nil
}

// placeholderNames are the placeholders s holds; s has been checked.
func placeholderNames(s string) []string {
	parts, _ := parse(s)
	var names []string
	for i := 1; i < len(parts); i += 2 {
		names = append(names, parts[i])
	}
	return names
}

func checkText(key, s string, known []string) error {
	parts, err := parse(s)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	for i := 1; i < len(parts); i += 2 {
		if !slices.Contains(known, parts[i]) {
			if len(known) == 0 {
				return fmt.Errorf("%s: {%s} is not a placeholder here, which takes none", key, parts[i])
			}
			return fmt.Errorf("%s: {%s} is not a placeholder here, which takes %s", key, parts[i], braces(known))
		}
	}
	return nil
}

func braces(names []string) string {
	b := make([]string, len(names))
	for i, n := range names {
		b[i] = "{" + n + "}"
	}
	return strings.Join(b, ", ")
}

// checkArgv checks a launcher's command line and environment. A program's
// command line starts with the program, a plain word.
func checkArgv(key string, argv Argv, env map[string]string, known []string, program bool) error {
	if program {
		if len(argv) == 0 {
			return fmt.Errorf("%s is missing: the program and its arguments", key)
		}
		if argv[0].Optional || argv[0].Words[0] == "" || checkText(key, argv[0].Words[0], nil) != nil {
			return fmt.Errorf("%s: its first element is the program, a plain string", key)
		}
	}
	for i, a := range argv {
		if a.Optional && len(a.Words) == 0 {
			return fmt.Errorf("%s: element %d is an empty optional group", key, i+1)
		}
		var names []string
		for _, w := range a.Words {
			if err := checkText(key, w, known); err != nil {
				return err
			}
			names = append(names, placeholderNames(w)...)
		}
		if a.Optional && len(names) == 0 {
			return fmt.Errorf("%s: element %d is an optional group with no placeholder, which would always be given; write its words as plain elements", key, i+1)
		}
	}
	names := make([]string, 0, len(env))
	for n := range env {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if n == "" || strings.ContainsAny(n, "=\x00") {
			return fmt.Errorf("%s: %q is not an environment variable name", envKey(key), n)
		}
		if err := checkText(envKey(key)+"."+n, env[n], known); err != nil {
			return err
		}
	}
	return nil
}

func envKey(argvKey string) string {
	table, _, _ := strings.Cut(argvKey, ".")
	return table + ".env"
}

// plainArgv checks a command line of plain words, which starts with the
// program.
func plainArgv(key string, argv []string, known []string) error {
	if len(argv) == 0 || argv[0] == "" {
		return fmt.Errorf("%s is missing: the program and its arguments", key)
	}
	if err := checkText(key, argv[0], nil); err != nil {
		return fmt.Errorf("%s: its first element is the program, a plain string", key)
	}
	for _, w := range argv[1:] {
		if err := checkText(key, w, known); err != nil {
			return err
		}
	}
	return nil
}

// Expand replaces each placeholder in s by its value in values. A
// placeholder with no value, absent or empty, is an error that names it.
func Expand(s string, values map[string]string) (string, error) {
	parts, err := parse(s)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for i, p := range parts {
		if i%2 == 0 {
			b.WriteString(p)
			continue
		}
		v := values[p]
		if v == "" {
			return "", fmt.Errorf("{%s} has no value in this start", p)
		}
		b.WriteString(v)
	}
	return b.String(), nil
}

func hasValues(s string, values map[string]string) bool {
	for _, n := range placeholderNames(s) {
		if values[n] == "" {
			return false
		}
	}
	return true
}

// ExpandArgv expands a command line: each word is expanded, and an optional
// group is given only when every placeholder in it has a value. A word
// outside a group whose placeholder has no value is an error.
func ExpandArgv(argv Argv, values map[string]string) ([]string, error) {
	var out []string
	for _, a := range argv {
		if a.Optional {
			given := true
			for _, w := range a.Words {
				given = given && hasValues(w, values)
			}
			if !given {
				continue
			}
		}
		for _, w := range a.Words {
			e, err := Expand(w, values)
			if err != nil {
				return nil, err
			}
			out = append(out, e)
		}
	}
	return out, nil
}

// ExpandEnv expands an environment, as NAME=value entries sorted by name. An
// entry is set only when every placeholder in its value has a value, so that
// a component started without, say, a claim token is not given the variable
// at all.
func ExpandEnv(env map[string]string, values map[string]string) ([]string, error) {
	names := make([]string, 0, len(env))
	for n := range env {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []string
	for _, n := range names {
		if !hasValues(env[n], values) {
			continue
		}
		v, err := Expand(env[n], values)
		if err != nil {
			return nil, err
		}
		out = append(out, n+"="+v)
	}
	return out, nil
}

// ExpandPlain expands a command line of plain words; every placeholder must
// have a value.
func ExpandPlain(argv []string, values map[string]string) ([]string, error) {
	out := make([]string, len(argv))
	for i, w := range argv {
		e, err := Expand(w, values)
		if err != nil {
			return nil, err
		}
		out[i] = e
	}
	return out, nil
}
