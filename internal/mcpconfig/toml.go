package mcpconfig

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// rawValue is a TOML value this reader does not need, such as a number or a
// boolean, kept as written.
type rawValue string

// readTOML reads the subset of TOML that MCP server tables use: tables, string
// keys, strings, arrays of strings, and inline tables of strings. Anything else is
// kept raw or skipped, never guessed at. Tables are keyed by their dotted path,
// joined with "\x00".
func readTOML(content string) (map[string]map[string]any, error) {
	tables := map[string]map[string]any{"": {}}
	current := ""
	lines := strings.Split(content, "\n")
	for i := 0; i < len(lines); i++ {
		line, err := stripComment(lines[i])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "[["):
			// Arrays of tables are not used by MCP servers; skip their keys.
			current = "\x01"
			continue
		case strings.HasPrefix(line, "["):
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("line %d: malformed table header", i+1)
			}
			keys, err := splitKeys(line[1 : len(line)-1])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", i+1, err)
			}
			current = strings.Join(keys, "\x00")
			if tables[current] == nil {
				tables[current] = map[string]any{}
			}
			continue
		}
		eq := indexOutside(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected key = value", i+1)
		}
		keys, err := splitKeys(line[:eq])
		if err != nil || len(keys) != 1 {
			return nil, fmt.Errorf("line %d: unsupported key", i+1)
		}
		value := strings.TrimSpace(line[eq+1:])
		// Multi-line arrays and strings continue until they close.
		for (strings.HasPrefix(value, "[") && !balanced(value)) ||
			(strings.HasPrefix(value, `"""`) && strings.Count(value, `"""`) < 2) ||
			(strings.HasPrefix(value, `'''`) && strings.Count(value, `'''`) < 2) {
			i++
			if i == len(lines) {
				return nil, fmt.Errorf("unterminated value for %s", keys[0])
			}
			next := lines[i]
			if !strings.HasPrefix(value, `"""`) && !strings.HasPrefix(value, `'''`) {
				if next, err = stripComment(next); err != nil {
					return nil, fmt.Errorf("line %d: %w", i+1, err)
				}
			}
			value += "\n" + next
		}
		parsed, err := parseValue(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", keys[0], err)
		}
		if current != "\x01" {
			tables[current][keys[0]] = parsed
		}
	}
	return tables, nil
}

// stripComment removes a # comment outside strings, and fails on a string left
// open at the end of the line.
func stripComment(line string) (string, error) {
	if t := strings.TrimSpace(line); strings.HasPrefix(t, `"""`) || strings.HasPrefix(t, `'''`) {
		return line, nil
	}
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote == '"' && c == '\\':
			i++
		case quote != 0 && c == quote:
			quote = 0
		case quote == 0 && (c == '"' || c == '\''):
			if strings.HasPrefix(line[i:], `"""`) || strings.HasPrefix(line[i:], `'''`) {
				return line, nil
			}
			quote = c
		case quote == 0 && c == '#':
			return line[:i], nil
		}
	}
	if quote != 0 {
		return "", errors.New("unterminated string")
	}
	return line, nil
}

func indexOutside(s string, target byte) int {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '"' && c == '\\':
			i++
		case quote != 0 && c == quote:
			quote = 0
		case quote == 0 && (c == '"' || c == '\''):
			quote = c
		case quote == 0 && c == target:
			return i
		}
	}
	return -1
}

func balanced(s string) bool {
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '"' && c == '\\':
			i++
		case quote != 0 && c == quote:
			quote = 0
		case quote == 0 && (c == '"' || c == '\''):
			quote = c
		case quote == 0 && (c == '[' || c == '{'):
			depth++
		case quote == 0 && (c == ']' || c == '}'):
			depth--
		}
	}
	return depth <= 0
}

// splitKeys splits a dotted key such as mcp_servers."splunk-mcp".env.
func splitKeys(s string) ([]string, error) {
	var keys []string
	for {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, errors.New("empty key")
		}
		var key string
		if s[0] == '"' || s[0] == '\'' {
			end, value, err := readString(s)
			if err != nil {
				return nil, err
			}
			key, s = value, s[end:]
		} else {
			end := strings.IndexByte(s, '.')
			if end < 0 {
				end = len(s)
			}
			key, s = strings.TrimSpace(s[:end]), s[end:]
		}
		keys = append(keys, key)
		s = strings.TrimSpace(s)
		if s == "" {
			return keys, nil
		}
		if s[0] != '.' {
			return nil, errors.New("malformed key")
		}
		s = s[1:]
	}
}

// readString reads one quoted string at the start of s and returns its length.
func readString(s string) (int, string, error) {
	if s[0] == '\'' {
		end := strings.IndexByte(s[1:], '\'')
		if end < 0 {
			return 0, "", errors.New("unterminated string")
		}
		return end + 2, s[1 : end+1], nil
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			return i + 1, b.String(), nil
		}
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		if i+1 == len(s) {
			break
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '"', '\\':
			b.WriteByte(s[i])
		case 'u':
			if i+4 >= len(s) {
				return 0, "", errors.New("malformed escape")
			}
			r, err := strconv.ParseUint(s[i+1:i+5], 16, 32)
			if err != nil {
				return 0, "", errors.New("malformed escape")
			}
			b.WriteRune(rune(r))
			i += 4
		default:
			return 0, "", errors.New("unsupported escape")
		}
	}
	return 0, "", errors.New("unterminated string")
}

func parseValue(s string) (any, error) {
	switch {
	case strings.HasPrefix(s, `"""`), strings.HasPrefix(s, `'''`):
		return rawValue(s), nil
	case strings.HasPrefix(s, `"`), strings.HasPrefix(s, `'`):
		end, value, err := readString(s)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(s[end:]) != "" {
			return nil, errors.New("unexpected text after string")
		}
		return value, nil
	case strings.HasPrefix(s, "["):
		return parseList(s[1:], ']', func(item string) (string, string, error) {
			value, err := parseValue(item)
			if str, ok := value.(string); ok && err == nil {
				return "", str, nil
			}
			return "", "", errors.New("not a string")
		})
	case strings.HasPrefix(s, "{"):
		pairs, err := parseList(s[1:], '}', func(item string) (string, string, error) {
			eq := indexOutside(item, '=')
			if eq < 0 {
				return "", "", errors.New("expected key = value")
			}
			keys, err := splitKeys(item[:eq])
			if err != nil || len(keys) != 1 {
				return "", "", errors.New("unsupported key")
			}
			value, err := parseValue(strings.TrimSpace(item[eq+1:]))
			if str, ok := value.(string); ok && err == nil {
				return keys[0], str, nil
			}
			return "", "", errors.New("not a string")
		})
		if err != nil {
			return rawValue(s), nil
		}
		table := map[string]string{}
		for _, p := range pairs.([][2]string) {
			table[p[0]] = p[1]
		}
		return table, nil
	default:
		return rawValue(s), nil
	}
}

// parseList splits the items of an array or inline table up to its closing
// bracket. An array holding anything but strings is kept raw.
func parseList(s string, closing byte, item func(string) (string, string, error)) (any, error) {
	var strs []string
	var pairs [][2]string
	for {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, errors.New("unterminated list")
		}
		if s[0] == closing {
			if closing == '}' {
				return pairs, nil
			}
			return strs, nil
		}
		end := indexOutside(s, ',')
		if stop := indexOutside(s, closing); end < 0 || (stop >= 0 && stop < end) {
			end = stop
		}
		if end < 0 {
			return nil, errors.New("unterminated list")
		}
		k, v, err := item(strings.TrimSpace(s[:end]))
		if err != nil {
			if closing == ']' {
				return rawValue("[" + s), nil
			}
			return nil, err
		}
		if closing == '}' {
			pairs = append(pairs, [2]string{k, v})
		} else {
			strs = append(strs, v)
		}
		s = s[end:]
		if s[0] == ',' {
			s = s[1:]
		}
	}
}
