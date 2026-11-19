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

// emptyTable reports whether value is an inline table with nothing in it.
func emptyTable(value string) bool {
	inner, ok := strings.CutPrefix(value, "{")
	inner, closed := strings.CutSuffix(inner, "}")
	return ok && closed && strings.TrimSpace(inner) == ""
}

// readTOML reads the subset of TOML that Codex's config uses: tables, keys,
// dotted too, strings, arrays of strings, and inline tables of strings and inline
// tables. Anything else is kept raw or skipped, never guessed at. Tables are keyed
// by their dotted path, joined with "\x00", and a dotted key sets a key of the
// table its path names, as one under that table's header would. An MCP server's
// key is an error but under its own table's header, and not dotted: an inline
// server would go unread, and the table keyward mcp prints in place of one would
// leave a dotted key out.
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
		if err != nil {
			return nil, fmt.Errorf("line %d: unsupported key", i+1)
		}
		table := current
		for _, k := range keys[:len(keys)-1] {
			table = strings.TrimPrefix(table+"\x00"+k, "\x00")
		}
		key := keys[len(keys)-1]
		path := strings.TrimPrefix(table+"\x00"+key, "\x00")
		value := strings.TrimSpace(line[eq+1:])
		// An empty table holds no server to leave unread.
		if strings.HasPrefix(path+"\x00", "mcp_servers\x00") && (len(keys) > 1 || !strings.HasPrefix(current, "mcp_servers\x00")) && !emptyTable(value) {
			return nil, fmt.Errorf("line %d: unsupported key", i+1)
		}
		// Multi-line arrays, inline tables and strings continue until they close.
		for ((strings.HasPrefix(value, "[") || strings.HasPrefix(value, "{")) && !balanced(value)) ||
			(strings.HasPrefix(value, `"""`) && strings.Count(value, `"""`) < 2) ||
			(strings.HasPrefix(value, `'''`) && strings.Count(value, `'''`) < 2) {
			i++
			if i == len(lines) {
				return nil, fmt.Errorf("unterminated value for %s", key)
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
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		if current != "\x01" {
			if tables[table] == nil {
				tables[table] = map[string]any{}
			}
			tables[table][key] = parsed
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
			r, err := strconv.ParseUint(s[i+1:i+5], 16, 16)
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
		return parseList(s[1:], ']', func(item string) (string, any, error) {
			value, err := parseValue(item)
			if str, ok := value.(string); ok && err == nil {
				return "", str, nil
			}
			return "", nil, errors.New("not a string")
		})
	case strings.HasPrefix(s, "{"):
		pairs, err := parseList(s[1:], '}', func(item string) (string, any, error) {
			eq := indexOutside(item, '=')
			if eq < 0 {
				return "", nil, errors.New("expected key = value")
			}
			keys, err := splitKeys(item[:eq])
			if err != nil || len(keys) != 1 {
				return "", nil, errors.New("unsupported key")
			}
			value, err := parseValue(strings.TrimSpace(item[eq+1:]))
			switch value.(type) {
			case string, map[string]string, map[string]any:
				return keys[0], value, err
			}
			return "", nil, errors.New("not a string or an inline table")
		})
		if err != nil {
			return rawValue(s), nil
		}
		// One of strings alone is read as an MCP server's env and headers are.
		table, strs := pairs.(map[string]any), map[string]string{}
		for k, v := range table {
			if str, ok := v.(string); ok {
				strs[k] = str
			}
		}
		if len(strs) < len(table) {
			return table, nil
		}
		return strs, nil
	default:
		return rawValue(s), nil
	}
}

// parseList splits the items of an array or inline table up to its closing
// bracket. An array holding anything but strings is kept raw.
func parseList(s string, closing byte, item func(string) (string, any, error)) (any, error) {
	var strs []string
	pairs := map[string]any{}
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
		end := itemEnd(s, closing)
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
			pairs[k] = v
		} else {
			strs = append(strs, v.(string))
		}
		s = s[end:]
		if s[0] == ',' {
			s = s[1:]
		}
	}
}

// itemEnd is where the first item of a list ends in s: at a comma or the list's
// closing bracket outside strings and the inline tables the item holds, or -1.
// An item that holds a list is no string or inline table, wherever it ends.
func itemEnd(s string, closing byte) int {
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case quote == '"' && c == '\\':
			i++
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '{':
			depth++
		case depth > 0 && c == '}':
			depth--
		case depth == 0 && (c == ',' || c == closing):
			return i
		}
	}
	return -1
}
