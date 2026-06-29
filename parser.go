package main

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// EnvVar represents a parsed environment variable with its metadata from comments.
type EnvVar struct {
	Key          string
	DefaultValue string
	Type         string   // "int", "bool", "float", "string", "email", "url", "enum", or custom YAML types
	EnumVals     []string // values for enum type
	Optional     bool
	Deprecated   bool
	Comment      string

	// Range validation (int/float bounds)
	HasRange bool
	RangeMin float64
	RangeMax float64

	// Length validation (string char count bounds)
	HasLen bool
	LenMin int
	LenMax int

	// Regular expression patterns validation
	HasRegex     bool
	RegexPattern string
}

var (
	typeRegex  = regexp.MustCompile(`type:([a-zA-Z0-9_]+(?:\([^)]*\))?)`)
	rangeRegex = regexp.MustCompile(`range\(([^,]+),([^)]+)\)`)
	lenRegex   = regexp.MustCompile(`len\(([^,]+),([^)]+)\)`)
)

// ParseEnvFile reads an env file and returns a map of Key -> EnvVar.
func ParseEnvFile(filepath string) (map[string]*EnvVar, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return ParseEnvReader(file)
}

// ParseEnvReader parses from an io.Reader.
func ParseEnvReader(reader io.Reader) (map[string]*EnvVar, error) {
	result := make(map[string]*EnvVar)
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle export prefix
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimPrefix(line, "export ")
			line = strings.TrimSpace(line)
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) < 2 {
			continue // Invalid line, ignore
		}

		key := strings.TrimSpace(parts[0])
		rest := strings.TrimSpace(parts[1])

		value, comment := parseValueAndComment(rest)

		envVar := &EnvVar{
			Key:          key,
			DefaultValue: value,
		}

		if comment != "" {
			envVar.Comment = comment
			parseMetadata(comment, envVar)
		}

		result[key] = envVar
	}

	return result, scanner.Err()
}

// parseValueAndComment splits the right-hand side of a variable definition into value and comment.
// It respects quotes (both single and double) to prevent splitting on # inside quotes.
func parseValueAndComment(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}

	runes := []rune(s)
	length := len(runes)
	inQuote := false
	var quoteChar rune
	valEnd := -1
	commentStart := -1

	for i := 0; i < length; i++ {
		r := runes[i]
		if inQuote {
			if r == quoteChar {
				// Handle escaped quote (e.g. \")
				if i > 0 && runes[i-1] == '\\' {
					continue
				}
				inQuote = false
				valEnd = i + 1
			}
		} else {
			if r == '"' || r == '\'' {
				inQuote = true
				quoteChar = r
				if valEnd == -1 {
					// mark start of value
				}
			} else if r == '#' {
				commentStart = i
				if valEnd == -1 {
					valEnd = i
				}
				break
			}
		}
	}

	if valEnd == -1 {
		valEnd = length
	}

	valStr := string(runes[:valEnd])
	valStr = strings.TrimSpace(valStr)

	// Strip outer quotes if they exist around the entire value
	if len(valStr) >= 2 {
		first := valStr[0]
		last := valStr[len(valStr)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			valStr = valStr[1 : len(valStr)-1]
			// Unescape quotes inside
			if first == '"' {
				valStr = strings.ReplaceAll(valStr, `\"`, `"`)
			} else {
				valStr = strings.ReplaceAll(valStr, `\'`, `'`)
			}
		}
	}

	var commentStr string
	if commentStart != -1 {
		commentStr = string(runes[commentStart:])
	}

	return valStr, commentStr
}

// parseMetadata parses instructions from comments, like type:int, optional, deprecated.
func parseMetadata(comment string, ev *EnvVar) {
	lowerComment := strings.ToLower(comment)

	// Check optional status
	if containsToken(lowerComment, "optional") {
		ev.Optional = true
	}

	// Check deprecated status
	if containsToken(lowerComment, "deprecated") {
		ev.Deprecated = true
	}

	// Match type information
	matches := typeRegex.FindStringSubmatch(comment)
	if len(matches) > 1 {
		rawType := matches[1]
		if strings.HasPrefix(rawType, "enum(") && strings.HasSuffix(rawType, ")") {
			ev.Type = "enum"
			inner := rawType[5 : len(rawType)-1]
			vals := strings.Split(inner, ",")
			for i, v := range vals {
				vals[i] = strings.TrimSpace(v)
			}
			ev.EnumVals = vals
		} else {
			ev.Type = strings.ToLower(rawType)
		}
	}

	// Parse range(min,max)
	rangeMatches := rangeRegex.FindStringSubmatch(comment)
	if len(rangeMatches) > 2 {
		minVal, errMin := strconv.ParseFloat(strings.TrimSpace(rangeMatches[1]), 64)
		maxVal, errMax := strconv.ParseFloat(strings.TrimSpace(rangeMatches[2]), 64)
		if errMin == nil && errMax == nil {
			ev.HasRange = true
			ev.RangeMin = minVal
			ev.RangeMax = maxVal
		}
	}

	// Parse len(min,max)
	lenMatches := lenRegex.FindStringSubmatch(comment)
	if len(lenMatches) > 2 {
		minVal, errMin := strconv.Atoi(strings.TrimSpace(lenMatches[1]))
		maxVal, errMax := strconv.Atoi(strings.TrimSpace(lenMatches[2]))
		if errMin == nil && errMax == nil {
			ev.HasLen = true
			ev.LenMin = minVal
			ev.LenMax = maxVal
		}
	}

	// Parse regex(pattern) using parenthesis matching to support embedded groups
	if idx := strings.Index(comment, "regex("); idx != -1 {
		start := idx + 6
		depth := 1
		end := -1
		runes := []rune(comment[start:])
		for i, r := range runes {
			if r == '(' {
				depth++
			} else if r == ')' {
				depth--
				if depth == 0 {
					end = start + i
					break
				}
			}
		}
		if end != -1 {
			ev.HasRegex = true
			ev.RegexPattern = comment[start:end]
		}
	}
}

// containsToken checks if a target word exists as a separate token in the comment string.
func containsToken(s, target string) bool {
	// Look for target word bounded by non-alphanumeric characters
	idx := strings.Index(s, target)
	if idx == -1 {
		return false
	}
	// Check boundaries
	beforeOk := idx == 0 || !isAlphaNum(s[idx-1])
	afterOk := idx+len(target) == len(s) || !isAlphaNum(s[idx+len(target)])
	return beforeOk && afterOk
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}
