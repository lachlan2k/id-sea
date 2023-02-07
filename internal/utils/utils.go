package utils

import (
	"strings"

	"github.com/lachlan2k/id-sea/internal/config"
)

// Allows you to specify *.google.com or *@gmail.com to a suffix match.
// Effectively, if the first character is a *, it just checks to see if its a suffix
// If it's a string literal, it does a literal match
func MatchesWithWildcard(matcher string, valueToEvaluate string) bool {
	if matcher[0] == '*' {
		return strings.HasSuffix(valueToEvaluate, matcher[1:])
	}
	return valueToEvaluate == matcher
}

// Evalute a slice against a single string matches
// For example, check ["google.com", "foo.example.com", "bing.com"] has a match for "*.example.com"
func TestSliceAgainstStringMatcher(matcher string, in []string) bool {
	for _, x := range in {
		if MatchesWithWildcard(x, matcher) {
			return true
		}
	}

	return false
}

// Evalute a single string against possible wildcards in slice
// For example, check "foo.example.com" against ["google.com", "*.example.com", "bing.com"]
func TestStringAgainstSliceMatchers(matchers []string, in string) bool {
	for _, matcher := range matchers {
		if MatchesWithWildcard(matcher, in) {
			return true
		}
	}

	return false
}

func MergeSlicesUniq(inputs ...[]string) []string {
	unique := map[string]bool{}
	for _, input := range inputs {
		for _, value := range input {
			unique[value] = true
		}
	}

	result := make([]string, 0, len(unique))
	for entry := range unique {
		result = append(result, entry)
	}

	return result
}

// Merge session roles and mapped roles
func GetAllRolesForUser(conf *config.Config, email string, sessionRoles []string) []string {
	mappedRoles, ok := conf.AccessControl.RoleMapping[email]

	if !ok {
		return sessionRoles
	}

	return MergeSlicesUniq(sessionRoles, mappedRoles)
}
