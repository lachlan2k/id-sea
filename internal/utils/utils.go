package utils

import "strings"

// Allows you to specify *.google.com or *@gmail.com to a suffix match.
// Effectively, if the first character is a *, it just checks to see if its a suffix
// If it's a string literal, it does a literal match
func MatchesWithWildcard(valueToEvaluate string, matcher string) bool {
	if matcher[0] == '*' {
		return strings.HasSuffix(valueToEvaluate, matcher[1:])
	}
	return valueToEvaluate == matcher
}

func SliceHasMatch(in []string, matcher string, wildcardSupport bool) bool {
	for _, x := range in {
		if (wildcardSupport && MatchesWithWildcard(x, matcher)) || x == matcher {
			return true
		}
	}

	return false
}
