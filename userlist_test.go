package main

import (
	"testing"
)

func TestShortName(t *testing.T) {
	var tests = []struct {
		fqdn           string
		defaultDomain  string
		expectedResult string
	}{
		{"foo.testdomain.com", "fakedomain.com", "foo.testdomain.com"},
		{"foo.testdomain.com", "testdomain.com", "foo"},
		{"foo", "fakedomain.com", "foo"},
		{"foo..testdomain.com", "testdomain.com", "foo"},
		{"foo..testdomain.com", "fakedomain.com", "foo.testdomain.com"},
	}

	for _, tt := range tests {
		hostname := shortName(tt.fqdn, tt.defaultDomain)
		if hostname != tt.expectedResult {
			t.Errorf("Unexpected shortname: Wanted=%s, Got=%s", tt.expectedResult, hostname)
		}
	}
}
