package main

import (
	"os"
	"strings"
	"testing"
)

func TestPhoneAllocationRespectsLiveAndPendingNetworks(t *testing.T) {
	for _, tc := range []struct {
		used []string
		want string
	}{
		{nil, "10.77.0.2/32"},
		{[]string{"10.77.0.2/32", "10.77.0.3/32", "10.77.0.253/32", "10.77.0.254/32"}, "10.77.0.4/32"},
		{[]string{"10.77.0.0/25"}, "10.77.0.128/32"},
		{[]string{"10.77.0.0/28", "10.77.0.16/30", "10.77.0.20/32"}, "10.77.0.22/32"},
		{[]string{"10.77.0.0/28", "10.77.0.16/30", "10.77.0.20/32", "10.77.0.22/32"}, "10.77.0.24/32"},
	} {
		got, err := phoneAddress(tc.used)
		if err != nil || got != tc.want {
			t.Fatalf("address: %s, %v", got, err)
		}
	}
	for _, used := range [][]string{{"10.77.0.0/24"}, {"invalid"}} {
		if _, err := phoneAddress(used); err == nil {
			t.Fatal("invalid/exhausted reservation accepted")
		}
	}
}

func TestServerEnrollmentRejectsPublicOutputDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := serverNew([]string{"--config", dir, "--out", dir, "--name", "phone", "--endpoint", "192.0.2.1:51824", "--routes", "10.77.0.1/32"}); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatal("public output directory accepted")
	}
}
