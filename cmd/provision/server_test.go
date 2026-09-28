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
		{nil, "10.42.0.2/32"},
		{[]string{"10.42.0.2/32", "10.42.0.3/32", "10.42.0.253/32", "10.42.0.254/32"}, "10.42.0.4/32"},
		{[]string{"10.42.0.0/25"}, "10.42.0.128/32"},
		{[]string{"10.42.0.0/28", "10.42.0.16/30", "10.42.0.20/32"}, "10.42.0.21/32"},
		{[]string{"10.42.0.0/28", "10.42.0.16/30", "10.42.0.20/32", "10.42.0.21/32"}, "10.42.0.22/32"},
	} {
		got, err := phoneAddress("10.42.0.1/32", tc.used)
		if err != nil || got != tc.want {
			t.Fatalf("address: %s, %v", got, err)
		}
	}
	for _, used := range [][]string{{"10.42.0.0/24"}, {"invalid"}} {
		if _, err := phoneAddress("10.42.0.1/32", used); err == nil {
			t.Fatal("invalid/exhausted reservation accepted")
		}
	}
	if got, err := phoneAddress("172.20.4.1/32", nil); err != nil || got != "172.20.4.2/32" {
		t.Fatalf("alternate private pool: %q, %v", got, err)
	}
	for _, route := range []string{"0.0.0.0/0", "203.0.113.1/32", "invalid"} {
		if _, err := phoneAddress(route, nil); err == nil {
			t.Fatal("invalid first service route accepted")
		}
	}
}

func TestServerEnrollmentRejectsPublicOutputDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := serverNew([]string{"--config", dir, "--out", dir, "--name", "phone", "--endpoint", "192.0.2.1:51824", "--routes", "10.42.0.1/32"}); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatal("public output directory accepted")
	}
}
