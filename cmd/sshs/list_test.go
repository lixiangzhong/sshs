package main

import "testing"

func Test_authMethodsShowsPasswordFromEnvFallback(t *testing.T) {
	t.Setenv("SSHS_PASSWORD", "env-pass")
	c := Config{Name: "web", Host: "10.0.0.1"}

	auth := authMethods(c)
	if len(auth) != 1 || auth[0] != "password" {
		t.Fatalf("authMethods() = %v, want [password] with env fallback", auth)
	}
}

func Test_authMethodsNoPasswordWithoutEnv(t *testing.T) {
	t.Setenv("SSHS_PASSWORD", "")
	c := Config{Name: "web", Host: "10.0.0.1", KeyPath: "~/.ssh/id_rsa"}

	auth := authMethods(c)
	if len(auth) != 1 || auth[0] != "key" {
		t.Fatalf("authMethods() = %v, want [key] without env", auth)
	}
}
