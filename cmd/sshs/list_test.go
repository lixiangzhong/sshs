package main

import "testing"

func Test_authMethodsShowsPasswordFromKeyringFallback(t *testing.T) {
	mock := &mockKeyring{data: map[string]string{"sshs/default-password": "keyring-default-pass"}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	c := Config{Name: "web", Host: "10.0.0.1"}

	auth := authMethods(c)
	if len(auth) != 1 || auth[0] != "password" {
		t.Fatalf("authMethods() = %v, want [password] with keyring default fallback", auth)
	}
}

func Test_authMethodsNoPasswordWithoutKeyringDefault(t *testing.T) {
	mock := &mockKeyring{data: make(map[string]string)}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	c := Config{Name: "web", Host: "10.0.0.1", KeyPath: "~/.ssh/id_rsa"}

	auth := authMethods(c)
	if len(auth) != 1 || auth[0] != "key" {
		t.Fatalf("authMethods() = %v, want [key] without keyring default", auth)
	}
}
