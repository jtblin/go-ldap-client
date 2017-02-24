package ldap

import "testing"

func TestJoinDn(t *testing.T) {
	if joinDn("a") != "a" {
		t.Fatal("joinDn failed")
	}
	if joinDn("a", "b") != "a,b" {
		t.Fatal("joinDn failed")
	}
	if joinDn("", "b") != "b" {
		t.Fatal("joinDn failed")
	}
	if joinDn("a", "") != "a" {
		t.Fatal("joinDn failed")
	}
}
