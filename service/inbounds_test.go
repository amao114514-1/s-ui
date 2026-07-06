package service

import "testing"

func TestParseClientIdsRejectsNonNumericInput(t *testing.T) {
	if _, err := parseClientIds("1,2) OR 1=1 --"); err == nil {
		t.Fatal("expected non-numeric initUsers input to be rejected")
	}
}

func TestParseClientIdsAcceptsNumericInput(t *testing.T) {
	ids, err := parseClientIds("1, 2,3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 3 || ids[0] != 1 || ids[1] != 2 || ids[2] != 3 {
		t.Fatalf("unexpected ids: %#v", ids)
	}
}
