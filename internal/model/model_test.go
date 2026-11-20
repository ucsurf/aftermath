package model

import (
	"strings"
	"testing"
)

func TestFinalizeIdempotentAndRedacts(t *testing.T) {
	f := Finalize(Finding{
		Collector: "pkg",
		RuleID:    "pkg.token",
		Severity:  High,
		Title:     "token",
		Evidence:  "token=npm_DemoTokenValueShouldNeverPrint0001\nINJECTED",
		Key:       "npmrc",
	})
	if strings.Contains(f.Evidence, "npm_DemoTokenValueShouldNeverPrint0001") {
		t.Fatalf("evidence leaked: %q", f.Evidence)
	}
	if strings.Contains(f.Evidence, "\n") {
		t.Fatalf("evidence kept a newline: %q", f.Evidence)
	}
	again := Finalize(f)
	if again.Fingerprint != f.Fingerprint || again.Identity != f.Identity {
		t.Fatalf("fingerprint changed on second finalize")
	}
}

func TestParseSeverity(t *testing.T) {
	s, ok := ParseSeverity(" HIGH ")
	if !ok || s != High || s.Rank() != 3 {
		t.Fatalf("got %s %v", s, ok)
	}
	if _, ok := ParseSeverity("nope"); ok {
		t.Fatal("accepted unknown severity")
	}
}
