package playbook

import "testing"

func TestSplitWindowsFactSections(t *testing.T) {
	input := "=== WINGET ===\nPRESENT\nok\n=== CHOCO ===\nMISSING\n=== EXEC_POLICY ===\nRestricted\n"

	sections := splitWindowsFactSections(input)

	if got := sections["WINGET"]; got != "PRESENT\nok\n" {
		t.Fatalf("WINGET section = %q, want %q", got, "PRESENT\nok\n")
	}
	if got := sections["CHOCO"]; got != "MISSING\n" {
		t.Fatalf("CHOCO section = %q, want %q", got, "MISSING\n")
	}
	if got := sections["EXEC_POLICY"]; got != "Restricted\n\n" {
		t.Fatalf("EXEC_POLICY section = %q, want %q", got, "Restricted\n\n")
	}
	if _, ok := sections["SCOOP"]; ok {
		t.Fatal("unexpected SCOOP section when none was present in input")
	}
}
