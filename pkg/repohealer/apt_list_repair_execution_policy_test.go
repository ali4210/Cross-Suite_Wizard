package repohealer

import "testing"

func TestHashiCorpAPTListRepairExecutionEnabled(t *testing.T) {
	const environmentVariable = "CROSS_SUITE_HASHICORP_APT_LIST_REPAIR_ENABLED"

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "Unset", value: "", want: false},
		{name: "True", value: "true", want: true},
		{name: "Uppercase true", value: "TRUE", want: true},
		{name: "Mixed case true", value: "TrUe", want: true},
		{name: "Whitespace true", value: " true ", want: true},
		{name: "One is not enabled", value: "1", want: false},
		{name: "Yes is not enabled", value: "yes", want: false},
		{name: "False", value: "false", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(environmentVariable, test.value)

			if got := HashiCorpAPTListRepairExecutionEnabled(); got != test.want {
				t.Fatalf(
					"HashiCorpAPTListRepairExecutionEnabled() = %t, want %t for %q",
					got,
					test.want,
					test.value,
				)
			}
		})
	}
}
