package repohealer

import "testing"

func TestDeb822RepairExecutionEnabled(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{
			name:  "Unset",
			value: "",
			want:  false,
		},
		{
			name:  "Whitespace",
			value: "  ",
			want:  false,
		},
		{
			name:  "False",
			value: "false",
			want:  false,
		},
		{
			name:  "One",
			value: "1",
			want:  false,
		},
		{
			name:  "Yes",
			value: "yes",
			want:  false,
		},
		{
			name:  "Exact true",
			value: "true",
			want:  true,
		},
		{
			name:  "Uppercase true",
			value: "TRUE",
			want:  true,
		},
		{
			name:  "Trimmed true",
			value: " true ",
			want:  true,
		},
		{
			name:  "Near match",
			value: "true!",
			want:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(deb822RepairExecutionEnabledEnv, test.value)

			if got := Deb822RepairExecutionEnabled(); got != test.want {
				t.Fatalf(
					"Deb822RepairExecutionEnabled() = %t, want %t for %q",
					got,
					test.want,
					test.value,
				)
			}
		})
	}
}
