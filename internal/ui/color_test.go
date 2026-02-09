package ui

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// TestMain disables colors globally for all tests to prevent test pollution
func TestMain(m *testing.M) {
	SetEnabled(false)
	os.Exit(m.Run())
}

func TestColorFunctions_Disabled(t *testing.T) {
	SetEnabled(false)

	tests := []struct {
		name     string
		fn       func(string) string
		input    string
		expected string
	}{
		{"Bold", Bold, "test", "test"},
		{"Dim", Dim, "test", "test"},
		{"Cyan", Cyan, "test", "test"},
		{"Yellow", Yellow, "test", "test"},
		{"Red", Red, "test", "test"},
		{"Green", Green, "test", "test"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_disabled", func(t *testing.T) {
			result := tt.fn(tt.input)
			if result != tt.expected {
				t.Errorf("%s(%q) = %q, want %q", tt.name, tt.input, result, tt.expected)
			}
		})
	}
}

func TestColorFunctions_Enabled(t *testing.T) {
	SetEnabled(true)
	defer SetEnabled(false)

	tests := []struct {
		name     string
		fn       func(string) string
		input    string
		expected string
	}{
		{"Bold", Bold, "test", "\033[1mtest\033[0m"},
		{"Dim", Dim, "test", "\033[2mtest\033[0m"},
		{"Cyan", Cyan, "test", "\033[36mtest\033[0m"},
		{"Yellow", Yellow, "test", "\033[33mtest\033[0m"},
		{"Red", Red, "test", "\033[31mtest\033[0m"},
		{"Green", Green, "test", "\033[32mtest\033[0m"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_enabled", func(t *testing.T) {
			result := tt.fn(tt.input)
			if result != tt.expected {
				t.Errorf("%s(%q) = %q, want %q", tt.name, tt.input, result, tt.expected)
			}
		})
	}
}

func TestEnabled(t *testing.T) {
	// Test initial state
	SetEnabled(false)
	if Enabled() {
		t.Error("Enabled() = true, want false")
	}

	// Test enabled state
	SetEnabled(true)
	if !Enabled() {
		t.Error("Enabled() = false, want true")
	}

	// Reset
	SetEnabled(false)
}

func TestShouldEnableColor_FlagPrecedence(t *testing.T) {
	// Create a mock TTY (we can't actually test with os.Stdout in tests)
	buf := &bytes.Buffer{}

	// Flag should take precedence over everything
	result := shouldEnableColor(buf, true)
	if result {
		t.Error("shouldEnableColor with noColorFlag=true returned true, want false")
	}
}

func TestShouldEnableColor_NOCOLOREnv(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	buf := &bytes.Buffer{}

	// NO_COLOR env should disable colors
	result := shouldEnableColor(buf, false)
	if result {
		t.Error("shouldEnableColor with NO_COLOR env returned true, want false")
	}
}

func TestShouldEnableColor_NOCOLOREmpty(t *testing.T) {
	// NO_COLOR with empty value should still disable colors (per spec)
	t.Setenv("NO_COLOR", "")

	buf := &bytes.Buffer{}

	result := shouldEnableColor(buf, false)
	if result {
		t.Error("shouldEnableColor with NO_COLOR='' env returned true, want false")
	}
}

func TestShouldEnableColor_NonTTY(t *testing.T) {
	// bytes.Buffer is not a TTY
	buf := &bytes.Buffer{}

	result := shouldEnableColor(buf, false)
	if result {
		t.Error("shouldEnableColor with bytes.Buffer returned true, want false")
	}
}

func TestShouldEnableColor_PriorityChain(t *testing.T) {
	tests := []struct {
		name        string
		noColorFlag bool
		setNOCOLOR  bool
		writer      io.Writer
		expected    bool
	}{
		{
			name:        "flag_overrides_all",
			noColorFlag: true,
			setNOCOLOR:  false,
			writer:      os.Stdout, // Even with potential TTY, flag should disable
			expected:    false,
		},
		{
			name:        "NO_COLOR_overrides_TTY",
			noColorFlag: false,
			setNOCOLOR:  true,
			writer:      os.Stdout,
			expected:    false,
		},
		{
			name:        "non_TTY_disables",
			noColorFlag: false,
			setNOCOLOR:  false,
			writer:      &bytes.Buffer{},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setNOCOLOR {
				t.Setenv("NO_COLOR", "1")
			}

			result := shouldEnableColor(tt.writer, tt.noColorFlag)
			if result != tt.expected {
				t.Errorf("shouldEnableColor() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestInitialize(t *testing.T) {
	// Test that Initialize sets the global state correctly
	buf := &bytes.Buffer{}

	// Initialize with colors disabled
	Initialize(buf, true)
	if Enabled() {
		t.Error("After Initialize(buf, true), Enabled() = true, want false")
	}

	// Initialize with colors potentially enabled (will be false for bytes.Buffer)
	Initialize(buf, false)
	if Enabled() {
		t.Error("After Initialize(bytes.Buffer, false), Enabled() = true, want false")
	}

	// Reset
	SetEnabled(false)
}

func TestColorFunctions_EmptyString(t *testing.T) {
	SetEnabled(true)
	defer SetEnabled(false)

	// Test that color functions handle empty strings correctly
	if Bold("") != "\033[1m\033[0m" {
		t.Error("Bold(\"\") should return ANSI codes even for empty string")
	}
}

func TestColorFunctions_MultilineString(t *testing.T) {
	SetEnabled(true)
	defer SetEnabled(false)

	input := "line1\nline2\nline3"
	expected := "\033[36mline1\nline2\nline3\033[0m"

	result := Cyan(input)
	if result != expected {
		t.Errorf("Cyan(multiline) = %q, want %q", result, expected)
	}
}
