package ui

import (
	"io"
	"os"

	"golang.org/x/term"
)

// colorEnabled tracks whether color output is enabled globally
var colorEnabled = false

// Initialize sets up color support based on TTY detection and user preferences.
// Priority: --no-color flag > NO_COLOR env var > TTY detection
func Initialize(w io.Writer, noColorFlag bool) {
	colorEnabled = shouldEnableColor(w, noColorFlag)
}

// shouldEnableColor determines if color output should be enabled based on the priority chain
func shouldEnableColor(w io.Writer, noColorFlag bool) bool {
	// 1. Flag takes precedence
	if noColorFlag {
		return false
	}

	// 2. NO_COLOR environment variable
	if _, exists := os.LookupEnv("NO_COLOR"); exists {
		return false
	}

	// 3. Check if output is a TTY
	if f, ok := w.(*os.File); ok {
		return term.IsTerminal(int(f.Fd()))
	}

	return false
}

// Enabled returns whether colors are currently enabled
func Enabled() bool {
	return colorEnabled
}

// SetEnabled allows tests to override the global state
func SetEnabled(enabled bool) {
	colorEnabled = enabled
}

// Bold returns the string wrapped in ANSI bold codes if colors are enabled
func Bold(s string) string {
	if !colorEnabled {
		return s
	}
	return "\033[1m" + s + "\033[0m"
}

// Dim returns the string wrapped in ANSI dim codes if colors are enabled
func Dim(s string) string {
	if !colorEnabled {
		return s
	}
	return "\033[2m" + s + "\033[0m"
}

// Cyan returns the string wrapped in ANSI cyan codes if colors are enabled
func Cyan(s string) string {
	if !colorEnabled {
		return s
	}
	return "\033[36m" + s + "\033[0m"
}

// Yellow returns the string wrapped in ANSI yellow codes if colors are enabled
func Yellow(s string) string {
	if !colorEnabled {
		return s
	}
	return "\033[33m" + s + "\033[0m"
}

// Red returns the string wrapped in ANSI red codes if colors are enabled
func Red(s string) string {
	if !colorEnabled {
		return s
	}
	return "\033[31m" + s + "\033[0m"
}

// Green returns the string wrapped in ANSI green codes if colors are enabled
func Green(s string) string {
	if !colorEnabled {
		return s
	}
	return "\033[32m" + s + "\033[0m"
}
