package api

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	// MaxArgLength is the maximum length for a single argument
	MaxArgLength = 4096

	// MaxTotalArgs is the maximum number of arguments
	MaxTotalArgs = 100
)

// Dangerous shell metacharacters that should not appear in arguments
var dangerousChars = []string{
	";", "|", "&", "$", "`", "<", ">", "(", ")", "\n", "\r",
}

// ValidateCommand validates that a command is allowed
func ValidateCommand(command string) error {
	if command == "" {
		return fmt.Errorf("command cannot be empty")
	}

	// Check for dangerous characters
	for _, char := range dangerousChars {
		if strings.Contains(command, char) {
			return fmt.Errorf("command contains dangerous character: %s", char)
		}
	}

	return nil
}

// ValidateArgs validates command arguments for security
func ValidateArgs(args []string) error {
	if len(args) > MaxTotalArgs {
		return fmt.Errorf("too many arguments: %d (max: %d)", len(args), MaxTotalArgs)
	}

	for i, arg := range args {
		// Check argument length
		if len(arg) > MaxArgLength {
			return fmt.Errorf("argument %d exceeds maximum length: %d > %d", i, len(arg), MaxArgLength)
		}

		// Check for dangerous characters in arguments
		for _, char := range dangerousChars {
			if strings.Contains(arg, char) {
				return fmt.Errorf("argument %d contains dangerous character: %s", i, char)
			}
		}

		// Check for path traversal attempts
		if strings.Contains(arg, "..") {
			// Allow .. in legitimate paths, but warn if suspicious
			if matched, _ := regexp.MatchString(`^-.*\.\.`, arg); matched {
				return fmt.Errorf("argument %d looks like path traversal attempt", i)
			}
		}
	}

	return nil
}

// SanitizeOutput removes ANSI escape codes and control characters from output
func SanitizeOutput(output string) string {
	// Remove ANSI escape codes
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	cleaned := ansiRegex.ReplaceAllString(output, "")

	// Remove other control characters except newlines and tabs
	controlRegex := regexp.MustCompile(`[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]`)
	cleaned = controlRegex.ReplaceAllString(cleaned, "")

	return cleaned
}

// IsDestructiveCommand checks if a command is potentially destructive
func IsDestructiveCommand(command string, args []string) bool {
	destructiveSubcommands := map[string]bool{
		"delete": true,
		"purge":  true,
		"remove": true,
	}

	// Check if any argument is a destructive subcommand
	for _, arg := range args {
		if destructiveSubcommands[arg] {
			return true
		}
	}

	return false
}
