package api

import (
	"fmt"
	"regexp"
	"strings"
)

// Parser parses Fastly CLI help output
type Parser struct {
	executor *Executor
}

// NewParser creates a new help parser
func NewParser(executor *Executor) *Parser {
	return &Parser{
		executor: executor,
	}
}

// ParseHelp parses the help output for a command
func (p *Parser) ParseHelp(args []string) (*Command, error) {
	result := p.executor.Execute(args, 10)
	if result.Error != nil && result.ExitCode != 0 {
		return nil, fmt.Errorf("failed to get help: %w", result.Error)
	}

	// Fastly CLI outputs help to stderr
	output := result.Stderr
	if output == "" {
		output = result.Stdout
	}

	cmd := &Command{
		Flags:       []Flag{},
		Subcommands: []*Command{},
	}

	// Extract command name from args
	if len(args) > 0 && args[len(args)-1] == "--help" {
		if len(args) > 1 {
			cmd.Name = args[len(args)-2]
		} else {
			cmd.Name = "fastly"
		}
	}

	// Parse the output
	lines := strings.Split(output, "\n")

	// State machine for parsing
	inCommands := false
	inFlags := false
	inUsage := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check section headers (case insensitive for flexibility)
		trimmedUpper := strings.ToUpper(trimmed)

		if strings.HasPrefix(trimmedUpper, "USAGE") {
			inUsage = true
			inCommands = false
			inFlags = false
			continue
		}

		if trimmedUpper == "COMMANDS" || strings.HasPrefix(trimmedUpper, "AVAILABLE COMMANDS") {
			inCommands = true
			inFlags = false
			inUsage = false
			continue
		}

		if trimmedUpper == "FLAGS" || trimmedUpper == "OPTIONS" ||
			strings.HasPrefix(trimmedUpper, "GLOBAL FLAGS") ||
			strings.HasPrefix(trimmedUpper, "COMMAND FLAGS") {
			inFlags = true
			inCommands = false
			inUsage = false
			continue
		}

		// Stop parsing at common section boundaries
		if strings.HasPrefix(trimmedUpper, "EXAMPLES") || strings.HasPrefix(trimmedUpper, "SEE ALSO") ||
			strings.HasPrefix(trimmed, "Learn more:") || strings.HasPrefix(trimmed, "Use \"") ||
			strings.HasPrefix(trimmed, "https://") {
			inCommands = false
			inFlags = false
			inUsage = false
			continue
		}

		// Parse description (first non-empty line before sections)
		if !inCommands && !inFlags && !inUsage && cmd.Description == "" && trimmed != "" {
			cmd.Description = trimmed
		}

		// Parse commands
		if inCommands && trimmed != "" {
			if subcmd := p.parseCommandLine(trimmed); subcmd != nil {
				cmd.Subcommands = append(cmd.Subcommands, subcmd)
			}
		}

		// Parse flags
		if inFlags && trimmed != "" {
			if flag := p.parseFlagLine(trimmed); flag != nil {
				cmd.Flags = append(cmd.Flags, *flag)
			}
		}
	}

	return cmd, nil
}

// parseCommandLine parses a line from the COMMANDS section
func (p *Parser) parseCommandLine(line string) *Command {
	// Fastly CLI format: "  command-name    Description here"
	// Commands are indented with 2 spaces

	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil
	}

	// Split on whitespace
	parts := strings.Fields(line)
	if len(parts) < 1 {
		return nil
	}

	name := parts[0]
	// Remove trailing comma if present
	name = strings.TrimSuffix(name, ",")

	// Skip special entries
	if name == "help" || name == "h" {
		return nil
	}

	description := ""
	if len(parts) > 1 {
		// Description starts after the command name
		description = strings.TrimSpace(strings.TrimPrefix(trimmed, name))
	}

	return &Command{
		Name:        name,
		Description: description,
		Flags:       []Flag{},
		Subcommands: []*Command{},
	}
}

// parseFlagLine parses a line from the FLAGS section
func (p *Parser) parseFlagLine(line string) *Flag {
	// Common formats:
	// "  -f, --flag string    Description here (default: value)"
	// "  --flag               Description here"
	// "      --long-flag      Description here"

	// Must start with whitespace and contain a dash
	if (!strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t")) || !strings.Contains(line, "-") {
		return nil
	}

	flag := &Flag{
		ValueType: "bool", // Default to bool
	}

	// Extract flags and description using regex
	// Pattern: optional short flag, long flag, optional type, description
	flagPattern := regexp.MustCompile(`^\s*(?:-([a-zA-Z]),?\s*)?--([a-z][a-z0-9-]*)\s*(?:(string|int|value|path|duration|ADDR|HOST|URL|PORT))?\s*(.*)$`)
	matches := flagPattern.FindStringSubmatch(line)

	if matches == nil {
		return nil
	}

	if matches[1] != "" {
		flag.ShortName = matches[1]
	}
	flag.Name = matches[2]

	if matches[3] != "" {
		valueType := strings.ToLower(matches[3])
		switch valueType {
		case "string", "path", "addr", "host", "url":
			flag.ValueType = "string"
		case "int", "port":
			flag.ValueType = "int"
		case "duration":
			flag.ValueType = "string"
		default:
			flag.ValueType = "string"
		}
	}

	description := strings.TrimSpace(matches[4])

	// Check for (required) marker
	if strings.Contains(description, "(required)") || strings.Contains(description, "[required]") {
		flag.Required = true
		description = strings.ReplaceAll(description, "(required)", "")
		description = strings.ReplaceAll(description, "[required]", "")
		description = strings.TrimSpace(description)
	}

	// Extract default value
	defaultPattern := regexp.MustCompile(`\(default:?\s*([^)]+)\)`)
	if defaultMatch := defaultPattern.FindStringSubmatch(description); defaultMatch != nil {
		flag.DefaultVal = strings.TrimSpace(defaultMatch[1])
		description = defaultPattern.ReplaceAllString(description, "")
		description = strings.TrimSpace(description)
	}

	flag.Description = description

	return flag
}
