package api

import (
	"sync"
)

// Flag represents a command-line flag
type Flag struct {
	Name        string `json:"name"`
	ShortName   string `json:"short_name,omitempty"`
	ValueType   string `json:"value_type"` // "string", "bool", "int"
	Required    bool   `json:"required"`
	Description string `json:"description"`
	DefaultVal  string `json:"default,omitempty"`
}

// Command represents a CLI command with its metadata
type Command struct {
	Name        string     `json:"name"`
	Path        string     `json:"path"` // e.g., "service.list"
	Description string     `json:"description"`
	Flags       []Flag     `json:"flags,omitempty"`
	Subcommands []*Command `json:"subcommands,omitempty"`
}

// CommandRegistry holds the complete command catalog
type CommandRegistry struct {
	mu       sync.RWMutex
	commands map[string]*Command
	root     *Command
	executor *Executor
}

// NewCommandRegistry creates a new command registry
func NewCommandRegistry(executor *Executor) *CommandRegistry {
	return &CommandRegistry{
		commands: make(map[string]*Command),
		executor: executor,
		root: &Command{
			Name:        "fastly",
			Path:        "",
			Description: "Fastly CLI",
			Subcommands: []*Command{},
		},
	}
}

// GetCommand retrieves a command by its path (e.g., "service.list")
func (r *CommandRegistry) GetCommand(path string) *Command {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.commands[path]
}

// GetAllCommands returns all registered commands
func (r *CommandRegistry) GetAllCommands() map[string]*Command {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Create a copy to avoid race conditions
	result := make(map[string]*Command, len(r.commands))
	for k, v := range r.commands {
		result[k] = v
	}
	return result
}

// GetRoot returns the root command
func (r *CommandRegistry) GetRoot() *Command {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.root
}

// AddCommand adds a command to the registry
func (r *CommandRegistry) addCommand(cmd *Command) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands[cmd.Path] = cmd
}

// Discover builds a static command registry for API-based operations
func (r *CommandRegistry) Discover() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.root = &Command{
		Name:        "fastly",
		Path:        "",
		Description: "Fastly API",
		Subcommands: []*Command{},
	}

	whoamiCmd := &Command{
		Name:        "whoami",
		Path:        "whoami",
		Description: "Get current user information",
		Flags:       []Flag{},
	}
	r.commands["whoami"] = whoamiCmd
	r.root.Subcommands = append(r.root.Subcommands, whoamiCmd)

	serviceCmd := &Command{
		Name:        "service",
		Path:        "service",
		Description: "Service operations",
		Subcommands: []*Command{
			{
				Name:        "list",
				Path:        "service.list",
				Description: "List all services",
				Flags: []Flag{
					{Name: "customer_id", ValueType: "string", Description: "Filter by customer ID"},
				},
			},
			{
				Name:        "describe",
				Path:        "service.describe",
				Description: "Get service details",
				Flags: []Flag{
					{Name: "service_id", ValueType: "string", Required: true, Description: "Service ID"},
				},
			},
		},
	}
	r.commands["service"] = serviceCmd
	r.commands["service.list"] = serviceCmd.Subcommands[0]
	r.commands["service.describe"] = serviceCmd.Subcommands[1]
	r.root.Subcommands = append(r.root.Subcommands, serviceCmd)

	versionCmd := &Command{
		Name:        "version",
		Path:        "version",
		Description: "Version operations",
		Subcommands: []*Command{
			{
				Name:        "list",
				Path:        "version.list",
				Description: "List service versions",
				Flags: []Flag{
					{Name: "service_id", ValueType: "string", Required: true, Description: "Service ID"},
				},
			},
		},
	}
	r.commands["version"] = versionCmd
	r.commands["version.list"] = versionCmd.Subcommands[0]
	r.root.Subcommands = append(r.root.Subcommands, versionCmd)

	return nil
}

// discoverSubcommands recursively discovers subcommands
func (r *CommandRegistry) discoverSubcommands(cmd *Command, path []string) error {
	parser := NewParser(r.executor)

	// Build the command path string
	cmdPath := ""
	for i, p := range path {
		if i > 0 {
			cmdPath += "."
		}
		cmdPath += p
	}
	cmd.Path = cmdPath
	r.addCommand(cmd)

	// Try to get detailed help for this command
	helpArgs := append(path, "--help")
	detailedCmd, err := parser.ParseHelp(helpArgs)
	if err != nil {
		// If we can't parse help, keep what we have
		return nil
	}

	// Update flags from detailed help
	cmd.Flags = detailedCmd.Flags
	cmd.Description = detailedCmd.Description

	// If there are subcommands, discover them recursively
	if len(detailedCmd.Subcommands) > 0 {
		cmd.Subcommands = detailedCmd.Subcommands
		for _, subcmd := range detailedCmd.Subcommands {
			subPath := append(path, subcmd.Name)
			if err := r.discoverSubcommands(subcmd, subPath); err != nil {
				continue
			}
		}
	}

	return nil
}

// ListCommands returns a flat list of all command paths
func (r *CommandRegistry) ListCommands() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	paths := make([]string, 0, len(r.commands))
	for path := range r.commands {
		if path != "" { // Skip root
			paths = append(paths, path)
		}
	}
	return paths
}
