package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fastly/cli/api"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// CommandRegistry is a wrapper for api.CommandRegistry
type CommandRegistry = api.CommandRegistry

// NewCommandRegistry creates a new command registry
func NewCommandRegistry(executor *api.Executor) *CommandRegistry {
	return api.NewCommandRegistry(executor)
}

// registerTools registers all MCP tools with the server
func (s *FastlyMCPServer) registerTools(server *mcpserver.MCPServer) error {
	// Tool 1: execute_fastly_js
	executeTool := mcp.NewTool("execute_fastly_js",
		mcp.WithDescription("Execute arbitrary JavaScript code in a full sandboxed JavaScript environment with access to Fastly API functions. This is a complete JavaScript runtime that supports complex scripts with multiple function definitions, variables, control flow, and all standard JavaScript features. You can write multi-line scripts that define and call multiple functions in a single execution.\n\nIMPORTANT: All Fastly API functions are SYNCHRONOUS and return values immediately. Do NOT use 'await' or 'async' - they are not supported. Simply call functions directly: `const services = fastly.service.list();`"),
		mcp.WithString("code",
			mcp.Required(),
			mcp.Description("JavaScript code to execute (can be a full script with multiple functions and statements). Do NOT use async/await - all API functions are synchronous."),
		),
		mcp.WithNumber("timeout",
			mcp.Description("Execution timeout in seconds (default: 30)"),
		),
	)
	server.AddTool(executeTool, s.handleExecuteJS)

	// Tool 2: list_fastly_commands
	listTool := mcp.NewTool("list_fastly_commands",
		mcp.WithDescription("List all available Fastly JavaScript API functions organized by namespace"),
	)
	server.AddTool(listTool, s.handleListCommands)

	// Tool 3: get_command_help
	helpTool := mcp.NewTool("get_command_help",
		mcp.WithDescription("Get detailed help for a specific Fastly API function including parameters and usage examples"),
		mcp.WithString("command",
			mcp.Required(),
			mcp.Description("Function path (e.g., 'service.list', 'compute.deploy')"),
		),
	)
	server.AddTool(helpTool, s.handleGetCommandHelp)

	// Tool 4: get_fastly_types
	typesTool := mcp.NewTool("get_fastly_types",
		mcp.WithDescription("Get TypeScript type definitions for all Fastly API functions, showing parameter types and return types. This helps understand what arguments each function expects and what it returns. NOTE: All functions are synchronous - do not use await."),
	)
	server.AddTool(typesTool, s.handleGetTypes)

	return nil
}

// handleExecuteJS handles the execute_fastly_js tool
func (s *FastlyMCPServer) handleExecuteJS(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Get code argument
	code, err := request.RequireString("code")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error: code parameter is required: %v", err)), nil
	}

	// Log the JavaScript code being executed
	if s.config.Logger != nil {
		s.config.Logger.Printf("MCP: Executing JavaScript code from client:")
		// Log each line with indentation for readability
		for i, line := range strings.Split(code, "\n") {
			s.config.Logger.Printf("MCP:   %3d | %s", i+1, line)
		}
	}

	// Get timeout (optional, default 30)
	timeout := 30
	// Try to get timeout from arguments
	if request.Params.Arguments != nil {
		if args, ok := request.Params.Arguments.(map[string]interface{}); ok {
			if timeoutVal, ok := args["timeout"].(float64); ok && timeoutVal > 0 {
				timeout = int(timeoutVal)
			}
		}
	}

	// Create a fresh VM for this execution (clean environment)
	vm, err := s.CreateFreshVM()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error creating VM: %v", err)), nil
	}

	// Execute the code
	result := vm.Execute(code, timeout)

	// Log execution result
	if s.config.Logger != nil {
		if result.Error != nil {
			s.config.Logger.Printf("MCP: Execution failed with error: %v", result.Error)
		} else {
			s.config.Logger.Printf("MCP: Execution completed in %v", result.Duration)
		}
	}

	// Build response
	var response strings.Builder

	if result.Error != nil {
		response.WriteString(fmt.Sprintf("Error: %v\n", result.Error))
	}

	if len(result.Output) > 0 {
		response.WriteString("Console Output:\n")
		for _, line := range result.Output {
			response.WriteString(fmt.Sprintf("  %s\n", line))
		}
	}

	if result.Value != nil && result.Error == nil {
		response.WriteString(fmt.Sprintf("\nResult: %v\n", result.Value))

		// If result is JSON-serializable, include JSON
		if jsonBytes, err := json.MarshalIndent(result.Value, "", "  "); err == nil {
			response.WriteString(fmt.Sprintf("\nJSON:\n%s\n", string(jsonBytes)))
		}
	}

	response.WriteString(fmt.Sprintf("\nExecution time: %v\n", result.Duration))

	return mcp.NewToolResultText(response.String()), nil
}

// handleListCommands handles the list_fastly_commands tool
func (s *FastlyMCPServer) handleListCommands(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Get or create registry
	registry := s.getOrCreateRegistry()

	// Get all command paths
	paths := registry.ListCommands()

	// Build response
	var response strings.Builder
	response.WriteString(fmt.Sprintf("Available Fastly API Functions (%d total):\n\n", len(paths)))

	// Group by top-level command
	grouped := make(map[string][]string)
	for _, path := range paths {
		parts := strings.Split(path, ".")
		topLevel := parts[0]
		grouped[topLevel] = append(grouped[topLevel], path)
	}

	// Output grouped
	for topLevel, commands := range grouped {
		response.WriteString(fmt.Sprintf("%s (%d functions):\n", topLevel, len(commands)))
		for i, cmd := range commands {
			if i >= 5 {
				response.WriteString(fmt.Sprintf("  ... and %d more\n", len(commands)-5))
				break
			}
			response.WriteString(fmt.Sprintf("  - %s\n", cmd))
		}
		response.WriteString("\n")
	}

	response.WriteString("\nExample usage (all functions are synchronous - no await needed):\n")
	response.WriteString("  const services = fastly.service.list();\n")
	response.WriteString("  const result = fastly.compute.deploy({path: './pkg'});\n")
	response.WriteString("  const user = fastly.whoami();\n")

	return mcp.NewToolResultText(response.String()), nil
}

// handleGetCommandHelp handles the get_command_help tool
func (s *FastlyMCPServer) handleGetCommandHelp(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Get command argument
	commandPath, err := request.RequireString("command")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error: command parameter is required: %v", err)), nil
	}

	// Get registry
	registry := s.getOrCreateRegistry()

	// Get command
	cmd := registry.GetCommand(commandPath)
	if cmd == nil {
		return mcp.NewToolResultError(fmt.Sprintf("Function not found: %s", commandPath)), nil
	}

	// Build response
	var response strings.Builder
	response.WriteString(fmt.Sprintf("Function: %s\n", cmd.Path))
	response.WriteString(fmt.Sprintf("Description: %s\n\n", cmd.Description))

	if len(cmd.Flags) > 0 {
		response.WriteString(fmt.Sprintf("Parameters (%d):\n", len(cmd.Flags)))
		for _, flag := range cmd.Flags {
			required := ""
			if flag.Required {
				required = " (required)"
			}
			response.WriteString(fmt.Sprintf("  %s [%s]%s\n", strings.ReplaceAll(flag.Name, "-", "_"), flag.ValueType, required))
			if flag.Description != "" {
				response.WriteString(fmt.Sprintf("    %s\n", flag.Description))
			}
		}
		response.WriteString("\n")
	}

	if len(cmd.Subcommands) > 0 {
		response.WriteString(fmt.Sprintf("Subcommands (%d):\n", len(cmd.Subcommands)))
		for _, sub := range cmd.Subcommands {
			response.WriteString(fmt.Sprintf("  - %s: %s\n", sub.Name, sub.Description))
		}
		response.WriteString("\n")
	}

	// Add JavaScript usage example
	response.WriteString("JavaScript Usage (synchronous - no await needed):\n")
	jsPath := strings.ReplaceAll(cmd.Path, ".", ".")
	response.WriteString(fmt.Sprintf("  const result = fastly.%s({\n", jsPath))
	if len(cmd.Flags) > 0 {
		for i, flag := range cmd.Flags {
			if i >= 3 {
				break
			}
			example := "value"
			if flag.ValueType == "bool" {
				example = "true"
			}
			response.WriteString(fmt.Sprintf("    %s: %s,\n", strings.ReplaceAll(flag.Name, "-", "_"), example))
		}
	}
	response.WriteString("  });\n")

	return mcp.NewToolResultText(response.String()), nil
}

// handleGetTypes handles the get_fastly_types tool
func (s *FastlyMCPServer) handleGetTypes(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Get registry
	registry := s.getOrCreateRegistry()

	// Generate TypeScript definitions
	typedef := generateTypeScriptDefinitions(registry)

	return mcp.NewToolResultText(typedef), nil
}

// getOrCreateRegistry gets or creates the command registry
func (s *FastlyMCPServer) getOrCreateRegistry() *CommandRegistry {
	registry, err := s.GetOrCreateRegistry()
	if err != nil {
		// Fallback to creating a new registry
		registry = NewCommandRegistry(s.executor)
		_ = registry.Discover() // Ignore errors for now
	}
	return registry
}

// generateTypeScriptDefinitions generates TypeScript type definitions from the function registry
func generateTypeScriptDefinitions(registry *CommandRegistry) string {
	var sb strings.Builder

	sb.WriteString("// Fastly JavaScript API - TypeScript Definitions\n")
	sb.WriteString("// Auto-generated type definitions for all Fastly operations\n")
	sb.WriteString("//\n")
	sb.WriteString("// IMPORTANT: All functions are SYNCHRONOUS and return values immediately.\n")
	sb.WriteString("// Do NOT use 'await' or 'async' - they are not supported in this environment.\n")
	sb.WriteString("//\n")
	sb.WriteString("// Example usage:\n")
	sb.WriteString("//   const services = fastly.service.list();\n")
	sb.WriteString("//   const user = fastly.whoami();\n")
	sb.WriteString("//   services.forEach(s => console.log(s.name));\n")
	sb.WriteString("\n")

	// Get all commands and organize by namespace
	commands := registry.GetAllCommands()

	// Build namespace tree
	namespaces := make(map[string]map[string]*api.Command)
	rootCommands := []*api.Command{}

	for path, cmd := range commands {
		if path == "" {
			continue
		}

		parts := strings.Split(path, ".")
		if len(parts) == 1 {
			// Root-level command
			rootCommands = append(rootCommands, cmd)
		} else {
			// Namespaced command
			namespace := parts[0]
			if namespaces[namespace] == nil {
				namespaces[namespace] = make(map[string]*api.Command)
			}
			namespaces[namespace][path] = cmd
		}
	}

	sb.WriteString("declare namespace fastly {\n")

	// Generate root-level functions
	for _, cmd := range rootCommands {
		sb.WriteString(generateFunctionSignature(cmd, "  "))
	}

	// Generate namespaces
	for ns := range namespaces {
		sb.WriteString(fmt.Sprintf("\n  namespace %s {\n", ns))

		// Get all commands in this namespace
		for _, cmd := range namespaces[ns] {
			sb.WriteString(generateFunctionSignature(cmd, "    "))
		}

		sb.WriteString("  }\n")
	}

	sb.WriteString("}\n")

	return sb.String()
}

// generateFunctionSignature generates a TypeScript function signature for a command
func generateFunctionSignature(cmd *api.Command, indent string) string {
	// Get the function name (last part of the path)
	parts := strings.Split(cmd.Path, ".")
	funcName := parts[len(parts)-1]
	funcName = strings.ReplaceAll(funcName, "-", "_")

	// Build parameter interface
	var paramTypes []string
	hasRequired := false

	for _, flag := range cmd.Flags {
		tsType := mapCLITypeToTS(flag.ValueType)
		optional := "?"
		if flag.Required {
			optional = ""
			hasRequired = true
		}
		paramName := strings.ReplaceAll(flag.Name, "-", "_")
		paramTypes = append(paramTypes, fmt.Sprintf("%s%s: %s", paramName, optional, tsType))
	}

	// Build function signature
	var sig string
	if len(paramTypes) > 0 {
		optionalMarker := "?"
		if hasRequired {
			optionalMarker = ""
		}
		sig = fmt.Sprintf("%s/**\n", indent)
		sig += fmt.Sprintf("%s * %s\n", indent, cmd.Description)
		sig += fmt.Sprintf("%s */\n", indent)
		sig += fmt.Sprintf("%sfunction %s(options%s: {\n", indent, funcName, optionalMarker)
		for _, pt := range paramTypes {
			sig += fmt.Sprintf("%s  %s;\n", indent, pt)
		}
		sig += fmt.Sprintf("%s}): any;\n", indent)
	} else {
		sig = fmt.Sprintf("%s/**\n", indent)
		sig += fmt.Sprintf("%s * %s\n", indent, cmd.Description)
		sig += fmt.Sprintf("%s */\n", indent)
		sig += fmt.Sprintf("%sfunction %s(): any;\n", indent, funcName)
	}

	return sig
}

// mapCLITypeToTS maps parameter types to TypeScript types
func mapCLITypeToTS(cliType string) string {
	switch strings.ToLower(cliType) {
	case "bool", "boolean":
		return "boolean"
	case "int", "integer", "number":
		return "number"
	case "string":
		return "string"
	default:
		return "any"
	}
}
