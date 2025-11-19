package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	apiclient "github.com/fastly/openapi/clients/go/client"
	"github.com/fastly/openapi/clients/go/client/account"
	"github.com/fastly/openapi/clients/go/client/configuration"
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// Executor handles secure execution of Fastly API operations
type Executor struct {
	apiToken       string
	client         *apiclient.FastlyGoClient
	defaultTimeout int
}

// ExecuteResult contains the result of an API operation execution
type ExecuteResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Error    error
	JSON     interface{} // Parsed JSON output if available
}

// NewExecutor creates a new API executor
// Note: apiToken parameter replaces cliPath from the original
func NewExecutor(apiToken string, timeout int) *Executor {
	// Create HTTP transport
	transport := httptransport.New("api.fastly.com", "/", []string{"https"})
	transport.Consumers["application/vnd.api+json"] = runtime.JSONConsumer()
	transport.Producers["application/vnd.api+json"] = runtime.JSONProducer()
	transport.Consumers["text/html"] = runtime.TextConsumer()
	transport.Producers["text/html"] = runtime.TextProducer()

	// Create API client
	formats := strfmt.Default
	client := apiclient.New(transport, formats)

	return &Executor{
		apiToken:       apiToken,
		client:         client,
		defaultTimeout: timeout,
	}
}

// Execute runs a Fastly API operation with the given arguments
// This translates command-line style arguments to API calls
func (e *Executor) Execute(args []string, timeoutSeconds int) *ExecuteResult {
	result := &ExecuteResult{
		ExitCode: -1,
	}

	// Validate arguments for security
	if err := ValidateArgs(args); err != nil {
		result.Error = fmt.Errorf("argument validation failed: %w", err)
		return result
	}

	if len(args) == 0 {
		result.Error = fmt.Errorf("no command specified")
		return result
	}

	// Use default timeout if not specified
	if timeoutSeconds <= 0 {
		timeoutSeconds = e.defaultTimeout
	}

	// Create auth
	tokenAuth := httptransport.APIKeyAuth("Fastly-Key", "header", e.apiToken)

	// Route to appropriate API call based on command path
	ctx := context.TODO()

	// Parse command and options
	commandPath, options := parseCommandAndOptions(args)

	// Route based on command path
	switch {
	case matchCommand(commandPath, "whoami"):
		return e.executeWhoami(ctx, tokenAuth, options)

	case matchCommand(commandPath, "service", "list"):
		return e.executeServiceList(ctx, tokenAuth, options)

	case matchCommand(commandPath, "service", "describe"):
		return e.executeServiceDescribe(ctx, tokenAuth, options)

	case matchCommand(commandPath, "version", "list"):
		return e.executeVersionList(ctx, tokenAuth, options)

	default:
		result.Error = fmt.Errorf("unsupported command: %s (API mapping not yet implemented)", strings.Join(commandPath, " "))
		result.Stderr = result.Error.Error()
		return result
	}
}

// executeWhoami implements the whoami operation
func (e *Executor) executeWhoami(ctx context.Context, auth runtime.ClientAuthInfoWriter, options map[string]interface{}) *ExecuteResult {
	result := &ExecuteResult{}

	params := account.GetCurrentUserParams{
		Context: ctx,
	}

	resp, err := e.client.Account.GetCurrentUser(&params, auth)
	if err != nil {
		result.Error = fmt.Errorf("API error: %w", err)
		result.Stderr = result.Error.Error()
		result.ExitCode = 1
		return result
	}

	// Marshal response to JSON
	jsonData, err := json.MarshalIndent(resp.Payload, "", "  ")
	if err != nil {
		result.Error = fmt.Errorf("failed to marshal response: %w", err)
		result.ExitCode = 1
		return result
	}

	result.Stdout = string(jsonData)

	// Convert struct to map[string]interface{} for JavaScript consumption
	var jsonMap interface{}
	if err := json.Unmarshal(jsonData, &jsonMap); err != nil {
		result.Error = fmt.Errorf("failed to unmarshal to map: %w", err)
		result.ExitCode = 1
		return result
	}
	result.JSON = jsonMap
	result.ExitCode = 0
	return result
}

// executeServiceList implements the service list operation
func (e *Executor) executeServiceList(ctx context.Context, auth runtime.ClientAuthInfoWriter, options map[string]interface{}) *ExecuteResult {
	result := &ExecuteResult{}

	params := configuration.GetServicesParams{
		Context: ctx,
	}

	// Handle optional customer_id filter
	if customerID, ok := options["customer_id"].(string); ok && customerID != "" {
		params.FilterCustomerID = &customerID
	}

	resp, err := e.client.Configuration.GetServices(&params, auth)
	if err != nil {
		result.Error = fmt.Errorf("API error: %w", err)
		result.Stderr = result.Error.Error()
		result.ExitCode = 1
		return result
	}

	// Marshal response to JSON
	jsonData, err := json.MarshalIndent(resp.Payload, "", "  ")
	if err != nil {
		result.Error = fmt.Errorf("failed to marshal response: %w", err)
		result.ExitCode = 1
		return result
	}

	result.Stdout = string(jsonData)

	// Convert struct to map[string]interface{} for JavaScript consumption
	var jsonMap interface{}
	if err := json.Unmarshal(jsonData, &jsonMap); err != nil {
		result.Error = fmt.Errorf("failed to unmarshal to map: %w", err)
		result.ExitCode = 1
		return result
	}
	result.JSON = jsonMap
	result.ExitCode = 0
	return result
}

// executeServiceDescribe implements the service describe operation
func (e *Executor) executeServiceDescribe(ctx context.Context, auth runtime.ClientAuthInfoWriter, options map[string]interface{}) *ExecuteResult {
	result := &ExecuteResult{}

	// Service ID is required
	serviceID, ok := options["service_id"].(string)
	if !ok || serviceID == "" {
		result.Error = fmt.Errorf("service_id is required")
		result.Stderr = result.Error.Error()
		result.ExitCode = 1
		return result
	}

	params := configuration.GetServicesParams{
		Context:  ctx,
		FilterID: &serviceID,
	}

	resp, err := e.client.Configuration.GetServices(&params, auth)
	if err != nil {
		result.Error = fmt.Errorf("API error: %w", err)
		result.Stderr = result.Error.Error()
		result.ExitCode = 1
		return result
	}

	// Marshal response to JSON
	jsonData, err := json.MarshalIndent(resp.Payload, "", "  ")
	if err != nil {
		result.Error = fmt.Errorf("failed to marshal response: %w", err)
		result.ExitCode = 1
		return result
	}

	result.Stdout = string(jsonData)

	// Convert struct to map[string]interface{} for JavaScript consumption
	var jsonMap interface{}
	if err := json.Unmarshal(jsonData, &jsonMap); err != nil {
		result.Error = fmt.Errorf("failed to unmarshal to map: %w", err)
		result.ExitCode = 1
		return result
	}
	result.JSON = jsonMap
	result.ExitCode = 0
	return result
}

// executeVersionList implements the version list operation
func (e *Executor) executeVersionList(ctx context.Context, auth runtime.ClientAuthInfoWriter, options map[string]interface{}) *ExecuteResult {
	result := &ExecuteResult{}

	// Service ID is required
	serviceID, ok := options["service_id"].(string)
	if !ok || serviceID == "" {
		result.Error = fmt.Errorf("service_id is required")
		result.Stderr = result.Error.Error()
		result.ExitCode = 1
		return result
	}

	params := configuration.ServiceVersionsParams{
		Context:   ctx,
		ServiceID: serviceID,
	}

	resp, err := e.client.Configuration.ServiceVersions(&params, auth)
	if err != nil {
		result.Error = fmt.Errorf("API error: %w", err)
		result.Stderr = result.Error.Error()
		result.ExitCode = 1
		return result
	}

	// Marshal response to JSON
	jsonData, err := json.MarshalIndent(resp.Payload, "", "  ")
	if err != nil {
		result.Error = fmt.Errorf("failed to marshal response: %w", err)
		result.ExitCode = 1
		return result
	}

	result.Stdout = string(jsonData)

	// Convert struct to map[string]interface{} for JavaScript consumption
	var jsonMap interface{}
	if err := json.Unmarshal(jsonData, &jsonMap); err != nil {
		result.Error = fmt.Errorf("failed to unmarshal to map: %w", err)
		result.ExitCode = 1
		return result
	}
	result.JSON = jsonMap
	result.ExitCode = 0
	return result
}

// parseCommandAndOptions parses command-line style arguments into command path and options
func parseCommandAndOptions(args []string) ([]string, map[string]interface{}) {
	commandPath := []string{}
	options := make(map[string]interface{})

	i := 0
	for i < len(args) {
		arg := args[i]

		// Check if it's a flag
		if strings.HasPrefix(arg, "--") {
			flagName := strings.TrimPrefix(arg, "--")
			flagName = strings.ReplaceAll(flagName, "-", "_") // Convert kebab-case to snake_case

			// Check if next arg is the value
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				options[flagName] = args[i+1]
				i += 2
			} else {
				// Boolean flag
				options[flagName] = true
				i++
			}
		} else {
			// Part of command path
			commandPath = append(commandPath, arg)
			i++
		}
	}

	return commandPath, options
}

// matchCommand checks if a command path matches the expected sequence
func matchCommand(commandPath []string, expected ...string) bool {
	if len(commandPath) != len(expected) {
		return false
	}
	for i, cmd := range commandPath {
		if cmd != expected[i] {
			return false
		}
	}
	return true
}

// ExecuteWithJSON runs an API operation and ensures JSON output
func (e *Executor) ExecuteWithJSON(args []string, timeoutSeconds int) *ExecuteResult {
	// API calls always return JSON, so just execute normally
	return e.Execute(args, timeoutSeconds)
}

// GetCLIPath returns empty string (not applicable for API executor)
func (e *Executor) GetCLIPath() string {
	return ""
}

// GetDefaultTimeout returns the default timeout in seconds
func (e *Executor) GetDefaultTimeout() int {
	return e.defaultTimeout
}
