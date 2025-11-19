package sandbox

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/dop251/goja"
	"github.com/fastly/cli/api"
)

// InjectAPI injects the Fastly API into the VM
func (vm *VM) InjectAPI() error {
	if vm.registry == nil {
		return fmt.Errorf("command registry not set")
	}

	// Create the root fastly object
	fastlyObj := vm.runtime.NewObject()

	// Get all commands from registry
	root := vm.registry.GetRoot()

	// Build the API structure recursively
	if err := vm.buildAPIObject(fastlyObj, root.Subcommands, []string{}); err != nil {
		return fmt.Errorf("failed to build API: %w", err)
	}

	// Set the global fastly object
	if err := vm.runtime.Set("fastly", fastlyObj); err != nil {
		return fmt.Errorf("failed to set fastly global: %w", err)
	}

	return nil
}

// buildAPIObject recursively builds the JavaScript API object structure
func (vm *VM) buildAPIObject(obj *goja.Object, commands []*api.Command, path []string) error {
	for _, cmd := range commands {
		if cmd.Name == "" {
			continue
		}

		// If command has subcommands, create a nested object
		if len(cmd.Subcommands) > 0 {
			subObj := vm.runtime.NewObject()

			// Add subcommands to the nested object
			newPath := append(path, cmd.Name)
			if err := vm.buildAPIObject(subObj, cmd.Subcommands, newPath); err != nil {
				return err
			}

			// Set the nested object
			funcName := cmd.Name
			if err := obj.Set(funcName, subObj); err != nil {
				return fmt.Errorf("failed to set nested object %s: %w", funcName, err)
			}
		} else {
			// Leaf command - create a function
			funcName := cmd.Name

			// Create the function
			cmdFullPath := append(path, cmd.Name)
			fn := vm.createCommandFunction(cmdFullPath)

			if err := obj.Set(funcName, fn); err != nil {
				return fmt.Errorf("failed to set function %s: %w", funcName, err)
			}
		}
	}

	return nil
}

// createCommandFunction creates a JavaScript function that executes a Fastly operation
func (vm *VM) createCommandFunction(commandPath []string) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		// Log function call if verbose logging is enabled
		if vm.logger != nil {
			vm.logger.Printf("JS: Calling fastly.%s()", strings.Join(commandPath, "."))
		}

		// Get options argument (first parameter)
		var options map[string]interface{}
		if len(call.Arguments) > 0 && !goja.IsUndefined(call.Arguments[0]) && !goja.IsNull(call.Arguments[0]) {
			exported := call.Arguments[0].Export()
			if opts, ok := exported.(map[string]interface{}); ok {
				options = opts
			}
		}

		if options == nil {
			options = make(map[string]interface{})
		}

		// Log options if provided
		if vm.logger != nil && len(options) > 0 {
			vm.logger.Printf("JS: Options: %+v", options)
		}

		// Auto-inject --json for operations that return structured data
		// This makes the API work intuitively for LLMs without requiring explicit {json: true}
		if shouldAutoJSON(commandPath) {
			// Only add if user didn't explicitly set it
			if _, hasJSON := options["json"]; !hasJSON {
				if _, hasFormat := options["format"]; !hasFormat {
					options["json"] = true
				}
			}
		}

		// Build arguments from operation path and options
		args := make([]string, 0, len(commandPath)+len(options)*2)

		// Add operation path
		args = append(args, commandPath...)

		// Convert options to flags
		for key, value := range options {
			flagName := "--" + strings.ReplaceAll(key, "_", "-")

			// Handle boolean flags
			if boolVal, ok := value.(bool); ok {
				if boolVal {
					args = append(args, flagName)
				}
				continue
			}

			// Handle other types
			args = append(args, flagName)
			args = append(args, fmt.Sprintf("%v", value))
		}

		// Execute the operation
		if vm.logger != nil {
			vm.logger.Printf("JS: Executing API call with args: %v", args)
		}

		result := vm.executor.Execute(args, vm.executor.GetDefaultTimeout())

		// Check for errors
		if result.Error != nil {
			if vm.logger != nil {
				vm.logger.Printf("JS: API call failed: %v", result.Error)
			}
			// Throw JavaScript error
			panic(vm.runtime.ToValue(result.Error.Error()))
		}

		// Log success
		if vm.logger != nil {
			if result.JSON != nil {
				vm.logger.Printf("JS: API call succeeded, returned JSON data")
			} else {
				vm.logger.Printf("JS: API call succeeded, returned: %s", result.Stdout)
			}
		}

		// Return the JSON result if available
		if result.JSON != nil {
			// Convert PascalCase property names to camelCase for JavaScript friendliness
			camelCased := toCamelCaseKeys(result.JSON)

			// Log the converted data structure in verbose mode
			if vm.logger != nil {
				jsonBytes, err := json.Marshal(camelCased)
				if err == nil {
					jsonStr := string(jsonBytes)
					// Truncate if too long to avoid massive logs
					if len(jsonStr) > 1000 {
						vm.logger.Printf("JS: Returned data (truncated): %s...", jsonStr[:1000])
					} else {
						vm.logger.Printf("JS: Returned data: %s", jsonStr)
					}
				}
			}

			// Auto-unwrap JSON-API data arrays for better LLM experience
			// If the response has a "data" field containing an array, return just the array
			// This makes list operations more intuitive: fastly.service.list() returns array directly
			if m, ok := camelCased.(map[string]interface{}); ok {
				if dataField, hasData := m["data"]; hasData {
					if _, isArray := dataField.([]interface{}); isArray {
						if vm.logger != nil {
							vm.logger.Printf("JS: Auto-unwrapping 'data' array for direct access")
						}
						// Flatten JSON:API attributes for array items
						flattenedArray := flattenJSONAPIArray(dataField.([]interface{}))
						return vm.runtime.ToValue(flattenedArray)
					}
				}
			}

			// Flatten single JSON:API objects too
			flattened := flattenJSONAPIObject(camelCased)
			return vm.runtime.ToValue(flattened)
		}

		// Otherwise return stdout
		return vm.runtime.ToValue(result.Stdout)
	}
}

// toCamelCaseKeys recursively converts all map keys from PascalCase to camelCase
// This makes JSON responses more JavaScript-friendly
func toCamelCaseKeys(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			camelKey := toCamelCase(key)
			result[camelKey] = toCamelCaseKeys(value)
		}
		// Add convenient aliases for common properties that LLMs expect
		addConvenientAliases(result)
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = toCamelCaseKeys(item)
		}
		return result
	default:
		return v
	}
}

// flattenJSONAPIArray flattens JSON:API objects in an array by merging attributes to the top level
// Converts: [{attributes: {name: "x"}, id: "y"}] -> [{name: "x", id: "y"}]
func flattenJSONAPIArray(arr []interface{}) []interface{} {
	result := make([]interface{}, len(arr))
	for i, item := range arr {
		result[i] = flattenJSONAPIObject(item)
	}
	return result
}

// flattenJSONAPIObject flattens a single JSON:API object by merging attributes to the top level
func flattenJSONAPIObject(data interface{}) interface{} {
	m, ok := data.(map[string]interface{})
	if !ok {
		return data
	}

	// If there's an "attributes" field, merge it to the top level
	if attrs, hasAttrs := m["attributes"]; hasAttrs {
		if attrsMap, ok := attrs.(map[string]interface{}); ok {
			// Create a new map with all top-level fields
			flattened := make(map[string]interface{})

			// Copy all non-attributes fields first
			for k, v := range m {
				if k != "attributes" {
					flattened[k] = v
				}
			}

			// Merge attributes to top level (attributes take precedence)
			for k, v := range attrsMap {
				flattened[k] = v
			}

			return flattened
		}
	}

	return m
}

// addConvenientAliases adds LLM-friendly property aliases
// e.g., "id" as alias for "serviceID", "customerId", etc.
func addConvenientAliases(m map[string]interface{}) {
	// If there's a "serviceID" property, add "id" as alias
	if val, ok := m["serviceID"]; ok && m["id"] == nil {
		m["id"] = val
	}
	// If there's a "customerID" but no "customerId", add the camelCase variant
	if val, ok := m["customerID"]; ok && m["customerId"] == nil {
		m["customerId"] = val
	}
}

// toCamelCase converts a PascalCase string to camelCase by lowercasing the first letter
// Examples: "ServiceID" -> "serviceID", "Name" -> "name", "ActiveVersion" -> "activeVersion"
func toCamelCase(s string) string {
	if s == "" {
		return s
	}

	runes := []rune(s)
	if len(runes) == 0 {
		return s
	}

	// Simple approach: just lowercase the first character
	// This gives us: ServiceID -> serviceID, Name -> name, etc.
	runes[0] = unicode.ToLower(runes[0])
	return string(runes)
}

// shouldAutoJSON determines if an operation should automatically have --json added
// Operations that return structured data should use JSON for better LLM integration
func shouldAutoJSON(commandPath []string) bool {
	if len(commandPath) == 0 {
		return false
	}

	// Get the last part of the path (the actual operation)
	lastPart := commandPath[len(commandPath)-1]

	// Operations that typically return structured data
	dataCommands := []string{
		"list",
		"describe",
		"get",
		"show",
		"stats",
		"versions",
		"diff",
		"endpoints",
		"backends",
		"domains",
		"services",
		"users",
		"tokens",
		"dictionaries",
		"acls",
		"edges",
		"pop",
		"pops",
	}

	for _, cmd := range dataCommands {
		if lastPart == cmd {
			return true
		}
	}

	// Also check for common data-returning patterns
	// e.g., "service-version" likely returns data
	if strings.Contains(lastPart, "list") ||
		strings.HasSuffix(lastPart, "s") && len(commandPath) == 2 {
		return true
	}

	return false
}

// CreateAsyncWrapper wraps synchronous functions in Promises
// NOTE: This is currently not used as functions execute synchronously by default
// This allows Fastly functions to be used with async/await if needed
func (vm *VM) CreateAsyncWrapper() error {
	// Inject a helper to make functions async
	_, err := vm.runtime.RunString(`
		// Helper to convert sync fastly functions to Promises
		function __makeAsync(fn) {
			return function(options) {
				return new Promise((resolve, reject) => {
					try {
						const result = fn(options);
						resolve(result);
					} catch (error) {
						reject(error);
					}
				});
			};
		}

		// Wrap all fastly functions with async support
		function __wrapAPIWithPromises(obj) {
			const wrapped = {};
			for (const key in obj) {
				if (typeof obj[key] === 'function') {
					wrapped[key] = __makeAsync(obj[key]);
				} else if (typeof obj[key] === 'object' && obj[key] !== null) {
					wrapped[key] = __wrapAPIWithPromises(obj[key]);
				} else {
					wrapped[key] = obj[key];
				}
			}
			return wrapped;
		}

		// Replace fastly object with async-wrapped version
		if (typeof fastly !== 'undefined') {
			fastly = __wrapAPIWithPromises(fastly);
		}
	`)

	return err
}
