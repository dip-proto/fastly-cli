package sandbox

import (
	"fmt"
)

// setupSecurity configures security restrictions for the VM
func (vm *VM) setupSecurity() error {
	// Block dangerous global objects and functions
	dangerousGlobals := []string{
		"require",      // CommonJS require
		"module",       // CommonJS module
		"exports",      // CommonJS exports
		"process",      // Node.js process
		"global",       // Node.js global
		"Buffer",       // Node.js Buffer
		"__dirname",    // Node.js __dirname
		"__filename",   // Node.js __filename
		"setTimeout",   // Timers (can be used for DoS)
		"setInterval",  // Timers
		"setImmediate", // Timers
		"clearTimeout", // Timers
		"clearInterval", // Timers
		"clearImmediate", // Timers
	}

	// Set all dangerous globals to undefined using JavaScript
	blockScript := ""
	for _, name := range dangerousGlobals {
		blockScript += fmt.Sprintf("var %s = undefined;\n", name)
	}

	if blockScript != "" {
		if _, err := vm.runtime.RunString(blockScript); err != nil {
			return fmt.Errorf("failed to block dangerous globals: %w", err)
		}
	}

	// Block eval and Function constructor
	_, err := vm.runtime.RunString(`
		// Block eval
		eval = undefined;

		// Block Function constructor (while keeping Function.prototype)
		const OriginalFunction = Function;
		Function = undefined;

		// Freeze important objects to prevent tampering
		Object.freeze(Object.prototype);
		Object.freeze(Array.prototype);
		Object.freeze(String.prototype);
		Object.freeze(Number.prototype);
		Object.freeze(Boolean.prototype);
	`)

	if err != nil {
		return fmt.Errorf("failed to setup security restrictions: %w", err)
	}

	return nil
}

// setupConsole configures a safe console object for logging
func (vm *VM) setupConsole() error {
	// Create output array to capture console output
	_, err := vm.runtime.RunString(`
		var __console_output = [];

		var console = {
			log: function(...args) {
				__console_output.push(args.map(String).join(' '));
			},
			error: function(...args) {
				__console_output.push('[ERROR] ' + args.map(String).join(' '));
			},
			warn: function(...args) {
				__console_output.push('[WARN] ' + args.map(String).join(' '));
			},
			info: function(...args) {
				__console_output.push('[INFO] ' + args.map(String).join(' '));
			},
			debug: function(...args) {
				__console_output.push('[DEBUG] ' + args.map(String).join(' '));
			}
		};
	`)

	if err != nil {
		return fmt.Errorf("failed to setup console: %w", err)
	}

	return nil
}
