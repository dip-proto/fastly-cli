package sandbox

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/dop251/goja"
	"github.com/fastly/cli/api"
)

// VM represents a Goja JavaScript sandbox
type VM struct {
	runtime  *goja.Runtime
	executor *api.Executor
	registry *api.CommandRegistry
	logger   *log.Logger
}

// ExecuteResult contains the result of JavaScript execution
type ExecuteResult struct {
	Value    interface{}
	Output   []string // Console output
	Error    error
	Duration time.Duration
}

// NewVM creates a new JavaScript sandbox
func NewVM(executor *api.Executor) (*VM, error) {
	runtime := goja.New()

	vm := &VM{
		runtime:  runtime,
		executor: executor,
	}

	// Set up security restrictions
	if err := vm.setupSecurity(); err != nil {
		return nil, fmt.Errorf("failed to setup security: %w", err)
	}

	// Set up console
	if err := vm.setupConsole(); err != nil {
		return nil, fmt.Errorf("failed to setup console: %w", err)
	}

	return vm, nil
}

// Execute runs JavaScript code with timeout
func (vm *VM) Execute(code string, timeoutSeconds int) *ExecuteResult {
	result := &ExecuteResult{
		Output: []string{},
	}

	start := time.Now()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	// Execute in a goroutine to support timeout
	done := make(chan struct{})
	var val goja.Value
	var err error

	go func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic during execution: %v", r)
				if vm.logger != nil {
					vm.logger.Printf("JS: Panic during execution: %v", r)
				}
			}
			close(done)
		}()

		// Compile and run
		val, err = vm.runtime.RunString(code)
		if err != nil && vm.logger != nil {
			vm.logger.Printf("JS: Execution error: %v", err)
		}
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		result.Duration = time.Since(start)
		if err != nil {
			result.Error = err
			if vm.logger != nil {
				vm.logger.Printf("JS: Execution failed: %v", err)
			}
		} else if val != nil {
			result.Value = val.Export()
			if vm.logger != nil {
				vm.logger.Printf("JS: Execution completed successfully")
			}
		}
	case <-ctx.Done():
		result.Duration = time.Since(start)
		result.Error = fmt.Errorf("execution timeout after %d seconds", timeoutSeconds)
		vm.runtime.Interrupt("execution timeout")
		if vm.logger != nil {
			vm.logger.Printf("JS: Execution timeout after %d seconds", timeoutSeconds)
		}
	}

	// Get console output from the VM
	if consoleObj := vm.runtime.Get("__console_output"); consoleObj != nil {
		if arr, ok := consoleObj.Export().([]interface{}); ok {
			for _, item := range arr {
				result.Output = append(result.Output, fmt.Sprintf("%v", item))
			}
		}
	}

	return result
}

// GetRuntime returns the underlying Goja runtime (for advanced use)
func (vm *VM) GetRuntime() *goja.Runtime {
	return vm.runtime
}

// SetRegistry sets the command registry and injects the API
func (vm *VM) SetRegistry(registry *api.CommandRegistry) error {
	vm.registry = registry

	// Inject the Fastly API
	if err := vm.InjectAPI(); err != nil {
		return fmt.Errorf("failed to inject API: %w", err)
	}

	// Note: Not using Promise wrapper because Goja doesn't have an event loop
	// Functions are synchronous and return values directly

	return nil
}

// GetRegistry returns the command registry
func (vm *VM) GetRegistry() *api.CommandRegistry {
	return vm.registry
}

// SetLogger sets the logger for the VM
func (vm *VM) SetLogger(logger *log.Logger) {
	vm.logger = logger
}
