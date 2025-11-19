package server

import (
	"log"

	"github.com/fastly/cli/api"
	"github.com/fastly/cli/sandbox"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// Config holds server configuration
type Config struct {
	FastlyCLI      string
	DefaultTimeout int
	Logger         *log.Logger
}

// FastlyMCPServer implements the MCP server for Fastly CLI
type FastlyMCPServer struct {
	config   *Config
	executor *api.Executor
	registry *CommandRegistry // Cached command registry
}

// NewFastlyMCPServer creates a new Fastly MCP server instance
func NewFastlyMCPServer(config *Config) *FastlyMCPServer {
	executor := api.NewExecutor(config.FastlyCLI, config.DefaultTimeout)

	return &FastlyMCPServer{
		config:   config,
		executor: executor,
		registry: nil, // Will be initialized when needed
	}
}

// Register registers the server with the MCP instance
func (s *FastlyMCPServer) Register(server *mcpserver.MCPServer) error {
	// Register tools
	if err := s.registerTools(server); err != nil {
		return err
	}

	// Register resources
	if err := s.registerResources(server); err != nil {
		return err
	}

	return nil
}

// GetExecutor returns the API executor
func (s *FastlyMCPServer) GetExecutor() *api.Executor {
	return s.executor
}

// GetOrCreateRegistry returns the command registry, creating and caching it if needed
func (s *FastlyMCPServer) GetOrCreateRegistry() (*CommandRegistry, error) {
	if s.registry == nil {
		registry := NewCommandRegistry(s.executor)
		if err := registry.Discover(); err != nil {
			return nil, err
		}
		s.registry = registry
	}
	return s.registry, nil
}

// CreateFreshVM creates a new VM instance with a fresh environment
// This ensures each execution starts with a clean slate
func (s *FastlyMCPServer) CreateFreshVM() (*sandbox.VM, error) {
	vm, err := sandbox.NewVM(s.executor)
	if err != nil {
		return nil, err
	}

	// Set logger if available
	if s.config.Logger != nil {
		vm.SetLogger(s.config.Logger)
	}

	// Get or create the cached registry
	registry, err := s.GetOrCreateRegistry()
	if err != nil {
		return nil, err
	}

	// Inject the API into the fresh VM
	if err := vm.SetRegistry(registry); err != nil {
		return nil, err
	}

	return vm, nil
}
