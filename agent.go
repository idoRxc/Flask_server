package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	VERSION = "1.0.0"
)

type AgentConfig struct {
	Agent struct {
		Host       string `yaml:"host"`
		Port       int    `yaml:"port"`
		ServerHost string `yaml:"server_host"`
		ServerPort int    `yaml:"server_port"`
		ID         string `yaml:"id,omitempty"`
		SSL        struct {
			CertPath string `yaml:"cert_path"`
			KeyPath  string `yaml:"key_path"`
			CAPath   string `yaml:"ca_path"`
		} `yaml:"ssl"`
	} `yaml:"agent"`
	Settings struct {
		ReconnectInterval int `yaml:"reconnect_interval"`
		JobTimeout        int `yaml:"job_timeout"`
	} `yaml:"settings"`
}

type CommandResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type CommandRequest struct {
	Command string                 `json:"command"`
	Args    map[string]interface{} `json:"args"`
	JobID   string                 `json:"job_id,omitempty"`
}

type Tool interface {
	Run(params map[string]interface{}) (interface{}, error)
	Name() string
}

type ExampleTool struct{}

func (t *ExampleTool) Run(params map[string]interface{}) (interface{}, error) {
	time.Sleep(2 * time.Second)
	return map[string]string{"result": "example data collected"}, nil
}

func (t *ExampleTool) Name() string {
	return "example_tool"
}

type OSINTAgent struct {
	config     *AgentConfig
	tlsConfig  *tls.Config
	tools      map[string]Tool
	jobs       map[string]*Job
	jobsMutex  sync.RWMutex
	logger     *log.Logger
	running    bool
	cancelFunc context.CancelFunc
}

type Job struct {
	ID         string
	Tool       string
	Parameters map[string]interface{}
	Cancel     context.CancelFunc
}

func NewOSINTAgent(configPath string) (*OSINTAgent, error) {
	dirs := []string{"log", "config", "certs"}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	logFile, err := os.OpenFile("log/agent.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	logger := log.New(io.MultiWriter(os.Stdout, logFile), "AGENT: ", log.LstdFlags)

	config, err := loadAgentConfig(configPath, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	agent := &OSINTAgent{
		config:  config,
		tools:   make(map[string]Tool),
		jobs:    make(map[string]*Job),
		logger:  logger,
		running: false,
	}

	if err := agent.setupTLS(); err != nil {
		return nil, fmt.Errorf("failed to setup TLS: %w", err)
	}

	agent.tools["example_tool"] = &ExampleTool{}

	return agent, nil
}

func loadAgentConfig(configPath string, logger *log.Logger) (*AgentConfig, error) {
	var config AgentConfig

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		config.Agent.Host = "0.0.0.0"
		config.Agent.Port = 9443
		config.Agent.ServerHost = "0.0.0.0"
		config.Agent.ServerPort = 8443
		config.Agent.SSL.CertPath = "certs/agent.crt"
		config.Agent.SSL.KeyPath = "certs/agent.key"
		config.Agent.SSL.CAPath = "certs/ca.crt"
		config.Settings.ReconnectInterval = 10
		config.Settings.JobTimeout = 300

		data, err := yaml.Marshal(&config)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal default config: %w", err)
		}

		if err := os.WriteFile(configPath, data, 0644); err != nil {
			return nil, fmt.Errorf("failed to write default config: %w", err)
		}

		logger.Printf("Created default config at %s", configPath)
	} else {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	return &config, nil
}

func (a *OSINTAgent) setupTLS() error {
	caCert, err := os.ReadFile(a.config.Agent.SSL.CAPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to append CA certificate to pool")
	}

	cert, err := tls.LoadX509KeyPair(a.config.Agent.SSL.CertPath, a.config.Agent.SSL.KeyPath)
	if err != nil {
		return fmt.Errorf("failed to load agent certificates (ensure they exist): %w", err)
	}

	a.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	return nil
}

func (a *OSINTAgent) registerWithServer() error {
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", a.config.Agent.ServerHost, a.config.Agent.ServerPort), a.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	cmd := CommandRequest{
		Command: "register_agent",
		Args: map[string]interface{}{
			"address": a.config.Agent.Host,
			"port":    float64(a.config.Agent.Port),
		},
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(cmd); err != nil {
		return fmt.Errorf("failed to send register command: %w", err)
	}

	var response CommandResponse
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("failed to read registration response: %w", err)
	}

	if response.Status != "success" {
		return fmt.Errorf("registration failed: %s", response.Message)
	}

	if data, ok := response.Data.(map[string]interface{}); ok {
		if agentID, ok := data["agent_id"].(string); ok {
			a.config.Agent.ID = agentID
			a.logger.Printf("Registered with server, assigned ID: %s", agentID)
			return nil
		}
	}

	return fmt.Errorf("invalid registration response format")
}

func (a *OSINTAgent) handleIdentify(args map[string]interface{}) CommandResponse {
	// Optional: Verify server hash for security
	if hash, ok := args["hash"].(string); ok && hash == "" {
		return CommandResponse{Status: "error", Message: "Invalid server hash"}
	}

	capabilities := make([]string, 0, len(a.tools))
	for name := range a.tools {
		capabilities = append(capabilities, name)
	}

	return CommandResponse{
		Status: "ready",
		Data:   capabilities,
	}
}

func (a *OSINTAgent) handleRunTool(args map[string]interface{}, jobID string) CommandResponse {
	toolName, ok := args["tool"].(string)
	if !ok {
		return CommandResponse{Status: "error", Message: "Missing or invalid tool parameter"}
	}

	tool, exists := a.tools[toolName]
	if !exists {
		return CommandResponse{Status: "error", Message: fmt.Sprintf("Tool not supported: %s", toolName)}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.config.Settings.JobTimeout)*time.Second)
	defer cancel()

	job := &Job{
		ID:         jobID,
		Tool:       toolName,
		Parameters: args,
		Cancel:     cancel,
	}

	a.jobsMutex.Lock()
	a.jobs[jobID] = job
	a.jobsMutex.Unlock()

	resultChan := make(chan interface{}, 1)
	errChan := make(chan error, 1)

	go func() {
		result, err := tool.Run(args)
		if err != nil {
			errChan <- err
		} else {
			resultChan <- result
		}
	}()

	select {
	case result := <-resultChan:
		a.jobsMutex.Lock()
		delete(a.jobs, jobID)
		a.jobsMutex.Unlock()
		return CommandResponse{Status: "success", Data: result}
	case err := <-errChan:
		a.jobsMutex.Lock()
		delete(a.jobs, jobID)
		a.jobsMutex.Unlock()
		return CommandResponse{Status: "error", Message: err.Error()}
	case <-ctx.Done():
		a.jobsMutex.Lock()
		delete(a.jobs, jobID)
		a.jobsMutex.Unlock()
		return CommandResponse{Status: "error", Message: "Job timed out"}
	}
}

func (a *OSINTAgent) handleCancelJob(args map[string]interface{}) CommandResponse {
	jobID, ok := args["job_id"].(string)
	if !ok {
		return CommandResponse{Status: "error", Message: "Missing or invalid job_id parameter"}
	}

	a.jobsMutex.RLock()
	job, exists := a.jobs[jobID]
	a.jobsMutex.RUnlock()

	if !exists {
		return CommandResponse{Status: "error", Message: "Job not found"}
	}

	job.Cancel()
	a.jobsMutex.Lock()
	delete(a.jobs, jobID)
	a.jobsMutex.Unlock()

	return CommandResponse{Status: "success", Message: "Job cancelled"}
}

func (a *OSINTAgent) handleClient(conn net.Conn) {
	defer conn.Close()

	var cmd CommandRequest
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&cmd); err != nil {
		a.logger.Printf("Error reading command: %v", err)
		json.NewEncoder(conn).Encode(CommandResponse{Status: "error", Message: "Invalid command format"})
		return
	}

	a.logger.Printf("Received command: %s (JobID: %s)", cmd.Command, cmd.JobID)

	var response CommandResponse
	switch cmd.Command {
	case "identify":
		response = a.handleIdentify(cmd.Args)
	case "run_tool":
		if cmd.JobID == "" {
			response = CommandResponse{Status: "error", Message: "Missing job_id"}
		} else {
			response = a.handleRunTool(cmd.Args, cmd.JobID)
		}
	case "cancel_job":
		response = a.handleCancelJob(cmd.Args)
	default:
		response = CommandResponse{Status: "error", Message: "Unknown command"}
	}

	if err := json.NewEncoder(conn).Encode(response); err != nil {
		a.logger.Printf("Error sending response: %v", err)
	}
}

func (a *OSINTAgent) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelFunc = cancel

	addr := fmt.Sprintf("%s:%d", a.config.Agent.Host, a.config.Agent.Port)
	listener, err := tls.Listen("tcp", addr, a.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	a.logger.Printf("OSINT Agent v%s started on %s", VERSION, addr)
	a.running = true

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if a.config.Agent.ID == "" {
					if err := a.registerWithServer(); err != nil {
						a.logger.Printf("Failed to register with server: %v", err)
						time.Sleep(time.Duration(a.config.Settings.ReconnectInterval) * time.Second)
						continue
					}
				}
				time.Sleep(time.Duration(a.config.Settings.ReconnectInterval) * time.Second)
			}
		}
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-shutdown
		a.logger.Printf("Received shutdown signal: %s", sig)
		a.Stop()
		listener.Close()
	}()

	for a.running {
		conn, err := listener.Accept()
		if err != nil {
			if a.running {
				a.logger.Printf("Error accepting connection: %v", err)
			}
			continue
		}
		go a.handleClient(conn)
	}

	return nil
}

func (a *OSINTAgent) Stop() {
	a.logger.Printf("Stopping OSINT Agent...")
	a.running = false
	if a.cancelFunc != nil {
		a.cancelFunc()
	}
	a.logger.Printf("OSINT Agent stopped")
}

func main() {
	configPath := "config/agent.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	agent, err := NewOSINTAgent(configPath)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	if err := agent.Start(); err != nil {
		agent.logger.Fatalf("Failed to start agent: %v", err)
	}
}
