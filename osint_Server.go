package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

const (
	VERSION = "1.0.0"
)

type OSINTAgent struct {
	Address      string    `json:"address"`
	Port         int       `json:"port"`
	Status       string    `json:"status"`
	LastSeen     time.Time `json:"last_seen"`
	Capabilities []string  `json:"capabilities"`
	mutex        sync.Mutex
}

type Job struct {
	AgentID    string                 `json:"agent_id"`
	Tool       string                 `json:"tool"`
	Parameters map[string]interface{} `json:"parameters"`
	Status     string                 `json:"status"`
	StartTime  time.Time              `json:"start_time"`
	EndTime    *time.Time             `json:"end_time,omitempty"`
	ClientID   string                 `json:"client_id"`
	Result     interface{}            `json:"result,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

type ServerConfig struct {
	Server struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
		SSL  struct {
			CertPath string `yaml:"cert_path"`
			KeyPath  string `yaml:"key_path"`
			CAPath   string `yaml:"ca_path"`
		} `yaml:"ssl"`
	} `yaml:"server"`
	Settings struct {
		ClientTimeout      int `yaml:"client_timeout"`
		JobTimeout         int `yaml:"job_timeout"`
		MaxConcurrentJobs  int `yaml:"max_concurrent_jobs"`
		AgentCheckInterval int `yaml:"agent_check_interval"`
		JobCleanupInterval int `yaml:"job_cleanup_interval"`
	} `yaml:"settings"`
}

type CommandRequest struct {
	Command string                 `json:"command"`
	Args    map[string]interface{} `json:"args,omitempty"`
	JobID   string                 `json:"job_id,omitempty"`
}

type CommandResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type ServerState struct {
	Agents map[string]*OSINTAgent `json:"agents"`
	Jobs   map[string]*Job        `json:"jobs"`
}

type OSINTControlServer struct {
	config       *ServerConfig
	agents       map[string]*OSINTAgent
	jobs         map[string]*Job
	tlsConfig    *tls.Config
	startTime    time.Time
	running      bool
	agentsMutex  sync.RWMutex
	jobsMutex    sync.RWMutex
	logger       *log.Logger
	cancelFunc   context.CancelFunc
	securityHash string
}

func NewOSINTControlServer(configPath string) (*OSINTControlServer, error) {
	dirs := []string{"log", "data", "config", "certs"}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	logFile, err := os.OpenFile("log/server.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	logger := log.New(io.MultiWriter(os.Stdout, logFile), "", log.LstdFlags)

	config, err := loadConfig(configPath, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	server := &OSINTControlServer{
		config:    config,
		agents:    make(map[string]*OSINTAgent),
		jobs:      make(map[string]*Job),
		startTime: time.Now(),
		running:   false,
		logger:    logger,
	}

	if err := server.setupTLS(); err != nil {
		return nil, fmt.Errorf("failed to setup TLS: %w", err)
	}

	if err := server.loadState(); err != nil {
		logger.Printf("Warning: Failed to load server state: %v", err)
	}

	return server, nil
}

func loadConfig(configPath string, logger *log.Logger) (*ServerConfig, error) {
	var config ServerConfig

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		config.Server.Host = "0.0.0.0"
		config.Server.Port = 8443
		config.Server.SSL.CertPath = "certs/server.crt"
		config.Server.SSL.KeyPath = "certs/server.key"
		config.Server.SSL.CAPath = "certs/ca.crt"

		config.Settings.ClientTimeout = 300
		config.Settings.JobTimeout = 3600
		config.Settings.MaxConcurrentJobs = 5
		config.Settings.AgentCheckInterval = 300
		config.Settings.JobCleanupInterval = 86400

		data, err := yaml.Marshal(&config)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal default config: %w", err)
		}

		if err := ioutil.WriteFile(configPath, data, 0644); err != nil {
			return nil, fmt.Errorf("failed to write default config: %w", err)
		}

		logger.Printf("Created default config at %s", configPath)
	} else {
		data, err := ioutil.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	return &config, nil
}

func (s *OSINTControlServer) setupTLS() error {
	_, certErr := os.Stat(s.config.Server.SSL.CertPath)
	_, keyErr := os.Stat(s.config.Server.SSL.KeyPath)

	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		s.logger.Printf("Certificates not found, generating self-signed certificate")
		if err := s.generateSelfSignedCert(); err != nil {
			return fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}
	}

	cert, err := tls.LoadX509KeyPair(s.config.Server.SSL.CertPath, s.config.Server.SSL.KeyPath)
	if err != nil {
		return fmt.Errorf("failed to load certificates: %w", err)
	}

	s.tlsConfig = &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		// Uncomment for client authentication if needed
		// ClientAuth: tls.RequireAndVerifyClientCert,
		// ClientCAs:  caCertPool,
	}

	return nil
}

func (s *OSINTControlServer) generateSelfSignedCert() error {
	certDir := filepath.Dir(s.config.Server.SSL.CertPath)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "OSINT Control Server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	keyOut, err := os.OpenFile(s.config.Server.SSL.KeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key file for writing: %w", err)
	}
	defer keyOut.Close()

	pemKey := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(keyOut, pemKey); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	certOut, err := os.OpenFile(s.config.Server.SSL.CertPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open cert file for writing: %w", err)
	}
	defer certOut.Close()

	pemCert := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	if err := pem.Encode(certOut, pemCert); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	caOut, err := os.OpenFile(s.config.Server.SSL.CAPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open CA file for writing: %w", err)
	}
	defer caOut.Close()

	if err := pem.Encode(caOut, pemCert); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	s.logger.Printf("Generated self-signed certificate")
	return nil
}

func (s *OSINTControlServer) saveState() error {
	s.agentsMutex.RLock()
	s.jobsMutex.RLock()
	defer s.agentsMutex.RUnlock()
	defer s.jobsMutex.RUnlock()

	state := ServerState{
		Agents: s.agents,
		Jobs:   s.jobs,
	}

	statePath := "data/server_state.json"
	if _, err := os.Stat(statePath); err == nil {
		if err := os.Rename(statePath, statePath+".bak"); err != nil {
			s.logger.Printf("Warning: Failed to create backup of state file: %v", err)
		}
	}
	if err := os.MkdirAll("data", 0755); err != nil { // Ensure data directory exists
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal server state: %w", err)
	}

	if err := ioutil.WriteFile(statePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write server state: %w", err)
	}

	return nil
}

func (s *OSINTControlServer) loadState() error {
	statePath := "data/server_state.json"
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		s.logger.Printf("No previous state found. Starting with fresh state.")
		return nil
	}

	data, err := ioutil.ReadFile(statePath)
	if err != nil {
		return fmt.Errorf("failed to read server state: %w", err)
	}

	var state ServerState
	if err := json.Unmarshal(data, &state); err != nil {
		backupPath := fmt.Sprintf("%s.corrupted.%d", statePath, time.Now().Unix())
		if copyErr := ioutil.WriteFile(backupPath, data, 0644); copyErr != nil {
			s.logger.Printf("Warning: Failed to backup corrupted state: %v", copyErr)
		} else {
			s.logger.Printf("Corrupted state backed up to %s", backupPath)
		}
		return fmt.Errorf("failed to parse server state: %w", err)
	}

	s.agentsMutex.Lock()
	s.jobsMutex.Lock()
	defer s.agentsMutex.Unlock()
	defer s.jobsMutex.Unlock()

	for id, agent := range state.Agents {
		agent.mutex = sync.Mutex{}
		s.agents[id] = agent
	}

	for id, job := range state.Jobs {
		s.jobs[id] = job
	}

	s.logger.Printf("Loaded server state: %d agents, %d jobs", len(s.agents), len(s.jobs))
	return nil
}

func (s *OSINTControlServer) checkAgentConnection(agent *OSINTAgent) bool {
	agent.mutex.Lock()
	defer agent.mutex.Unlock()

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", agent.Address, agent.Port), s.tlsConfig)
	if err != nil {
		s.logger.Printf("Failed to connect to agent %s:%d: %v", agent.Address, agent.Port, err)
		agent.Status = "disconnected"
		return false
	}
	defer conn.Close()

	identifyCmd := CommandRequest{
		Command: "identify",
		Args: map[string]interface{}{
			"server_id": "osint_control_server",
			"hash":      s.securityHash, // Use security hash for verification
		},
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(identifyCmd); err != nil {
		s.logger.Printf("Failed to send identify command to agent: %v", err)
		agent.Status = "error"
		return false
	}

	var response CommandResponse
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&response); err != nil {
		s.logger.Printf("Failed to read response from agent: %v", err)
		agent.Status = "error"
		return false
	}

	if response.Status != "ready" {
		s.logger.Printf("Agent returned non-ready status: %s", response.Status)
		agent.Status = "error"
		return false
	}

	agent.Status = "connected"
	agent.LastSeen = time.Now()

	if caps, ok := response.Data.([]interface{}); ok {
		agent.Capabilities = make([]string, 0, len(caps))
		for _, cap := range caps {
			if capStr, ok := cap.(string); ok {
				agent.Capabilities = append(agent.Capabilities, capStr)
			}
		}
	}

	return true
}

func (s *OSINTControlServer) sendCommandToAgent(agent *OSINTAgent, command string, args map[string]interface{}) (CommandResponse, error) {
	agent.mutex.Lock()
	defer agent.mutex.Unlock()

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", agent.Address, agent.Port), s.tlsConfig)
	if err != nil {
		return CommandResponse{Status: "error", Message: fmt.Sprintf("Failed to connect to agent: %v", err)}, err
	}
	defer conn.Close()

	cmd := CommandRequest{
		Command: command,
		Args:    args,
		JobID:   uuid.New().String(),
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(cmd); err != nil {
		return CommandResponse{Status: "error", Message: fmt.Sprintf("Failed to send command: %v", err)}, err
	}

	var response CommandResponse
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&response); err != nil {
		return CommandResponse{Status: "error", Message: fmt.Sprintf("Failed to read response: %v", err)}, err
	}

	agent.LastSeen = time.Now()
	return response, nil
}

func (s *OSINTControlServer) handleRegisterAgent(args map[string]interface{}) CommandResponse {
	address, ok := args["address"].(string)
	if !ok {
		return CommandResponse{Status: "error", Message: "Missing or invalid address parameter"}
	}

	port, ok := args["port"].(float64)
	if !ok {
		return CommandResponse{Status: "error", Message: "Missing or invalid port parameter"}
	}

	agentID := uuid.New().String()

	newAgent := &OSINTAgent{
		Address:      address,
		Port:         int(port),
		Status:       "connecting",
		LastSeen:     time.Now(),
		Capabilities: []string{},
		mutex:        sync.Mutex{},
	}

	if !s.checkAgentConnection(newAgent) {
		return CommandResponse{
			Status:  "error",
			Message: "Failed to establish connection with agent",
		}
	}

	s.agentsMutex.Lock()
	s.agents[agentID] = newAgent
	s.agentsMutex.Unlock()

	if err := s.saveState(); err != nil {
		s.logger.Printf("Warning: Failed to save state after agent registration: %v", err)
	}

	s.logger.Printf("New agent registered: %s (%s:%d)", agentID, address, int(port))

	return CommandResponse{
		Status:  "success",
		Message: "Agent registered successfully",
		Data: map[string]string{
			"agent_id": agentID,
		},
	}
}

func (s *OSINTControlServer) handleListAgents(args map[string]interface{}) CommandResponse {
	s.agentsMutex.RLock()
	defer s.agentsMutex.RUnlock()

	agentList := make([]map[string]interface{}, 0, len(s.agents))
	for id, agent := range s.agents {
		agent.mutex.Lock()
		agentInfo := map[string]interface{}{
			"id":           id,
			"address":      agent.Address,
			"port":         agent.Port,
			"status":       agent.Status,
			"last_seen":    agent.LastSeen,
			"capabilities": agent.Capabilities,
		}
		agent.mutex.Unlock()
		agentList = append(agentList, agentInfo)
	}

	return CommandResponse{
		Status: "success",
		Data:   agentList,
	}
}

func (s *OSINTControlServer) handleAgentInfo(args map[string]interface{}) CommandResponse {
	agentID, ok := args["agent_id"].(string)
	if !ok {
		return CommandResponse{Status: "error", Message: "Missing or invalid agent_id parameter"}
	}

	s.agentsMutex.RLock()
	agent, exists := s.agents[agentID]
	s.agentsMutex.RUnlock()

	if !exists {
		return CommandResponse{Status: "error", Message: "Agent not found"}
	}

	agent.mutex.Lock()
	agentInfo := map[string]interface{}{
		"id":           agentID,
		"address":      agent.Address,
		"port":         agent.Port,
		"status":       agent.Status,
		"last_seen":    agent.LastSeen,
		"capabilities": agent.Capabilities,
	}
	agent.mutex.Unlock()

	return CommandResponse{
		Status: "success",
		Data:   agentInfo,
	}
}

func (s *OSINTControlServer) handleRunTool(args map[string]interface{}) CommandResponse {
	agentID, ok := args["agent_id"].(string)
	if !ok {
		return CommandResponse{Status: "error", Message: "Missing or invalid agent_id parameter"}
	}

	tool, ok := args["tool"].(string)
	if !ok {
		return CommandResponse{Status: "error", Message: "Missing or invalid tool parameter"}
	}

	var parameters map[string]interface{}
	if params, ok := args["parameters"]; ok && params != nil {
		if p, ok := params.(map[string]interface{}); ok {
			parameters = p
		} else {
			return CommandResponse{Status: "error", Message: "Parameters must be a map"}
		}
	} else {
		parameters = make(map[string]interface{})
	}

	s.agentsMutex.RLock()
	agent, exists := s.agents[agentID]
	s.agentsMutex.RUnlock()

	if !exists {
		return CommandResponse{Status: "error", Message: "Agent not found"}
	}

	agent.mutex.Lock()
	if agent.Status != "connected" {
		agent.mutex.Unlock()
		return CommandResponse{Status: "error", Message: "Agent is not connected"}
	}

	toolSupported := false
	for _, cap := range agent.Capabilities {
		if cap == tool {
			toolSupported = true
			break
		}
	}
	agent.mutex.Unlock()

	if !toolSupported {
		return CommandResponse{Status: "error", Message: fmt.Sprintf("Tool not supported by agent: %s", tool)}
	}

	s.jobsMutex.RLock()
	runningCount := 0
	for _, job := range s.jobs {
		if job.Status == "running" {
			runningCount++
		}
	}
	s.jobsMutex.RUnlock()

	if runningCount >= s.config.Settings.MaxConcurrentJobs {
		return CommandResponse{
			Status:  "error",
			Message: fmt.Sprintf("Maximum concurrent jobs limit reached (%d)", s.config.Settings.MaxConcurrentJobs),
		}
	}

	jobID := uuid.New().String()
	job := &Job{
		AgentID:    agentID,
		Tool:       tool,
		Parameters: parameters,
		Status:     "running",
		StartTime:  time.Now(),
		ClientID:   "client",
	}

	s.jobsMutex.Lock()
	s.jobs[jobID] = job
	s.jobsMutex.Unlock()

	go func() {
		response, err := s.sendCommandToAgent(agent, tool, parameters)
		s.jobsMutex.Lock()
		if err != nil {
			job.Status = "error"
			job.Error = err.Error()
		} else {
			job.Status = response.Status
			job.Result = response.Data
		}
		endTime := time.Now()
		job.EndTime = &endTime
		s.jobsMutex.Unlock()

		if err := s.saveState(); err != nil {
			s.logger.Printf("Warning: Failed to save state after job completion: %v", err)
		}
	}()

	return CommandResponse{
		Status:  "success",
		Message: "Job started",
		Data:    map[string]string{"job_id": jobID},
	}
}

func (s *OSINTControlServer) handleJobStatus(args map[string]interface{}) CommandResponse {
	jobID, ok := args["job_id"].(string)
	if !ok {
		return CommandResponse{Status: "error", Message: "Missing or invalid job_id parameter"}
	}

	s.jobsMutex.RLock()
	job, exists := s.jobs[jobID]
	s.jobsMutex.RUnlock()

	if !exists {
		return CommandResponse{Status: "error", Message: "Job not found"}
	}

	return CommandResponse{
		Status: "success",
		Data:   job,
	}
}

func (s *OSINTControlServer) handleListJobs(args map[string]interface{}) CommandResponse {
	filters, _ := args["filters"].(map[string]interface{})

	s.jobsMutex.RLock()
	defer s.jobsMutex.RUnlock()

	jobList := make([]map[string]interface{}, 0)
	for id, job := range s.jobs {
		if filters != nil {
			match := true
			for key, value := range filters {
				switch key {
				case "agent_id":
					if job.AgentID != value.(string) {
						match = false
					}
				case "status":
					if job.Status != value.(string) {
						match = false
					}
				case "tool":
					if job.Tool != value.(string) {
						match = false
					}
				}
			}
			if !match {
				continue
			}
		}

		jobInfo := map[string]interface{}{
			"id":         id,
			"agent_id":   job.AgentID,
			"tool":       job.Tool,
			"status":     job.Status,
			"start_time": job.StartTime,
			"end_time":   job.EndTime,
		}
		jobList = append(jobList, jobInfo)
	}

	return CommandResponse{
		Status: "success",
		Data:   jobList,
	}
}

func (s *OSINTControlServer) handleCancelJob(args map[string]interface{}) CommandResponse {
	jobID, ok := args["job_id"].(string)
	if !ok {
		return CommandResponse{Status: "error", Message: "Missing or invalid job_id parameter"}
	}

	s.jobsMutex.RLock()
	job, exists := s.jobs[jobID]
	if !exists {
		s.jobsMutex.RUnlock()
		return CommandResponse{Status: "error", Message: "Job not found"}
	}

	if job.Status != "running" {
		s.jobsMutex.RUnlock()
		return CommandResponse{
			Status:  "error",
			Message: fmt.Sprintf("Job is not running (current status: %s)", job.Status),
		}
	}

	agentID := job.AgentID
	s.jobsMutex.RUnlock()

	s.agentsMutex.RLock()
	agent, exists := s.agents[agentID]
	s.agentsMutex.RUnlock()

	if !exists {
		return CommandResponse{Status: "error", Message: "Agent not found"}
	}

	response, err := s.sendCommandToAgent(agent, "cancel_job", map[string]interface{}{
		"job_id": jobID,
	})

	if err != nil {
		return CommandResponse{
			Status:  "error",
			Message: fmt.Sprintf("Failed to cancel job: %v", err),
		}
	}

	s.jobsMutex.Lock()
	job.Status = "cancelled"
	endTime := time.Now()
	job.EndTime = &endTime
	s.jobsMutex.Unlock()

	if err := s.saveState(); err != nil {
		s.logger.Printf("Warning: Failed to save state after job cancellation: %v", err)
	}

	return response
}

func (s *OSINTControlServer) handleServerStatus(args map[string]interface{}) CommandResponse {
	uptime := time.Since(s.startTime)

	s.jobsMutex.RLock()
	jobCounts := make(map[string]int)
	for _, job := range s.jobs {
		jobCounts[job.Status]++
	}
	totalJobs := len(s.jobs)
	s.jobsMutex.RUnlock()

	s.agentsMutex.RLock()
	agentCounts := make(map[string]int)
	for _, agent := range s.agents {
		agent.mutex.Lock()
		agentCounts[agent.Status]++
		agent.mutex.Unlock()
	}
	totalAgents := len(s.agents)
	s.agentsMutex.RUnlock()

	serverStatus := map[string]interface{}{
		"version":    VERSION,
		"uptime":     uptime.String(),
		"start_time": s.startTime,
		"agents": map[string]interface{}{
			"total":     totalAgents,
			"by_status": agentCounts,
		},
		"jobs": map[string]interface{}{
			"total":          totalJobs,
			"by_status":      jobCounts,
			"max_concurrent": s.config.Settings.MaxConcurrentJobs,
		},
	}

	return CommandResponse{
		Status: "success",
		Data:   serverStatus,
	}
}

func (s *OSINTControlServer) getCommandHandlers() map[string]func(map[string]interface{}) CommandResponse {
	return map[string]func(map[string]interface{}) CommandResponse{
		"register_agent":   s.handleRegisterAgent,
		"unregister_agent": s.handleUnregisterAgent,
		"list_agents":      s.handleListAgents,
		"agent_info":       s.handleAgentInfo,
		"run_tool":         s.handleRunTool,
		"job_status":       s.handleJobStatus,
		"list_jobs":        s.handleListJobs,
		"cancel_job":       s.handleCancelJob,
		"server_status":    s.handleServerStatus,
	}
}

func (s *OSINTControlServer) handleClient(conn net.Conn) {
	defer conn.Close()

	s.logger.Printf("Client connected: %s", conn.RemoteAddr())

	if s.config.Settings.ClientTimeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(time.Duration(s.config.Settings.ClientTimeout) * time.Second)); err != nil {
			s.logger.Printf("Warning: Failed to set connection deadline: %v", err)
		}
	}

	handlers := s.getCommandHandlers()

	var cmd CommandRequest
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&cmd); err != nil {
		s.logger.Printf("Error reading command: %v", err)
		response := CommandResponse{Status: "error", Message: "Invalid command format"}
		encoder := json.NewEncoder(conn)
		encoder.Encode(response)
		return
	}

	handler, exists := handlers[cmd.Command]
	if !exists {
		s.logger.Printf("Unknown command: %s", cmd.Command)
		response := CommandResponse{Status: "error", Message: "Unknown command"}
		encoder := json.NewEncoder(conn)
		encoder.Encode(response)
		return
	}

	s.logger.Printf("Executing command: %s", cmd.Command)
	response := handler(cmd.Args)

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(response); err != nil {
		s.logger.Printf("Error sending response: %v", err)
		return
	}

	s.logger.Printf("Command completed: %s", cmd.Command)
}

func (s *OSINTControlServer) checkAgents(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(s.config.Settings.AgentCheckInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.logger.Printf("Checking agent connections...")

			s.agentsMutex.RLock()
			agents := make([]*OSINTAgent, 0, len(s.agents))
			agentIDs := make([]string, 0, len(s.agents))
			for id, agent := range s.agents {
				agents = append(agents, agent)
				agentIDs = append(agentIDs, id)
			}
			s.agentsMutex.RUnlock()

			changedCount := 0
			for i, agent := range agents {
				currentStatus := agent.Status
				s.checkAgentConnection(agent)

				if currentStatus != agent.Status {
					s.logger.Printf("Agent %s status changed: %s -> %s", agentIDs[i], currentStatus, agent.Status)
					changedCount++
				}
			}

			if changedCount > 0 {
				if err := s.saveState(); err != nil {
					s.logger.Printf("Warning: Failed to save state after agent check: %v", err)
				}
			}

			s.logger.Printf("Agent check completed: %d agents, %d changed", len(agents), changedCount)
		}
	}
}

func (s *OSINTControlServer) cleanupJobs(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(s.config.Settings.JobCleanupInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.logger.Printf("Starting job cleanup...")

			now := time.Now()

			s.jobsMutex.Lock()
			timedOutCount := 0
			for id, job := range s.jobs {
				if job.Status != "running" {
					continue
				}

				if now.Sub(job.StartTime).Seconds() > float64(s.config.Settings.JobTimeout) {
					s.logger.Printf("Job %s timed out", id)
					job.Status = "timed_out"
					endTime := now
					job.EndTime = &endTime
					job.Error = "Job timed out"
					timedOutCount++

					s.agentsMutex.RLock()
					if agent, exists := s.agents[job.AgentID]; exists {
						go s.sendCommandToAgent(agent, "cancel_job", map[string]interface{}{
							"job_id": id,
						})
					}
					s.agentsMutex.RUnlock()
				}
			}
			s.jobsMutex.Unlock()

			if timedOutCount > 0 {
				if err := s.saveState(); err != nil {
					s.logger.Printf("Warning: Failed to save state after job cleanup: %v", err)
				}
				s.logger.Printf("Job cleanup completed: %d jobs timed out", timedOutCount)
			} else {
				s.logger.Printf("Job cleanup completed: no changes")
			}
		}
	}
}

func (s *OSINTControlServer) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancelFunc = cancel

	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)
	listener, err := tls.Listen("tcp", addr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.logger.Printf("OSINT Control Server v%s started on %s", VERSION, addr)
	s.running = true

	go s.checkAgents(ctx)
	go s.cleanupJobs(ctx)

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-shutdown
		s.logger.Printf("Received shutdown signal: %s", sig)
		s.Stop()
		listener.Close()
	}()

	for s.running {
		conn, err := listener.Accept()
		if err != nil {
			if s.running {
				s.logger.Printf("Error accepting connection: %v", err)
			}
			continue
		}

		go s.handleClient(conn)
	}

	return nil
}

func (s *OSINTControlServer) Stop() {
	s.logger.Printf("Stopping OSINT Control Server...")
	s.running = false

	if s.cancelFunc != nil {
		s.cancelFunc()
	}

	if err := s.saveState(); err != nil {
		s.logger.Printf("Warning: Failed to save state during shutdown: %v", err)
	}

	s.logger.Printf("OSINT Control Server stopped")
}

func create_custom_hash() (string, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("cryptographically secure random number generation failed: %w", err)
	}

	zeroCount := 0
	for _, b := range randomBytes {
		if b == 0 {
			zeroCount++
		}
	}

	if zeroCount > len(randomBytes)/4 {
		return "", fmt.Errorf("insufficient entropy in random bytes")
	}

	hash := sha256.Sum256(randomBytes)
	return fmt.Sprintf("%x", hash), nil
}

func (s *OSINTControlServer) handleUnregisterAgent(args map[string]interface{}) CommandResponse {
	agentID, ok := args["agent_id"].(string)
	if !ok {
		return CommandResponse{Status: "error", Message: "Missing or invalid agent_id parameter"}
	}

	s.agentsMutex.Lock()
	if _, exists := s.agents[agentID]; !exists {
		s.agentsMutex.Unlock()
		return CommandResponse{Status: "error", Message: "Agent not found"}
	}

	delete(s.agents, agentID)
	s.agentsMutex.Unlock()

	if err := s.saveState(); err != nil {
		s.logger.Printf("Warning: Failed to save state after agent unregistration: %v", err)
	}

	s.logger.Printf("Agent unregistered: %s", agentID)
	return CommandResponse{
		Status:  "success",
		Message: "Agent unregistered successfully",
	}
}

func main() {
	configPath := "config/server.yaml"

	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	server, err := NewOSINTControlServer(configPath)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	hash, err := create_custom_hash()
	if err != nil {
		server.logger.Fatalf("Failed to generate server security hash: %v", err)
		os.Exit(1)
	}
	server.securityHash = hash
	server.logger.Printf("Server security hash generated: %s", server.securityHash)

	if err := server.Start(); err != nil {
		server.logger.Fatalf("Failed to start server: %v", err)
	}
}
