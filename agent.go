package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Ullaakut/nmap/v2"
	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

const (
	VERSION = "1.3.0"
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
		HeartbeatInterval int `yaml:"heartbeat_interval"`
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

type OSINTAgent struct {
	config     *AgentConfig
	tlsConfig  *tls.Config
	tools      map[string]Tool
	jobs       map[string]*Job
	jobsMutex  sync.RWMutex
	logger     *log.Logger
	running    bool
	cancelFunc context.CancelFunc
	conn       *websocket.Conn
	connMutex  sync.Mutex
}

type Job struct {
	ID         string
	Tool       string
	Parameters map[string]interface{}
	Cancel     context.CancelFunc
}

// SherlockTool: Username enumeration with Sherlock
type SherlockTool struct{}

func (t *SherlockTool) Run(params map[string]interface{}) (interface{}, error) {
	username, _ := params["username"].(string)
	if username == "" {
		return nil, fmt.Errorf("missing username parameter")
	}

	// Ensure Sherlock is installed (assumes Python and Sherlock are in PATH)
	cmd := exec.Command("python3", "-m", "sherlock.sherlock", username, "--print-found", "--timeout", "10")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sherlock failed: %w, output: %s", err, string(output))
	}

	// Parse Sherlock output (simple line-by-line for now)
	lines := strings.Split(string(output), "\n")
	results := make(map[string]string)
	for _, line := range lines {
		if strings.HasPrefix(line, "[+]") {
			parts := strings.SplitN(line[3:], ": ", 2)
			if len(parts) == 2 {
				results[parts[0]] = parts[1]
			}
		}
	}
	return results, nil
}

func (t *SherlockTool) Name() string {
	return "sherlock"
}

// NmapTool: Port scanning with Nmap
type NmapTool struct{}

func (t *NmapTool) Run(params map[string]interface{}) (interface{}, error) {
	target, _ := params["target"].(string)
	ports, _ := params["ports"].(string)
	if target == "" {
		return nil, fmt.Errorf("missing target parameter")
	}
	if ports == "" {
		ports = "22,80,443" // Default ports
	}

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithPorts(ports),
		nmap.WithTimingTemplate(nmap.TimingFast),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create scanner: %w", err)
	}

	result, _, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	openPorts := []int{}
	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			if port.State.State == "open" {
				openPorts = append(openPorts, int(port.ID))
			}
		}
	}

	return map[string]interface{}{
		"target":     target,
		"open_ports": openPorts,
	}, nil
}

func (t *NmapTool) Name() string {
	return "nmap_scan"
}

// GeoLocateTool: IP geolocation with ip-api.com
type GeoLocateTool struct {
	client *http.Client
}

func (t *GeoLocateTool) Run(params map[string]interface{}) (interface{}, error) {
	ip, _ := params["ip"].(string)
	if ip == "" {
		return nil, fmt.Errorf("missing ip parameter")
	}

	resp, err := t.client.Get(fmt.Sprintf("http://ip-api.com/json/%s", ip))
	if err != nil {
		return nil, fmt.Errorf("geolocation request failed: %w", err)
	}
	defer resp.Body.Close()

	var geoData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&geoData); err != nil {
		return nil, fmt.Errorf("failed to decode geolocation response: %w", err)
	}

	if geoData["status"] == "fail" {
		return nil, fmt.Errorf("geolocation failed: %s", geoData["message"])
	}

	return map[string]interface{}{
		"ip":        ip,
		"latitude":  geoData["lat"],
		"longitude": geoData["lon"],
		"city":      geoData["city"],
		"country":   geoData["country"],
	}, nil
}

func (t *GeoLocateTool) Name() string {
	return "geolocate_ip"
}

// TheHarvesterTool: Email and subdomain enumeration
type TheHarvesterTool struct{}

func (t *TheHarvesterTool) Run(params map[string]interface{}) (interface{}, error) {
	domain, _ := params["domain"].(string)
	if domain == "" {
		return nil, fmt.Errorf("missing domain parameter")
	}

	// Ensure theHarvester is installed
	cmd := exec.Command("theharvester", "-d", domain, "-b", "google,bing", "-l", "200")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("theHarvester failed: %w, output: %s", err, string(output))
	}

	// Parse output (simplified)
	lines := strings.Split(string(output), "\n")
	results := map[string][]string{
		"emails":     {},
		"subdomains": {},
	}
	for _, line := range lines {
		if strings.Contains(line, "@") {
			results["emails"] = append(results["emails"], line)
		} else if strings.Contains(line, domain) && !strings.HasPrefix(line, "Searching") {
			results["subdomains"] = append(results["subdomains"], line)
		}
	}
	return results, nil
}

func (t *TheHarvesterTool) Name() string {
	return "theharvester"
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

	logger := log.New(io.MultiWriter(os.Stdout, logFile), "AGENT: ", log.LstdFlags|log.Lshortfile)

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

	// Register tools
	agent.tools["sherlock"] = &SherlockTool{}
	agent.tools["nmap_scan"] = &NmapTool{}
	agent.tools["geolocate_ip"] = &GeoLocateTool{client: &http.Client{Timeout: 10 * time.Second}}
	agent.tools["theharvester"] = &TheHarvesterTool{}

	return agent, nil
}

func loadAgentConfig(configPath string, logger *log.Logger) (*AgentConfig, error) {
	var config AgentConfig
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		config.Agent.Host = "localhost"
		config.Agent.Port = 9443
		config.Agent.ServerHost = "localhost"
		config.Agent.ServerPort = 8443
		config.Agent.SSL.CertPath = "certs/agent.crt"
		config.Agent.SSL.KeyPath = "certs/agent.key"
		config.Agent.SSL.CAPath = "certs/ca.crt"
		config.Settings.ReconnectInterval = 10
		config.Settings.JobTimeout = 300
		config.Settings.HeartbeatInterval = 30

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
		return fmt.Errorf("failed to load agent certificates: %w", err)
	}

	a.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS13,
	}
	return nil
}

func (a *OSINTAgent) connectToServer() error {
	a.connMutex.Lock()
	defer a.connMutex.Unlock()

	if a.conn != nil {
		a.conn.Close()
	}

	dialer := websocket.Dialer{TLSClientConfig: a.tlsConfig}
	url := fmt.Sprintf("wss://%s:%d/agent", a.config.Agent.ServerHost, a.config.Agent.ServerPort)
	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	a.conn = conn
	a.logger.Printf("Connected to OSINT Server at %s", url)

	// Register agent
	cmd := CommandRequest{
		Command: "register_agent",
		Args: map[string]interface{}{
			"address":      a.config.Agent.Host,
			"port":         float64(a.config.Agent.Port),
			"capabilities": listTools(a.tools),
		},
	}
	if err := conn.WriteJSON(cmd); err != nil {
		return fmt.Errorf("failed to send register command: %w", err)
	}

	var resp CommandResponse
	if err := conn.ReadJSON(&resp); err != nil {
		return fmt.Errorf("failed to read registration response: %w", err)
	}
	if resp.Status != "success" {
		return fmt.Errorf("registration failed: %s", resp.Message)
	}
	if data, ok := resp.Data.(map[string]interface{}); ok {
		if agentID, ok := data["agent_id"].(string); ok {
			a.config.Agent.ID = agentID
			a.logger.Printf("Registered with ID: %s", agentID)
		}
	}
	return nil
}

func listTools(tools map[string]Tool) []string {
	capabilities := make([]string, 0, len(tools))
	for name := range tools {
		capabilities = append(capabilities, name)
	}
	return capabilities
}

func (a *OSINTAgent) handleRunTool(cmd CommandRequest) CommandResponse {
	toolName, ok := cmd.Args["tool"].(string)
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
		ID:         cmd.JobID,
		Tool:       toolName,
		Parameters: cmd.Args,
		Cancel:     cancel,
	}

	a.jobsMutex.Lock()
	a.jobs[cmd.JobID] = job
	a.jobsMutex.Unlock()

	resultChan := make(chan interface{}, 1)
	errChan := make(chan error, 1)

	go func() {
		result, err := tool.Run(cmd.Args)
		if err != nil {
			errChan <- err
		} else {
			resultChan <- result
		}
	}()

	select {
	case result := <-resultChan:
		a.jobsMutex.Lock()
		delete(a.jobs, cmd.JobID)
		a.jobsMutex.Unlock()
		return CommandResponse{Status: "success", Data: map[string]interface{}{
			"job_id":  cmd.JobID,
			"results": result,
		}}
	case err := <-errChan:
		a.jobsMutex.Lock()
		delete(a.jobs, cmd.JobID)
		a.jobsMutex.Unlock()
		return CommandResponse{Status: "error", Message: err.Error()}
	case <-ctx.Done():
		a.jobsMutex.Lock()
		delete(a.jobs, cmd.JobID)
		a.jobsMutex.Unlock()
		return CommandResponse{Status: "error", Message: "Job timed out"}
	}
}

func (a *OSINTAgent) handleCancelJob(cmd CommandRequest) CommandResponse {
	jobID, ok := cmd.Args["job_id"].(string)
	if !ok {
		return CommandResponse{Status: "error", Message: "Missing or invalid job_id"}
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

func (a *OSINTAgent) sendHeartbeat() {
	ticker := time.NewTicker(time.Duration(a.config.Settings.HeartbeatInterval) * time.Second)
	defer ticker.Stop()

	for a.running {
		select {
		case <-ticker.C:
			resp := CommandResponse{
				Status: "success",
				Data: map[string]interface{}{
					"agent_id": a.config.Agent.ID,
					"status":   "online",
					"jobs":     len(a.jobs),
					"uptime":   time.Now().Unix(),
				},
			}
			a.connMutex.Lock()
			if a.conn != nil {
				if err := a.conn.WriteJSON(resp); err != nil {
					a.logger.Printf("Heartbeat failed: %v", err)
				} else {
					a.logger.Println("Sent heartbeat")
				}
			}
			a.connMutex.Unlock()
		}
	}
}

func (a *OSINTAgent) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelFunc = cancel
	a.running = true

	// Connect to OSINT Server
	go func() {
		for a.running {
			if err := a.connectToServer(); err != nil {
				a.logger.Printf("Connection failed: %v", err)
				time.Sleep(time.Duration(a.config.Settings.ReconnectInterval) * time.Second)
				continue
			}

			// Start heartbeat
			go a.sendHeartbeat()

			// Handle commands
			for a.running && a.conn != nil {
				var cmd CommandRequest
				if err := a.conn.ReadJSON(&cmd); err != nil {
					a.logger.Printf("Error reading command: %v", err)
					break
				}
				a.logger.Printf("Received command: %v", cmd)

				var resp CommandResponse
				switch cmd.Command {
				case "run_tool":
					resp = a.handleRunTool(cmd)
				case "cancel_job":
					resp = a.handleCancelJob(cmd)
				default:
					resp = CommandResponse{Status: "error", Message: "Unknown command"}
				}

				a.connMutex.Lock()
				if a.conn != nil {
					if err := a.conn.WriteJSON(resp); err != nil {
						a.logger.Printf("Failed to send response: %v", err)
					}
				}
				a.connMutex.Unlock()
			}

			if a.running {
				time.Sleep(time.Duration(a.config.Settings.ReconnectInterval) * time.Second)
			}
		}
	}()

	a.logger.Printf("OSINT Agent v%s started", VERSION)
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	<-shutdown
	a.Stop()
	return nil
}

func (a *OSINTAgent) Stop() {
	a.logger.Printf("Stopping OSINT Agent...")
	a.running = false
	if a.cancelFunc != nil {
		a.cancelFunc()
	}
	a.connMutex.Lock()
	if a.conn != nil {
		a.conn.Close()
		a.conn = nil
	}
	a.connMutex.Unlock()
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
