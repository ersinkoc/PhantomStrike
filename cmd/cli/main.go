package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/term"
)

const (
	version   = "1.0.0"
	configDir = ".phantomstrike"
	configFile = "config.json"
)

// Config holds CLI configuration
type Config struct {
	ServerURL    string `json:"server_url"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	DefaultFormat string `json:"default_format"` // table or json
}

// Client is the API client for CLI
type Client struct {
	config     *Config
	httpClient *http.Client
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	client := &Client{
		config:     cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "version", "-v", "--version":
		fmt.Printf("PhantomStrike CLI v%s\n", version)
	case "login":
		handleLogin(client, args)
	case "logout":
		handleLogout(client)
	case "config":
		handleConfig(client, args)
	case "missions", "m":
		handleMissions(client, args)
	case "vulns", "v":
		handleVulns(client, args)
	case "tools", "t":
		handleTools(client, args)
	case "dashboard", "d":
		handleDashboard(client)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`PhantomStrike CLI - AI-Native Security Testing Platform

Usage:
  pscli <command> [args...]

Commands:
  login                           Authenticate with the server
  logout                          Clear authentication
  config                          Manage configuration
  missions, m                     Mission operations
  vulns, v                        Vulnerability operations
  tools, t                        Tool operations
  dashboard, d                    Show dashboard overview
  version                         Show version
  help                            Show this help

Mission Commands:
  pscli missions list             List all missions
  pscli missions get <id>         Get mission details
  pscli missions create           Create a new mission (interactive)
  pscli missions start <id>       Start a mission
  pscli missions pause <id>       Pause a mission
  pscli missions cancel <id>      Cancel a mission
  pscli missions logs <id>        Stream mission logs (real-time)

Vulnerability Commands:
  pscli vulns list                List vulnerabilities
  pscli vulns get <id>            Get vulnerability details

Tool Commands:
  pscli tools list                List available tools
  pscli tools get <name>          Get tool details

Config Commands:
  pscli config set-server <url>   Set server URL
  pscli config get-server         Show current server URL

Examples:
  pscli login
  pscli missions list
  pscli missions create
  pscli vulns list
  pscli dashboard
`)
}

// --- Config Management ---

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, configDir, configFile)
}

func loadConfig() (*Config, error) {
	path := configPath()
	cfg := &Config{
		ServerURL:     "http://localhost:8080",
		DefaultFormat: "table",
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}

func saveConfig(cfg *Config) error {
	path := configPath()
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// --- API Client Methods ---

func (c *Client) request(method, path string, body interface{}) (*http.Response, error) {
	url := c.config.ServerURL + "/api/v1" + path

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.Token)
	}

	return c.httpClient.Do(req)
}

func (c *Client) get(path string) (map[string]interface{}, error) {
	resp, err := c.request("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("unauthorized: please login first")
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed: %s", string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) post(path string, body interface{}) (map[string]interface{}, error) {
	resp, err := c.request("POST", path, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("unauthorized: please login first")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed: %s", string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// --- Command Handlers ---

func handleLogin(c *Client, args []string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Email: ")
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)

	fmt.Print("Password: ")
	passwordBytes, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	password := string(passwordBytes)

	resp, err := c.post("/auth/login", map[string]string{
		"email":    email,
		"password": password,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
		os.Exit(1)
	}

	token, _ := resp["token"].(string)
	refreshToken, _ := resp["refresh_token"].(string)

	if token == "" {
		fmt.Fprintf(os.Stderr, "Login failed: no token received\n")
		os.Exit(1)
	}

	c.config.Token = token
	c.config.RefreshToken = refreshToken

	if err := saveConfig(c.config); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Login successful!")
}

func handleLogout(c *Client) {
	c.config.Token = ""
	c.config.RefreshToken = ""

	if err := saveConfig(c.config); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Logged out successfully")
}

func handleConfig(c *Client, args []string) {
	if len(args) == 0 {
		fmt.Printf("Server URL: %s\n", c.config.ServerURL)
		fmt.Printf("Default Format: %s\n", c.config.DefaultFormat)
		return
	}

	switch args[0] {
	case "set-server":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: pscli config set-server <url>")
			os.Exit(1)
		}
		c.config.ServerURL = strings.TrimSuffix(args[1], "/")
		if err := saveConfig(c.config); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Server URL set to: %s\n", c.config.ServerURL)

	case "get-server":
		fmt.Printf("Server URL: %s\n", c.config.ServerURL)

	case "set-format":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: pscli config set-format <table|json>")
			os.Exit(1)
		}
		format := args[1]
		if format != "table" && format != "json" {
			fmt.Fprintln(os.Stderr, "Format must be 'table' or 'json'")
			os.Exit(1)
		}
		c.config.DefaultFormat = format
		if err := saveConfig(c.config); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Default format set to: %s\n", c.config.DefaultFormat)

	default:
		fmt.Fprintf(os.Stderr, "Unknown config command: %s\n", args[0])
		os.Exit(1)
	}
}

// --- Mission Commands ---

func handleMissions(c *Client, args []string) {
	if len(args) == 0 {
		// Default: list missions
		listMissions(c)
		return
	}

	switch args[0] {
	case "list", "ls":
		listMissions(c)
	case "get", "show":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: pscli missions get <id>")
			os.Exit(1)
		}
		getMission(c, args[1])
	case "create", "new":
		createMission(c)
	case "start":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: pscli missions start <id>")
			os.Exit(1)
		}
		missionAction(c, args[1], "start")
	case "pause":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: pscli missions pause <id>")
			os.Exit(1)
		}
		missionAction(c, args[1], "pause")
	case "cancel":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: pscli missions cancel <id>")
			os.Exit(1)
		}
		missionAction(c, args[1], "cancel")
	case "logs", "stream":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: pscli missions logs <id>")
			os.Exit(1)
		}
		streamMissionLogs(c, args[1])
	default:
		fmt.Fprintf(os.Stderr, "Unknown mission command: %s\n", args[0])
		os.Exit(1)
	}
}

func listMissions(c *Client) {
	resp, err := c.get("/missions?limit=20")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	missions, _ := resp["missions"].([]interface{})
	if len(missions) == 0 {
		fmt.Println("No missions found")
		return
	}

	// Print table header
	fmt.Printf("%-36s %-20s %-10s %-10s %-8s %s\n", "ID", "NAME", "STATUS", "MODE", "PROG", "CREATED")
	fmt.Println(strings.Repeat("-", 100))

	for _, m := range missions {
		mission := m.(map[string]interface{})
		id := mission["id"]
		name := truncate(mission["name"].(string), 20)
		status := mission["status"]
		mode := mission["mode"]
		progress := int(mission["progress"].(float64))
		created := formatTime(mission["created_at"])

		fmt.Printf("%-36s %-20s %-10s %-10s %-7d%% %s\n", id, name, status, mode, progress, created)
	}
}

func getMission(c *Client, id string) {
	resp, err := c.get("/missions/" + id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	printJSON(resp)
}

func createMission(c *Client) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Mission Name: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)

	fmt.Print("Description (optional): ")
	desc, _ := reader.ReadString('\n')
	desc = strings.TrimSpace(desc)

	fmt.Print("Mode (autonomous/guided/manual) [autonomous]: ")
	mode, _ := reader.ReadString('\n')
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "autonomous"
	}

	fmt.Print("Depth (quick/standard/deep/exhaustive) [standard]: ")
	depth, _ := reader.ReadString('\n')
	depth = strings.TrimSpace(depth)
	if depth == "" {
		depth = "standard"
	}

	fmt.Println("Target Scope (one per line, empty line to finish):")
	var scope []string
	for {
		fmt.Print("> ")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		scope = append(scope, line)
	}

	payload := map[string]interface{}{
		"name":        name,
		"description": desc,
		"mode":        mode,
		"depth":       depth,
		"target": map[string]interface{}{
			"scope": scope,
		},
	}

	resp, err := c.post("/missions", payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating mission: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Mission created successfully!")
	printJSON(resp)
}

func missionAction(c *Client, id, action string) {
	resp, err := c.post("/missions/"+id+"/"+action, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Mission %s: %s\n", action, id)
	printJSON(resp)
}

func streamMissionLogs(c *Client, missionID string) {
	// Get token for WebSocket
	token := c.config.Token
	if token == "" {
		fmt.Fprintln(os.Stderr, "Not authenticated")
		os.Exit(1)
	}

	wsURL := strings.Replace(c.config.ServerURL, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = wsURL + "/ws?token=" + token

	fmt.Printf("Connecting to mission stream: %s\n", missionID)
	fmt.Println("Press Ctrl+C to exit")
	fmt.Println(strings.Repeat("-", 80))

	// For now, poll the mission endpoint as a fallback
	// Full WebSocket implementation would require gorilla/websocket
	for {
		resp, err := c.get("/missions/" + missionID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		status, _ := resp["status"].(string)
		fmt.Printf("\rStatus: %-15s Progress: %d%%", status, int(resp["progress"].(float64)))

		if status == "completed" || status == "cancelled" || status == "failed" {
			fmt.Println("\nMission finished")
			break
		}

		time.Sleep(2 * time.Second)
	}
}

// --- Vulnerability Commands ---

func handleVulns(c *Client, args []string) {
	if len(args) == 0 {
		listVulns(c, "")
		return
	}

	switch args[0] {
	case "list", "ls":
		severity := ""
		if len(args) > 1 {
			severity = args[1]
		}
		listVulns(c, severity)
	case "get", "show":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: pscli vulns get <id>")
			os.Exit(1)
		}
		getVuln(c, args[1])
	default:
		fmt.Fprintf(os.Stderr, "Unknown vuln command: %s\n", args[0])
		os.Exit(1)
	}
}

func listVulns(c *Client, severity string) {
	path := "/vulnerabilities?limit=50"
	if severity != "" {
		path = path + "&severity=" + severity
	}

	resp, err := c.get(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	vulns, _ := resp["vulnerabilities"].([]interface{})
	if len(vulns) == 0 {
		fmt.Println("No vulnerabilities found")
		return
	}

	// Print table
	fmt.Printf("%-36s %-30s %-10s %-8s %s\n", "ID", "TITLE", "SEVERITY", "STATUS", "CREATED")
	fmt.Println(strings.Repeat("-", 100))

	for _, v := range vulns {
		vuln := v.(map[string]interface{})
		id := vuln["id"]
		title := truncate(vuln["title"].(string), 30)
		sev := vuln["severity"]
		status := vuln["status"]
		created := formatTime(vuln["created_at"])

		fmt.Printf("%-36s %-30s %-10s %-8s %s\n", id, title, sev, status, created)
	}
}

func getVuln(c *Client, id string) {
	resp, err := c.get("/vulnerabilities/" + id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	printJSON(resp)
}

// --- Tool Commands ---

func handleTools(c *Client, args []string) {
	if len(args) == 0 {
		listTools(c)
		return
	}

	switch args[0] {
	case "list", "ls":
		listTools(c)
	case "get", "show":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: pscli tools get <name>")
			os.Exit(1)
		}
		getTool(c, args[1])
	default:
		fmt.Fprintf(os.Stderr, "Unknown tool command: %s\n", args[0])
		os.Exit(1)
	}
}

func listTools(c *Client) {
	resp, err := c.get("/tools")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	tools, _ := resp["tools"].([]interface{})
	if len(tools) == 0 {
		fmt.Println("No tools found")
		return
	}

	// Group by category
	byCategory := make(map[string][]map[string]interface{})
	for _, t := range tools {
		tool := t.(map[string]interface{})
		cat := tool["category"]
		catStr := ""
		if cat != nil {
			catStr = cat.(string)
			parts := strings.Split(catStr, "/")
			catStr = parts[0]
		}
		byCategory[catStr] = append(byCategory[catStr], tool)
	}

	// Print by category
	for cat, catTools := range byCategory {
		fmt.Printf("\n[%s]\n", strings.ToUpper(cat))
		fmt.Println(strings.Repeat("-", 60))
		for _, tool := range catTools {
			name := tool["name"]
			enabled := tool["enabled"].(bool)
			status := "✓"
			if !enabled {
				status = "✗"
			}
			fmt.Printf("  %s %-30s\n", status, name)
		}
	}
	fmt.Println()
}

func getTool(c *Client, name string) {
	resp, err := c.get("/tools/" + name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	printJSON(resp)
}

// --- Dashboard ---

func handleDashboard(c *Client) {
	// Get stats
	stats, err := c.get("/vulnerabilities/stats")
	if err != nil {
		stats = map[string]interface{}{}
	}

	missions, err := c.get("/missions?limit=5")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║              PHANTOMSTRIKE DASHBOARD                       ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Stats
	fmt.Println("[VULNERABILITY STATISTICS]")
	fmt.Printf("  Total:    %d\n", intValue(stats["total"]))
	fmt.Printf("  Critical: %d  High: %d  Medium: %d  Low: %d  Info: %d\n",
		intValue(stats["critical"]), intValue(stats["high"]),
		intValue(stats["medium"]), intValue(stats["low"]), intValue(stats["info"]))
	fmt.Println()

	// Recent missions
	fmt.Println("[RECENT MISSIONS]")
	missionList, _ := missions["missions"].([]interface{})
	if len(missionList) == 0 {
		fmt.Println("  No missions")
	} else {
		for _, m := range missionList {
			mission := m.(map[string]interface{})
			name := mission["name"]
			status := mission["status"]
			progress := int(mission["progress"].(float64))
			fmt.Printf("  • %-30s [%s] %d%%\n", name, status, progress)
		}
	}
	fmt.Println()
}

// --- Helpers ---

func printJSON(data interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(data)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func formatTime(t interface{}) string {
	if t == nil {
		return "N/A"
	}
	ts, ok := t.(string)
	if !ok {
		return "N/A"
	}
	// Parse and format
	if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
		return parsed.Format("Jan %d %H:%M")
	}
	return ts[:16] // Fallback: truncate to reasonable length
}

func intValue(v interface{}) int {
	if v == nil {
		return 0
	}
	switch v := v.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(v)
		return n
	}
	return 0
}

// ValidateUUID checks if a string is a valid UUID
func validateUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}
