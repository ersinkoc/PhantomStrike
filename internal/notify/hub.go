// Package notify provides notification and integration hub functionality.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ChannelType represents a notification channel type.
type ChannelType string

const (
	ChannelTypeEmail     ChannelType = "email"
	ChannelTypeSlack     ChannelType = "slack"
	ChannelTypeDiscord   ChannelType = "discord"
	ChannelTypeTelegram  ChannelType = "telegram"
	ChannelTypeWebhook   ChannelType = "webhook"
	ChannelTypeJira      ChannelType = "jira"
	ChannelTypeGitHub    ChannelType = "github"
	ChannelTypePagerDuty ChannelType = "pagerduty"
	ChannelTypeOpsGenie  ChannelType = "opsgenie"
)

// Notification represents a notification to be sent.
type Notification struct {
	ID        uuid.UUID       `json:"id"`
	Type      string          `json:"type"`
	Title     string          `json:"title"`
	Message   string          `json:"message"`
	Severity  string          `json:"severity"` // info, warning, critical
	Data      json.RawMessage `json:"data,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
	Channels  []string        `json:"channels"`
}

// Channel represents a notification channel configuration.
type Channel struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Type     ChannelType     `json:"type"`
	Enabled  bool            `json:"enabled"`
	Config   json.RawMessage `json:"config"`
	Filters  []string        `json:"filters"` // notification types to send
	Severity []string        `json:"severity"` // min severity level
}

// Hub manages notification channels and sends notifications.
type Hub struct {
	db      *pgxpool.Pool
	client  *http.Client
	channels map[string]*Channel
}

// NewHub creates a new notification hub.
func NewHub(db *pgxpool.Pool) *Hub {
	return &Hub{
		db:       db,
		client:   &http.Client{Timeout: 10 * time.Second},
		channels: make(map[string]*Channel),
	}
}

// LoadChannels loads channel configurations from database.
func (h *Hub) LoadChannels(ctx context.Context) error {
	rows, err := h.db.Query(ctx,
		`SELECT id, name, type, enabled, config, filters, severity FROM notification_channels WHERE enabled = true`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var ch Channel
		if err := rows.Scan(&ch.ID, &ch.Name, &ch.Type, &ch.Enabled, &ch.Config, &ch.Filters, &ch.Severity); err != nil {
			continue
		}
		h.channels[ch.ID] = &ch
	}

	slog.Info("loaded notification channels", "count", len(h.channels))
	return nil
}

// Send sends a notification through configured channels.
func (h *Hub) Send(ctx context.Context, notif *Notification) error {
	// Save notification to database
	if err := h.saveNotification(ctx, notif); err != nil {
		slog.Error("failed to save notification", "error", err)
	}

	// Send to each matching channel
	var lastErr error
	for _, ch := range h.channels {
		if !h.shouldSendToChannel(notif, ch) {
			continue
		}

		if err := h.sendToChannel(ctx, notif, ch); err != nil {
			slog.Error("failed to send notification",
				"channel", ch.Name,
				"error", err)
			lastErr = err
		} else {
			slog.Debug("notification sent",
				"channel", ch.Name,
				"type", notif.Type)
		}
	}

	return lastErr
}

// shouldSendToChannel checks if a notification should be sent to a channel.
func (h *Hub) shouldSendToChannel(notif *Notification, ch *Channel) bool {
	// Check severity
	if len(ch.Severity) > 0 {
		found := false
		for _, s := range ch.Severity {
			if s == notif.Severity {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check filters
	if len(ch.Filters) > 0 {
		found := false
		for _, f := range ch.Filters {
			if f == notif.Type || f == "*" {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// sendToChannel sends a notification to a specific channel.
func (h *Hub) sendToChannel(ctx context.Context, notif *Notification, ch *Channel) error {
	switch ch.Type {
	case ChannelTypeEmail:
		return h.sendEmail(ctx, notif, ch)
	case ChannelTypeSlack:
		return h.sendSlack(ctx, notif, ch)
	case ChannelTypeDiscord:
		return h.sendDiscord(ctx, notif, ch)
	case ChannelTypeTelegram:
		return h.sendTelegram(ctx, notif, ch)
	case ChannelTypeWebhook:
		return h.sendWebhook(ctx, notif, ch)
	case ChannelTypeJira:
		return h.sendJira(ctx, notif, ch)
	case ChannelTypeGitHub:
		return h.sendGitHub(ctx, notif, ch)
	case ChannelTypePagerDuty:
		return h.sendPagerDuty(ctx, notif, ch)
	case ChannelTypeOpsGenie:
		return h.sendOpsGenie(ctx, notif, ch)
	default:
		return fmt.Errorf("unknown channel type: %s", ch.Type)
	}
}

// EmailConfig represents email channel configuration.
type EmailConfig struct {
	SMTPHost     string   `json:"smtp_host"`
	SMTPPort     int      `json:"smtp_port"`
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	From         string   `json:"from"`
	To           []string `json:"to"`
	UseTLS       bool     `json:"use_tls"`
}

func (h *Hub) sendEmail(ctx context.Context, notif *Notification, ch *Channel) error {
	var config EmailConfig
	if err := json.Unmarshal(ch.Config, &config); err != nil {
		return err
	}

	// Build email body
	subject := fmt.Sprintf("[%s] %s", notif.Severity, notif.Title)
	body := fmt.Sprintf("Subject: %s\r\n\r\n%s\r\n\r\n---\r\nPhantomStrike Security Platform",
		subject, notif.Message)

	// Send email
	addr := fmt.Sprintf("%s:%d", config.SMTPHost, config.SMTPPort)
	auth := smtp.PlainAuth("", config.Username, config.Password, config.SMTPHost)

	if err := smtp.SendMail(addr, auth, config.From, config.To, []byte(body)); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// SlackConfig represents Slack channel configuration.
type SlackConfig struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel,omitempty"`
	Username   string `json:"username,omitempty"`
}

func (h *Hub) sendSlack(ctx context.Context, notif *Notification, ch *Channel) error {
	var config SlackConfig
	if err := json.Unmarshal(ch.Config, &config); err != nil {
		return err
	}

	// Build Slack message
	color := "#36a64f" // green
	switch notif.Severity {
	case "warning":
		color = "#ff9900" // orange
	case "critical":
		color = "#ff0000" // red
	}

	payload := map[string]any{
		"text": notif.Title,
		"attachments": []map[string]any{
			{
				"color": color,
				"fields": []map[string]any{
					{"title": "Severity", "value": notif.Severity, "short": true},
					{"title": "Type", "value": notif.Type, "short": true},
					{"title": "Message", "value": notif.Message, "short": false},
				},
				"footer": "PhantomStrike",
				"ts": notif.Timestamp.Unix(),
			},
		},
	}

	if config.Channel != "" {
		payload["channel"] = config.Channel
	}

	return h.postJSON(ctx, config.WebhookURL, payload)
}

// DiscordConfig represents Discord channel configuration.
type DiscordConfig struct {
	WebhookURL string `json:"webhook_url"`
}

func (h *Hub) sendDiscord(ctx context.Context, notif *Notification, ch *Channel) error {
	var config DiscordConfig
	if err := json.Unmarshal(ch.Config, &config); err != nil {
		return err
	}

	color := 3066993 // green
	switch notif.Severity {
	case "warning":
		color = 16753920 // orange
	case "critical":
		color = 16711680 // red
	}

	payload := map[string]any{
		"embeds": []map[string]any{
			{
				"title":       notif.Title,
				"description": notif.Message,
				"color":       color,
				"fields": []map[string]any{
					{"name": "Severity", "value": notif.Severity, "inline": true},
					{"name": "Type", "value": notif.Type, "inline": true},
				},
				"timestamp": notif.Timestamp.Format(time.RFC3339),
				"footer": map[string]string{
					"text": "PhantomStrike",
				},
			},
		},
	}

	return h.postJSON(ctx, config.WebhookURL, payload)
}

// TelegramConfig represents Telegram channel configuration.
type TelegramConfig struct {
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

func (h *Hub) sendTelegram(ctx context.Context, notif *Notification, ch *Channel) error {
	var config TelegramConfig
	if err := json.Unmarshal(ch.Config, &config); err != nil {
		return err
	}

	message := fmt.Sprintf("*%s*\n\n%s\n\nSeverity: %s\nType: %s",
		notif.Title, notif.Message, notif.Severity, notif.Type)

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", config.BotToken)
	payload := map[string]any{
		"chat_id":    config.ChatID,
		"text":       message,
		"parse_mode": "Markdown",
	}

	return h.postJSON(ctx, url, payload)
}

// WebhookConfig represents webhook channel configuration.
type WebhookConfig struct {
	URL     string            `json:"url"`
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

func (h *Hub) sendWebhook(ctx context.Context, notif *Notification, ch *Channel) error {
	var config WebhookConfig
	if err := json.Unmarshal(ch.Config, &config); err != nil {
		return err
	}

	method := config.Method
	if method == "" {
		method = "POST"
	}

	payload := map[string]any{
		"notification": notif,
		"timestamp":    time.Now().Unix(),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, method, config.URL, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// JiraConfig represents Jira channel configuration.
type JiraConfig struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Token    string `json:"token"`
	Project  string `json:"project"`
	IssueType string `json:"issue_type,omitempty"`
}

func (h *Hub) sendJira(ctx context.Context, notif *Notification, ch *Channel) error {
	var config JiraConfig
	if err := json.Unmarshal(ch.Config, &config); err != nil {
		return err
	}

	issueType := config.IssueType
	if issueType == "" {
		issueType = "Bug"
	}

	priority := "Medium"
	switch notif.Severity {
	case "critical":
		priority = "Highest"
	case "high":
		priority = "High"
	}

	payload := map[string]any{
		"fields": map[string]any{
			"project": map[string]string{"key": config.Project},
			"summary": notif.Title,
			"description": notif.Message,
			"issuetype": map[string]string{"name": issueType},
			"priority": map[string]string{"name": priority},
		},
	}

	url := fmt.Sprintf("%s/rest/api/2/issue", config.URL)
	return h.postJSON(ctx, url, payload)
}

// GitHubConfig represents GitHub channel configuration.
type GitHubConfig struct {
	Token     string `json:"token"`
	Owner     string `json:"owner"`
	Repo      string `json:"repo"`
}

func (h *Hub) sendGitHub(ctx context.Context, notif *Notification, ch *Channel) error {
	var config GitHubConfig
	if err := json.Unmarshal(ch.Config, &config); err != nil {
		return err
	}

	// Create GitHub issue
	payload := map[string]any{
		"title":  notif.Title,
		"body":   notif.Message,
		"labels": []string{"security", notif.Severity},
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", config.Owner, config.Repo)

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "token "+config.Token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("github api returned status %d", resp.StatusCode)
	}

	return nil
}

// PagerDutyConfig represents PagerDuty channel configuration.
type PagerDutyConfig struct {
	IntegrationKey string `json:"integration_key"`
	Severity       string `json:"severity,omitempty"`
}

func (h *Hub) sendPagerDuty(ctx context.Context, notif *Notification, ch *Channel) error {
	var config PagerDutyConfig
	if err := json.Unmarshal(ch.Config, &config); err != nil {
		return err
	}

	severity := "warning"
	if notif.Severity == "critical" {
		severity = "critical"
	} else if notif.Severity == "warning" {
		severity = "warning"
	} else {
		severity = "info"
	}

	payload := map[string]any{
		"routing_key":  config.IntegrationKey,
		"event_action": "trigger",
		"payload": map[string]any{
			"summary":   notif.Title,
			"severity":  severity,
			"source":    "phantomstrike",
			"custom_details": map[string]any{
				"message": notif.Message,
				"type":    notif.Type,
			},
		},
	}

	return h.postJSON(ctx, "https://events.pagerduty.com/v2/enqueue", payload)
}

// OpsGenieConfig represents OpsGenie channel configuration.
type OpsGenieConfig struct {
	APIKey string `json:"api_key"`
}

func (h *Hub) sendOpsGenie(ctx context.Context, notif *Notification, ch *Channel) error {
	var config OpsGenieConfig
	if err := json.Unmarshal(ch.Config, &config); err != nil {
		return err
	}

	priority := "P3"
	switch notif.Severity {
	case "critical":
		priority = "P1"
	case "warning":
		priority = "P2"
	}

	payload := map[string]any{
		"message":     notif.Title,
		"description": notif.Message,
		"priority":    priority,
		"tags":        []string{"security", "phantomstrike"},
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.opsgenie.com/v2/alerts", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "GenieKey "+config.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// postJSON sends a POST request with JSON payload.
func (h *Hub) postJSON(ctx context.Context, url string, payload any) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("http error %d", resp.StatusCode)
	}

	return nil
}

// saveNotification saves notification to database.
func (h *Hub) saveNotification(ctx context.Context, notif *Notification) error {
	_, err := h.db.Exec(ctx,
		`INSERT INTO notifications (id, type, title, message, severity, data, timestamp)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		notif.ID, notif.Type, notif.Title, notif.Message,
		notif.Severity, notif.Data, notif.Timestamp)
	return err
}

// Notification Types
const (
	TypeVulnerabilityFound   = "vulnerability.found"
	TypeMissionStarted       = "mission.started"
	TypeMissionCompleted     = "mission.completed"
	TypeMissionFailed        = "mission.failed"
	TypeScanCompleted        = "scan.completed"
	TypeReportGenerated      = "report.generated"
	TypeComplianceViolation  = "compliance.violation"
	TypeToolExecutionFailed  = "tool.failed"
	TypeCriticalVulnerability = "vulnerability.critical"
)
