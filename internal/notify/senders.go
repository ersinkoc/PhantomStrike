package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"strings"
	"time"
)

// httpClient is the shared HTTP client for all senders.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// --- SlackSender ---

// SlackSender posts notifications to a Slack incoming webhook URL.
type SlackSender struct {
	webhookURL string
}

// NewSlackSender creates a new Slack sender.
func NewSlackSender(webhookURL string) *SlackSender {
	return &SlackSender{webhookURL: webhookURL}
}

func (s *SlackSender) Type() string { return "slack" }

func (s *SlackSender) Send(ctx context.Context, event Event) error {
	color := "#36a64f" // green
	switch event.Severity {
	case "critical":
		color = "#ff0000"
	case "high":
		color = "#ff6600"
	case "medium":
		color = "#ff9900"
	case "low":
		color = "#ffcc00"
	}

	payload := map[string]any{
		"text": fmt.Sprintf("[%s] %s", event.Severity, event.Title),
		"blocks": []map[string]any{
			{
				"type": "header",
				"text": map[string]any{
					"type": "plain_text",
					"text": event.Title,
				},
			},
			{
				"type": "section",
				"text": map[string]any{
					"type": "mrkdwn",
					"text": event.Message,
				},
			},
			{
				"type": "context",
				"elements": []map[string]any{
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Type:* %s | *Severity:* %s | *Mission:* %s",
							event.Type, event.Severity, event.MissionID),
					},
				},
			},
		},
		"attachments": []map[string]any{
			{
				"color":    color,
				"fallback": event.Message,
			},
		},
	}

	return postJSON(ctx, s.webhookURL, payload)
}

// --- DiscordSender ---

// DiscordSender posts notifications to a Discord webhook URL.
type DiscordSender struct {
	webhookURL string
}

// NewDiscordSender creates a new Discord sender.
func NewDiscordSender(webhookURL string) *DiscordSender {
	return &DiscordSender{webhookURL: webhookURL}
}

func (d *DiscordSender) Type() string { return "discord" }

func (d *DiscordSender) Send(ctx context.Context, event Event) error {
	color := 3066993 // green
	switch event.Severity {
	case "critical":
		color = 16711680 // red
	case "high":
		color = 16744192 // orange-red
	case "medium":
		color = 16753920 // orange
	case "low":
		color = 16776960 // yellow
	}

	payload := map[string]any{
		"content": fmt.Sprintf("**[%s]** %s", event.Severity, event.Title),
		"embeds": []map[string]any{
			{
				"title":       event.Title,
				"description": event.Message,
				"color":       color,
				"fields": []map[string]any{
					{"name": "Type", "value": event.Type, "inline": true},
					{"name": "Severity", "value": event.Severity, "inline": true},
					{"name": "Mission", "value": event.MissionID, "inline": true},
				},
				"footer": map[string]string{
					"text": "PhantomStrike",
				},
				"timestamp": time.Now().Format(time.RFC3339),
			},
		},
	}

	return postJSON(ctx, d.webhookURL, payload)
}

// --- ConsoleSender ---

// ConsoleSender logs notifications to the structured logger (for development).
type ConsoleSender struct{}

// NewConsoleSender creates a new console sender.
func NewConsoleSender() *ConsoleSender {
	return &ConsoleSender{}
}

func (c *ConsoleSender) Type() string { return "console" }

func (c *ConsoleSender) Send(ctx context.Context, event Event) error {
	slog.Info("notification",
		"type", event.Type,
		"title", event.Title,
		"message", event.Message,
		"severity", event.Severity,
		"mission_id", event.MissionID,
	)
	return nil
}

// --- EmailSender ---

// EmailSender sends notifications via SMTP email.
type EmailSender struct {
	smtpHost   string
	smtpPort   int
	from       string
	username   string
	password   string
	recipients []string
}

// NewEmailSender creates a new email sender.
func NewEmailSender(host string, port int, from, username, password string, recipients []string) *EmailSender {
	return &EmailSender{
		smtpHost:   host,
		smtpPort:   port,
		from:       from,
		username:   username,
		password:   password,
		recipients: recipients,
	}
}

func (e *EmailSender) Type() string { return "email" }

func (e *EmailSender) Send(ctx context.Context, event Event) error {
	if len(e.recipients) == 0 {
		return fmt.Errorf("no recipients configured for email sender")
	}

	subject := fmt.Sprintf("[PhantomStrike] %s: %s", event.Type, event.Title)

	var body strings.Builder
	body.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	body.WriteString(fmt.Sprintf("From: %s\r\n", e.from))
	body.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(e.recipients, ", ")))
	body.WriteString("MIME-Version: 1.0\r\n")
	body.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	body.WriteString("\r\n")
	body.WriteString(event.Message)
	body.WriteString("\r\n\r\n")
	body.WriteString(fmt.Sprintf("Severity: %s\r\n", event.Severity))
	if event.MissionID != "" {
		body.WriteString(fmt.Sprintf("Mission: %s\r\n", event.MissionID))
	}
	body.WriteString("\r\n---\r\nPhantomStrike Security Platform")

	addr := fmt.Sprintf("%s:%d", e.smtpHost, e.smtpPort)
	auth := smtp.PlainAuth("", e.username, e.password, e.smtpHost)

	if err := smtp.SendMail(addr, auth, e.from, e.recipients, []byte(body.String())); err != nil {
		return fmt.Errorf("sending email: %w", err)
	}

	return nil
}

// --- TelegramSender ---

// TelegramSender sends notifications via the Telegram Bot API.
type TelegramSender struct {
	botToken string
	chatID   string
}

// NewTelegramSender creates a new Telegram sender.
func NewTelegramSender(botToken, chatID string) *TelegramSender {
	return &TelegramSender{
		botToken: botToken,
		chatID:   chatID,
	}
}

func (t *TelegramSender) Type() string { return "telegram" }

func (t *TelegramSender) Send(ctx context.Context, event Event) error {
	text := fmt.Sprintf("<b>%s</b>\n%s\nSeverity: %s", event.Title, event.Message, event.Severity)
	if event.MissionID != "" {
		text += fmt.Sprintf("\nMission: %s", event.MissionID)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.botToken)
	payload := map[string]any{
		"chat_id":    t.chatID,
		"text":       text,
		"parse_mode": "HTML",
	}

	return postJSON(ctx, url, payload)
}

// --- postJSON helper ---

// postJSON sends a POST request with a JSON payload and checks the response status.
func postJSON(ctx context.Context, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	return nil
}
