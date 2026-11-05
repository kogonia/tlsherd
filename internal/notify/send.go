package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"
)

// Settings is global notification channel configuration.
type Settings struct {
	SMTP     SMTPSettings     `json:"smtp"`
	Telegram TelegramSettings `json:"telegram"`
	Worker   WorkerSettings   `json:"worker"`
}

type SMTPSettings struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	TLS      string `json:"tls"` // starttls | tls | none
}

type TelegramSettings struct {
	BotToken string `json:"bot_token"`
}

type WorkerSettings struct {
	Interval    string `json:"interval"`
	Batch       int    `json:"batch"`
	MaxAttempts int    `json:"max_attempts"`
}

// DefaultSettings returns empty channel config with sensible worker defaults.
func DefaultSettings() Settings {
	return Settings{
		SMTP:   SMTPSettings{Port: 587, TLS: "starttls"},
		Worker: WorkerSettings{Interval: "15s", Batch: 50, MaxAttempts: 8},
	}
}

// Message is a rendered notification body.
type Message struct {
	Subject string
	Text    string
	JSON    []byte
}

// EmailConfig is destination config for email.
type EmailConfig struct {
	Address string `json:"address"`
}

// TelegramConfig is destination config for telegram.
type TelegramConfig struct {
	ChatID string `json:"chat_id"`
}

// WebhookConfig is destination config for webhook.
type WebhookConfig struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

// SendEmail delivers msg via SMTP.
func SendEmail(ctx context.Context, cfg SMTPSettings, to string, msg Message) error {
	if cfg.Host == "" || cfg.From == "" || to == "" {
		return fmt.Errorf("smtp not configured")
	}
	port := cfg.Port
	if port == 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", cfg.Host, port)
	body := buildMIME(cfg.From, to, msg.Subject, msg.Text)

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	switch strings.ToLower(cfg.TLS) {
	case "tls":
		return sendSMTPTLS(ctx, addr, cfg.Host, auth, cfg.From, []string{to}, body)
	case "none":
		return smtp.SendMail(addr, auth, cfg.From, []string{to}, body)
	default: // starttls
		return sendSMTPStartTLS(ctx, addr, cfg.Host, auth, cfg.From, []string{to}, body)
	}
}

func buildMIME(from, to, subject, text string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(text)
	return b.Bytes()
}

func sendSMTPStartTLS(ctx context.Context, addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func sendSMTPTLS(ctx context.Context, addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	d := tls.Dialer{Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// SendTelegram delivers text via Bot API.
func SendTelegram(ctx context.Context, botToken, chatID, text string) error {
	if botToken == "" || chatID == "" {
		return fmt.Errorf("telegram not configured")
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	body, _ := json.Marshal(map[string]any{"chat_id": chatID, "text": text})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("telegram status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// SendWebhook POSTs JSON to url with optional HMAC signature.
func SendWebhook(ctx context.Context, url, secret string, payload []byte) error {
	if url == "" {
		return fmt.Errorf("webhook url empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tlsherd-notify/1")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(payload)
		req.Header.Set("X-Tlsherd-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("webhook status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// ChannelConfigured reports whether the global config for channel is usable.
func ChannelConfigured(set Settings, channel string) (bool, string) {
	switch channel {
	case "email":
		if set.SMTP.Host == "" || set.SMTP.From == "" {
			return false, "smtp not configured"
		}
		return true, ""
	case "telegram":
		if set.Telegram.BotToken == "" {
			return false, "telegram bot_token not configured"
		}
		return true, ""
	case "webhook":
		return true, ""
	default:
		return false, "unknown channel"
	}
}
