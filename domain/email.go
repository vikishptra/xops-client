package domain

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/gomail.v2"

	"xops-admin/config"
	"xops-admin/model"
)

type EmailData struct {
	Data      string
	FirstName string
	Subject   string
}

func ParseTemplateDir(dir string) (*template.Template, error) {
	var paths []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return template.ParseFiles(paths...)
}

func SendEmail(user *model.User, toEmail string, data *EmailData, file, templatee string) error {
	// Load config
	loadconfig, err := config.LoadConfig(".")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	from := loadconfig.FromEmailAddr
	password := loadconfig.SMTPpwd
	to := toEmail
	host := "smtp.gmail.com"
	port := 587

	// Debug info
	log.Printf("Sending email from: %s to: %s", from, to)
	log.Printf("Using template: %s with file: %s", templatee, file)

	// Parse template
	template, err := ParseTemplateDir(templatee)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Render template to body
	var body bytes.Buffer
	if err = template.ExecuteTemplate(&body, file, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// Debug template content

	// Create new email message
	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", data.Subject)
	m.SetBody("text/html", body.String())

	// Add important headers to improve deliverability
	m.SetHeader("X-Priority", "1") // High priority
	m.SetHeader("X-MSMail-Priority", "High")
	m.SetHeader("Importance", "High")

	// Add a plain text alternative for better deliverability

	// Create dialer with explicit authentication
	d := gomail.NewDialer(host, port, from, password)

	// Configure TLS
	d.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: host,
	}

	// Enable SMTP debugging
	d.SSL = false // Explicitly disable SSL for port 587 (which uses STARTTLS)

	// Add retry logic with better error handling
	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		log.Printf("Attempting to send email (attempt %d of %d)", attempt, maxRetries)

		// Try to send the email with SMTP conversation logging
		var smtpClient gomail.SendCloser
		var err error

		// Try to establish SMTP connection first to better debug issues
		smtpClient, err = d.Dial()
		if err != nil {
			log.Printf("SMTP connection failed: %v", err)

			// Add specific error handling for common issues
			if strings.Contains(err.Error(), "authentication failed") {
				log.Printf("Gmail authentication error - ensure you're using an App Password if 2FA is enabled")
			} else if strings.Contains(err.Error(), "i/o timeout") {
				log.Printf("Connection timeout - check network connectivity and firewall settings")
			}
		} else {
			// Connection succeeded, try to send
			log.Printf("SMTP connection established successfully")
			err = gomail.Send(smtpClient, m)
			smtpClient.Close()

			if err == nil {
				log.Printf("Email sent successfully to %sEmail content preview", to)
				log.Printf("Check Spam/Promotions folders if email is not visible in inbox")
				return nil
			}

			log.Printf("Email sending failed: %v", err)
		}

		// Wait before retrying with exponential backoff
		if attempt < maxRetries {
			backoffTime := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			log.Printf("Retrying in %v seconds", backoffTime.Seconds())
			time.Sleep(backoffTime)
		}
	}

	// All retries failed
	return fmt.Errorf("failed to send email after %d attempts: %w", maxRetries, err)
}

// Helper function to truncate string for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
