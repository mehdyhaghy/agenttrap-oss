package digest

import (
	"errors"
	"fmt"

	"github.com/mailjet/mailjet-apiv3-go/v4"
)

// Mail sends the digest through Mailjet's Send API (HTTPS), which also avoids
// cloud providers' blocks on outbound SMTP ports.
type Mail struct {
	APIKey    string // Mailjet API key (public)
	SecretKey string // Mailjet secret key
	From      string // validated sender, e.g. admin@demogpu.example
	FromName  string
	To        string
	ReplyTo   string // optional reply address (e.g. a contact form submitter)
	BaseURL   string // optional, for tests
}

// Send delivers a message with text and HTML parts.
func (m Mail) Send(subject, text, htmlBody string) error {
	if m.APIKey == "" || m.SecretKey == "" {
		return errors.New("mailjet: API key and secret key are required")
	}
	var mj *mailjet.Client
	if m.BaseURL != "" {
		mj = mailjet.NewMailjetClient(m.APIKey, m.SecretKey, m.BaseURL)
	} else {
		mj = mailjet.NewMailjetClient(m.APIKey, m.SecretKey)
	}
	info := mailjet.InfoMessagesV31{
		From:     &mailjet.RecipientV31{Email: m.From, Name: m.FromName},
		To:       &mailjet.RecipientsV31{{Email: m.To}},
		Subject:  subject,
		TextPart: text,
		HTMLPart: htmlBody,
		CustomID: "agenttrap",
	}
	if m.ReplyTo != "" {
		info.ReplyTo = &mailjet.RecipientV31{Email: m.ReplyTo}
	}
	msgs := mailjet.MessagesV31{Info: []mailjet.InfoMessagesV31{info}}
	res, err := mj.SendMailV31(&msgs)
	if err != nil {
		return fmt.Errorf("mailjet: %w", err)
	}
	if len(res.ResultsV31) == 0 || res.ResultsV31[0].Status != "success" {
		return fmt.Errorf("mailjet: unexpected result %+v", res)
	}
	return nil
}
