//go:build !js

package monitor

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

var nativeWebhookClient = &http.Client{
	Timeout: 8 * time.Second,
}

func defaultWebhookPost(urlClean string, body []byte) error {
	return postWebhookWithHeaders(context.Background(), urlClean, body, nil)
}

func postWebhookWithHeaders(ctx context.Context, urlClean string, body []byte, extraHeaders map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlClean, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "ServerNeedSafe-Monitor/2.0")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := nativeWebhookClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		msg := strings.TrimSpace(string(snippet))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("Webhook HTTP %d: %s", resp.StatusCode, msg)
	}
	return nil
}

// detectWebhookPlatform infers the target bot protocol from the webhook URL hostname.
func detectWebhookPlatform(urlClean string) string {
	u, err := url.Parse(urlClean)
	if err != nil {
		return "generic"
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case strings.Contains(host, "feishu.cn") || strings.Contains(host, "larksuite.com"):
		return "feishu"
	case strings.Contains(host, "dingtalk.com"):
		return "dingtalk"
	case strings.Contains(host, "weixin.qq.com"):
		return "wecom"
	default:
		return "generic"
	}
}

func formatAlertNotificationBodies(triggered, resolved []vault.MonitorAlert) (title, summaryText, markdownText, feishuColor string) {
	hasCrit := false
	for _, a := range triggered {
		if a.Severity == vault.SeverityCritical {
			hasCrit = true
			break
		}
	}
	switch {
	case hasCrit:
		title = fmt.Sprintf("ServerNeedSafe · 严重监控告警 (%d 条)", len(triggered))
		feishuColor = "red"
	case len(triggered) > 0:
		title = fmt.Sprintf("ServerNeedSafe · 监控预警 (%d 条)", len(triggered))
		feishuColor = "orange"
	default:
		title = fmt.Sprintf("ServerNeedSafe · 告警恢复通知 (%d 条)", len(resolved))
		feishuColor = "green"
	}

	var plainLines []string
	var md strings.Builder
	md.WriteString(fmt.Sprintf("### %s\n", title))
	md.WriteString(fmt.Sprintf("- **时间**：%s\n", time.Now().Local().Format("2006-01-02 15:04:05")))

	if len(triggered) > 0 {
		plainLines = append(plainLines, fmt.Sprintf("【触发/升级告警 %d 条】", len(triggered)))
		md.WriteString(fmt.Sprintf("\n**触发/升级告警 (%d 条)**：\n", len(triggered)))
		for _, a := range triggered {
			sev := strings.ToUpper(string(a.Severity))
			plainLines = append(plainLines, fmt.Sprintf("- [%s] %s (%s)", sev, a.Title, a.Detail))
			md.WriteString(fmt.Sprintf("- **[%s]** %s — %s\n", sev, a.Title, a.Detail))
		}
	}
	if len(resolved) > 0 {
		plainLines = append(plainLines, fmt.Sprintf("【恢复通知 %d 条】", len(resolved)))
		md.WriteString(fmt.Sprintf("\n**恢复通知 (%d 条)**：\n", len(resolved)))
		for _, a := range resolved {
			plainLines = append(plainLines, fmt.Sprintf("- [RESOLVED] %s", a.Title))
			md.WriteString(fmt.Sprintf("- **[已恢复]** %s\n", a.Title))
		}
	}

	summaryText = "ServerNeedSafe 服务器监控通知\n" + strings.Join(plainLines, "\n")
	markdownText = md.String()
	return title, summaryText, markdownText, feishuColor
}

// buildMonitorWebhookPayload formats a platform-compliant JSON payload for Feishu, DingTalk, WeCom, or generic webhooks.
func buildMonitorWebhookPayload(platform, title, summaryText, markdownText, feishuColor string, triggered, resolved []vault.MonitorAlert) ([]byte, error) {
	switch platform {
	case "feishu":
		payload := map[string]any{
			"msg_type": "interactive",
			"card": map[string]any{
				"header": map[string]any{
					"title": map[string]any{
						"tag":     "plain_text",
						"content": title,
					},
					"template": feishuColor,
				},
				"elements": []map[string]any{
					{
						"tag":     "markdown",
						"content": markdownText,
					},
				},
			},
		}
		return json.Marshal(payload)

	case "dingtalk":
		payload := map[string]any{
			"msgtype": "markdown",
			"markdown": map[string]string{
				"title": title,
				"text":  markdownText,
			},
		}
		return json.Marshal(payload)

	case "wecom":
		payload := map[string]any{
			"msgtype": "markdown",
			"markdown": map[string]string{
				"content": markdownText,
			},
		}
		return json.Marshal(payload)

	default:
		payload := map[string]any{
			"source":          "ServerNeedSafe",
			"event":           "monitor.alert",
			"timestamp":       time.Now().UTC().Format(time.RFC3339),
			"triggered_count": len(triggered),
			"resolved_count":  len(resolved),
			"triggered":       triggered,
			"resolved":        resolved,
			"title":           title,
			"text":            summaryText,
			"markdown":        markdownText,
			"msg_type":        "text",
			"content": map[string]string{
				"text": summaryText,
			},
		}
		return json.Marshal(payload)
	}
}

// sendSignedWebhookChannel delivers a monitor alert notification to a configured WebhookChannel (reusing AI patrol channels).
func sendSignedWebhookChannel(
	ctx context.Context,
	ch vault.WebhookChannel,
	title, summaryText, markdownText, feishuColor string,
	triggered, resolved []vault.MonitorAlert,
) error {
	targetURL := strings.TrimSpace(ch.URL)
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		return fmt.Errorf("无效的 Webhook URL")
	}

	kind := strings.ToLower(strings.TrimSpace(ch.Kind))
	if kind == "" {
		kind = detectWebhookPlatform(targetURL)
	}

	var bodyBytes []byte
	var err error
	headers := map[string]string{}

	switch kind {
	case "feishu":
		payload := map[string]any{
			"msg_type": "interactive",
			"card": map[string]any{
				"header": map[string]any{
					"title": map[string]any{
						"tag":     "plain_text",
						"content": title,
					},
					"template": feishuColor,
				},
				"elements": []map[string]any{
					{
						"tag":     "markdown",
						"content": markdownText,
					},
				},
			},
		}
		if ch.Secret != "" {
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			strToSign := ts + "\n" + ch.Secret
			mac := hmac.New(sha256.New, []byte(strToSign))
			payload["timestamp"] = ts
			payload["sign"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))
		}
		bodyBytes, err = json.Marshal(payload)

	case "dingtalk":
		if ch.Secret != "" {
			ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
			strToSign := ts + "\n" + ch.Secret
			mac := hmac.New(sha256.New, []byte(ch.Secret))
			_, _ = mac.Write([]byte(strToSign))
			sign := url.QueryEscape(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
			sep := "?"
			if strings.Contains(targetURL, "?") {
				sep = "&"
			}
			targetURL = fmt.Sprintf("%s%stimestamp=%s&sign=%s", targetURL, sep, ts, sign)
		}
		bodyBytes, err = buildMonitorWebhookPayload("dingtalk", title, summaryText, markdownText, feishuColor, triggered, resolved)

	case "wecom":
		bodyBytes, err = buildMonitorWebhookPayload("wecom", title, summaryText, markdownText, feishuColor, triggered, resolved)

	default:
		bodyBytes, err = buildMonitorWebhookPayload("generic", title, summaryText, markdownText, feishuColor, triggered, resolved)
		if err == nil && ch.Secret != "" {
			mac := hmac.New(sha256.New, []byte(ch.Secret))
			_, _ = mac.Write(bodyBytes)
			headers["X-SNS-Signature"] = "sha256=" + hex.EncodeToString(mac.Sum(nil))
		}
	}

	if err != nil {
		return err
	}
	return postWebhookWithHeaders(ctx, targetURL, bodyBytes, headers)
}
