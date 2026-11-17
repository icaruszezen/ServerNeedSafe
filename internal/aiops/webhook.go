package aiops

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// SendPatrolAlertWebhook dispatches a formatted patrol anomaly summary to a configured WebhookChannel.
func SendPatrolAlertWebhook(ctx context.Context, transport HTTPTransport, ch vault.WebhookChannel, rec vault.PatrolRecord) error {
	if strings.TrimSpace(ch.URL) == "" {
		return fmt.Errorf("Webhook URL 不能为空")
	}
	if transport == nil {
		transport = newDefaultHTTPTransport()
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	statusLabel := "健康"
	switch rec.Status {
	case "critical":
		statusLabel = "严重告警"
	case "warning":
		statusLabel = "风险预警"
	}

	var md strings.Builder
	md.WriteString(fmt.Sprintf("### [ServerNeedSafe] AI 巡检%s\n", statusLabel))
	md.WriteString(fmt.Sprintf("- **巡检时间**：%s\n", rec.CompletedAt.Local().Format("2006-01-02 15:04:05")))
	md.WriteString(fmt.Sprintf("- **主机统计**：共 %d 台（正常 %d · 预警 %d · 严重 %d）\n", rec.TotalServers, rec.HealthyCount, rec.WarningCount, rec.CriticalCount))

	for _, f := range rec.Findings {
		if len(f.Anomalies) == 0 && f.Reachable {
			continue
		}
		md.WriteString(fmt.Sprintf("- **%s (`%s`)**：%s\n", f.ServerName, f.Host, strings.Join(f.Anomalies, "；")))
	}
	if rec.AISummary != "" {
		md.WriteString(fmt.Sprintf("\n**AI 根因研判**：%s\n", rec.AISummary))
	}
	if len(rec.AIRecommendations) > 0 {
		md.WriteString("\n**处置建议（只读巡检未自动变更线上）**：\n")
		for i, r := range rec.AIRecommendations {
			if i >= 4 {
				break
			}
			md.WriteString(fmt.Sprintf("%d. %s\n", i+1, r))
		}
	}
	markdownText := md.String()

	targetURL := strings.TrimSpace(ch.URL)
	var bodyMap any
	var customSig string

	switch ch.Kind {
	case "feishu":
		payload := map[string]any{
			"msg_type": "interactive",
			"card": map[string]any{
				"header": map[string]any{
					"title": map[string]any{
						"tag":     "plain_text",
						"content": fmt.Sprintf("ServerNeedSafe · AI 巡检%s", statusLabel),
					},
					"template": map[string]string{"critical": "red", "warning": "orange", "healthy": "turquoise"}[rec.Status],
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
		bodyMap = payload

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
		bodyMap = map[string]any{
			"msgtype": "markdown",
			"markdown": map[string]string{
				"title": fmt.Sprintf("ServerNeedSafe AI 巡检%s", statusLabel),
				"text":  markdownText,
			},
		}

	case "wecom":
		bodyMap = map[string]any{
			"msgtype": "markdown",
			"markdown": map[string]string{
				"content": markdownText,
			},
		}

	default:
		bodyMap = map[string]any{
			"source":          "ServerNeedSafe",
			"event":           "aiops.patrol_alert",
			"status":          rec.Status,
			"timestamp":       rec.CompletedAt.Format(time.RFC3339),
			"total_servers":   rec.TotalServers,
			"warning_count":   rec.WarningCount,
			"critical_count":  rec.CriticalCount,
			"ai_summary":      rec.AISummary,
			"ai_root_cause":   rec.AIRootCause,
			"recommendations": rec.AIRecommendations,
			"findings":        rec.Findings,
			"markdown":        markdownText,
		}
	}

	rawBody, err := json.Marshal(bodyMap)
	if err != nil {
		return err
	}
	if ch.Kind == "custom" && ch.Secret != "" {
		mac := hmac.New(sha256.New, []byte(ch.Secret))
		_, _ = mac.Write(rawBody)
		customSig = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}
	if customSig != "" {
		headers["X-SNS-Signature"] = customSig
	}

	statusCode, respBody, err := transport.PostJSON(ctx, targetURL, headers, rawBody)
	if err != nil {
		return fmt.Errorf("发送 Webhook 请求失败: %w", err)
	}
	if statusCode >= 400 {
		msg := strings.TrimSpace(string(respBody))
		if len(msg) > 512 {
			msg = msg[:512]
		}
		return fmt.Errorf("Webhook 响应 HTTP %d: %s", statusCode, msg)
	}
	return nil
}
