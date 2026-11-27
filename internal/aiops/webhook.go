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
	if rec.AnalysisState == "pending_external" || rec.AnalysisState == "claimed" {
		md.WriteString("- **AI 研判状态**：原始异常速报（已进入待研判队列，等待外部 AI 通过 MCP 深度取证回写）\n")
	} else if rec.AISource == "external_mcp" && rec.AIAnalyzed {
		srcName := nonEmpty(rec.ExternalClient, "外部 AI (MCP)")
		if rec.AIModel != "" {
			srcName = fmt.Sprintf("%s · %s", srcName, rec.AIModel)
		}
		md.WriteString(fmt.Sprintf("- **AI 研判来源**：外部 AI 接管 (`%s`)\n", srcName))
	} else if rec.AnalysisState == "fallback_completed" && rec.AIAnalyzed {
		md.WriteString(fmt.Sprintf("- **AI 研判来源**：外部 AI 超时未认领，已由内置模型兜底 (`%s`)\n", nonEmpty(rec.AIModel, "内置模型")))
	}

	for _, f := range rec.Findings {
		if len(f.Anomalies) == 0 && f.Reachable {
			continue
		}
		md.WriteString(fmt.Sprintf("- **%s (`%s`)**：%s\n", f.ServerName, f.Host, strings.Join(f.Anomalies, "；")))
	}
	if rec.AISummary != "" {
		md.WriteString(fmt.Sprintf("\n**AI 根因研判**：%s\n", rec.AISummary))
	}
	if rec.AIRootCause != "" {
		md.WriteString(fmt.Sprintf("\n**根因分析**：%s\n", truncateStr(rec.AIRootCause, 600)))
	}
	if len(rec.DeepEvidence) > 0 {
		md.WriteString("\n**深度取证线索**：\n")
		for i, ev := range rec.DeepEvidence {
			if i >= 4 {
				break
			}
			md.WriteString(fmt.Sprintf("- %s\n", ev))
		}
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

	titleText := fmt.Sprintf("ServerNeedSafe · AI 巡检%s", statusLabel)
	if rec.AISource == "external_mcp" && rec.AIAnalyzed {
		titleText = fmt.Sprintf("ServerNeedSafe · %s 深度巡检报告 (%s)", nonEmpty(rec.ExternalClient, "外部 AI"), statusLabel)
	}
	colorTemplate := map[string]string{"critical": "red", "warning": "orange", "healthy": "turquoise"}[rec.Status]
	if colorTemplate == "" {
		colorTemplate = "blue"
	}

	customPayload := map[string]any{
		"source":          "ServerNeedSafe",
		"event":           "aiops.patrol_alert",
		"patrol_id":       rec.ID,
		"status":          rec.Status,
		"analysis_state":  rec.AnalysisState,
		"ai_source":       rec.AISource,
		"external_client": rec.ExternalClient,
		"timestamp":       rec.CompletedAt.Format(time.RFC3339),
		"total_servers":   rec.TotalServers,
		"warning_count":   rec.WarningCount,
		"critical_count":  rec.CriticalCount,
		"ai_summary":      rec.AISummary,
		"ai_root_cause":   rec.AIRootCause,
		"deep_evidence":   rec.DeepEvidence,
		"recommendations": rec.AIRecommendations,
		"findings":        rec.Findings,
		"markdown":        markdownText,
	}

	return sendFormattedWebhook(ctx, transport, ch, titleText, colorTemplate, markdownText, customPayload)
}

// SendExternalApprovalWebhook notifies operators via Webhook when an external MCP AI submits a HITL change plan.
func SendExternalApprovalWebhook(ctx context.Context, transport HTTPTransport, ch vault.WebhookChannel, ap vault.ExternalApproval) error {
	if strings.TrimSpace(ch.URL) == "" {
		return fmt.Errorf("Webhook URL 不能为空")
	}
	if transport == nil {
		transport = newDefaultHTTPTransport()
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	vault.NormalizeExternalApproval(&ap)

	var md strings.Builder
	md.WriteString(fmt.Sprintf("### [ServerNeedSafe] 外部 AI 提交变更审批计划（共 %d 步）\n", ap.TotalSteps))
	md.WriteString(fmt.Sprintf("- **计划标题**：%s\n", nonEmpty(ap.Title, "外部 AI 变更计划")))
	md.WriteString(fmt.Sprintf("- **提交来源**：%s (令牌: `%s`)\n", nonEmpty(ap.ClientName, "外部 MCP AI"), nonEmpty(ap.TokenName, ap.TokenID)))
	if ap.BlockedSteps > 0 {
		md.WriteString(fmt.Sprintf("- **风险提醒**：⚠️ 共 %d 步（可执行 %d 步 · **%d 步触发安全熔断已标红锁定**）\n", ap.TotalSteps, ap.ExecutableSteps, ap.BlockedSteps))
	} else {
		md.WriteString(fmt.Sprintf("- **风险等级**：`%s`（共 %d 步将按序执行）\n", nonEmpty(ap.RiskLevel, "high"), ap.TotalSteps))
	}
	md.WriteString(fmt.Sprintf("- **目标主机**：%s\n", nonEmpty(strings.Join(ap.ServerNames, ", "), strings.Join(ap.ServerIDs, ", "))))
	if ap.PatrolRecordID != "" {
		md.WriteString(fmt.Sprintf("- **关联巡检单**：`%s`\n", ap.PatrolRecordID))
	}
	md.WriteString(fmt.Sprintf("- **变更原因**：%s\n", ap.Reason))

	stepSummaries := make([]map[string]any, 0, len(ap.Steps))
	if len(ap.Steps) > 0 {
		md.WriteString("\n**有序执行步骤清单**：\n")
		for idx, st := range ap.Steps {
			opTag := "SSH"
			detail := truncateStr(st.Command, 140)
			if st.ToolName == "sftp_write_file" {
				opTag = "SFTP"
				detail = st.FilePath
			}
			flags := ""
			if st.Blocked {
				flags += " [已拦截锁定]"
			}
			if st.ContinueOnError {
				flags += " [遇错继续]"
			}
			if idx < 10 {
				md.WriteString(fmt.Sprintf("%d. **[%s]%s** (%s) `%s`\n",
					st.Index, opTag, flags, nonEmpty(strings.Join(st.ServerNames, ","), strings.Join(st.ServerIDs, ",")), detail))
			}
			stepSummaries = append(stepSummaries, map[string]any{
				"id":                st.ID,
				"index":             st.Index,
				"title":             st.Title,
				"tool_name":         st.ToolName,
				"server_ids":        st.ServerIDs,
				"server_names":      st.ServerNames,
				"command":           st.Command,
				"file_path":         st.FilePath,
				"continue_on_error": st.ContinueOnError,
				"blocked":           st.Blocked,
				"blocked_reason":    st.BlockedReason,
				"status":            st.Status,
			})
		}
		if len(ap.Steps) > 10 {
			md.WriteString(fmt.Sprintf("... 其余 %d 步请在 Web 控制台查看完整清单。\n", len(ap.Steps)-10))
		}
	}
	md.WriteString("\n> 该变更计划处于 **等待管理员审批** 状态，尚未在远端服务器执行。请登录 ServerNeedSafe 控制台左侧「执行审批」审阅全部步骤与 Diff 后一键批准按序执行或拒绝。\n")

	markdownText := md.String()
	titleText := fmt.Sprintf("ServerNeedSafe · 待审批外部 AI 变更计划 (%s · %d 步)", nonEmpty(ap.ClientName, "MCP"), ap.TotalSteps)
	color := "orange"
	if ap.BlockedSteps > 0 {
		color = "red"
	}
	customPayload := map[string]any{
		"source":           "ServerNeedSafe",
		"event":            "aiops.external_approval_pending",
		"approval_id":      ap.ID,
		"title":            ap.Title,
		"patrol_record_id": ap.PatrolRecordID,
		"client_name":      ap.ClientName,
		"token_name":       ap.TokenName,
		"tool_name":        ap.ToolName,
		"risk_level":       ap.RiskLevel,
		"server_ids":       ap.ServerIDs,
		"server_names":     ap.ServerNames,
		"reason":           ap.Reason,
		"total_steps":      ap.TotalSteps,
		"executable_steps": ap.ExecutableSteps,
		"blocked_steps":    ap.BlockedSteps,
		"steps":            stepSummaries,
		"created_at":       ap.CreatedAt.Format(time.RFC3339),
		"markdown":         markdownText,
	}

	return sendFormattedWebhook(ctx, transport, ch, titleText, color, markdownText, customPayload)
}

func sendFormattedWebhook(
	ctx context.Context,
	transport HTTPTransport,
	ch vault.WebhookChannel,
	titleText string,
	feishuColor string,
	markdownText string,
	customPayload map[string]any,
) error {
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
						"content": titleText,
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
				"title": titleText,
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
		bodyMap = customPayload
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
			msg = TruncateUTF8Bytes(msg, 512) + "..."
		}
		return fmt.Errorf("Webhook 响应 HTTP %d: %s", statusCode, msg)
	}
	return nil
}
