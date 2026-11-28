package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/qqbot"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// ============================================================================
// QQ Open Platform API v2 WebSocket Event Notification Handlers
// ============================================================================

func (s *Server) handleGetQQBotOverview(w http.ResponseWriter, r *http.Request) {
	if s.cfg.QQBot == nil {
		writeError(w, http.StatusServiceUnavailable, "QQBOT_UNAVAILABLE", "QQ 机器人通知服务尚未就绪")
		return
	}
	settings, err := s.cfg.Store.GetQQBotSettingsView()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	rtSnap := s.cfg.Store.GetQQBotRuntimeSnapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"settings":           settings,
		"runtime":            s.cfg.QQBot.Status(),
		"discovered_targets": rtSnap.DiscoveredTargets,
		"recent_events":      rtSnap.RecentEvents,
		"push_history":       rtSnap.PushHistory,
		"intent_catalog":     qqbot.IntentCatalog(),
	})
}

func (s *Server) handleUpdateQQBotConfig(w http.ResponseWriter, r *http.Request) {
	if s.cfg.QQBot == nil {
		writeError(w, http.StatusServiceUnavailable, "QQBOT_UNAVAILABLE", "QQ 机器人通知服务尚未就绪")
		return
	}
	var in vault.QQBotSettingsUpdateInput
	if err := decodeJSON(r, &in, 128*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "QQ 机器人配置参数格式错误")
		return
	}
	view, err := s.cfg.Store.UpdateQQBotSettings(in, extractClientIP(r))
	if in.AppSecret != nil {
		*in.AppSecret = ""
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.cfg.QQBot.NotifyConfigUpdated()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"settings": view,
		"runtime":  s.cfg.QQBot.Status(),
	})
}

func (s *Server) handleUpsertQQBotTarget(w http.ResponseWriter, r *http.Request) {
	if s.cfg.QQBot == nil {
		writeError(w, http.StatusServiceUnavailable, "QQBOT_UNAVAILABLE", "QQ 机器人通知服务尚未就绪")
		return
	}
	var req struct {
		ID         string                `json:"id"`
		Name       string                `json:"name"`
		TargetType vault.QQBotTargetType `json:"target_type"`
		TargetID   string                `json:"target_id"`
		GuildID    string                `json:"guild_id"`
		Enabled    *bool                 `json:"enabled"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "QQ 推送目标参数格式错误")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	saved, view, err := s.cfg.Store.UpsertQQBotTarget(vault.QQBotTarget{
		ID:         strings.TrimSpace(req.ID),
		Name:       strings.TrimSpace(req.Name),
		TargetType: req.TargetType,
		TargetID:   strings.TrimSpace(req.TargetID),
		GuildID:    strings.TrimSpace(req.GuildID),
		Enabled:    enabled,
	}, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"target":   saved,
		"settings": view,
	})
}

func (s *Server) handleDeleteQQBotTarget(w http.ResponseWriter, r *http.Request) {
	if s.cfg.QQBot == nil {
		writeError(w, http.StatusServiceUnavailable, "QQBOT_UNAVAILABLE", "QQ 机器人通知服务尚未就绪")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	view, err := s.cfg.Store.DeleteQQBotTarget(id, extractClientIP(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"settings": view,
	})
}

func (s *Server) handleGenerateQQBotBindCode(w http.ResponseWriter, r *http.Request) {
	if s.cfg.QQBot == nil {
		writeError(w, http.StatusServiceUnavailable, "QQBOT_UNAVAILABLE", "QQ 机器人通知服务尚未就绪")
		return
	}
	info := s.cfg.QQBot.GenerateBindCode()
	s.cfg.Store.RecordAudit("qqbot.bind_code", "qqbot-websocket", "生成一次性 QQ 通知目标绑定验证码（10 分钟内有效）", extractClientIP(r), true)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"bind_code": info,
		"runtime":   s.cfg.QQBot.Status(),
	})
}

func (s *Server) handleProbeQQBot(w http.ResponseWriter, r *http.Request) {
	if s.cfg.QQBot == nil {
		writeError(w, http.StatusServiceUnavailable, "QQBOT_UNAVAILABLE", "QQ 机器人通知服务尚未就绪")
		return
	}
	var in vault.QQBotSettingsUpdateInput
	_ = decodeJSON(r, &in, 64*1024)
	cfg, err := s.cfg.Store.ResolveQQBotSettingsForTransientCall(in)
	if in.AppSecret != nil {
		*in.AppSecret = ""
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	defer func() {
		cfg.AppSecret = ""
	}()

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := s.cfg.QQBot.ProbeConnection(ctx, cfg)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"probe": res,
	})
}

func (s *Server) handleReconnectQQBot(w http.ResponseWriter, r *http.Request) {
	if s.cfg.QQBot == nil {
		writeError(w, http.StatusServiceUnavailable, "QQBOT_UNAVAILABLE", "QQ 机器人通知服务尚未就绪")
		return
	}
	s.cfg.QQBot.ReconnectNow()
	s.cfg.Store.RecordAudit("qqbot.reconnect", "qqbot-websocket", "手动触发 QQ 机器人 WebSocket 重连", extractClientIP(r), true)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"runtime": s.cfg.QQBot.Status(),
	})
}

func (s *Server) handleTestQQBotPush(w http.ResponseWriter, r *http.Request) {
	if s.cfg.QQBot == nil {
		writeError(w, http.StatusServiceUnavailable, "QQBOT_UNAVAILABLE", "QQ 机器人通知服务尚未就绪")
		return
	}
	var req struct {
		vault.QQBotSettingsUpdateInput
		TargetID      string                `json:"target_id"`
		TargetType    vault.QQBotTargetType `json:"target_type"`
		CustomMessage string                `json:"custom_message"`
	}
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "QQ 测试推送参数格式错误")
		return
	}
	cfg, err := s.cfg.Store.ResolveQQBotSettingsForTransientCall(req.QQBotSettingsUpdateInput)
	if req.AppSecret != nil {
		*req.AppSecret = ""
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	defer func() {
		cfg.AppSecret = ""
	}()

	targetSelector := strings.TrimSpace(req.TargetID)
	// Allow testing an explicit ad-hoc target_type + target_id even before saving it as a permanent target
	if targetSelector != "" && req.TargetType != "" {
		found := false
		for _, t := range cfg.Targets {
			if t.ID == targetSelector || t.TargetID == targetSelector {
				found = true
				break
			}
		}
		if !found {
			tt := vault.NormalizeQQBotTargetType(req.TargetType)
			if !vault.IsValidQQBotTargetType(tt) {
				writeDomainError(w, fmt.Errorf("%w: 不支持的 QQ 推送目标类型", vault.ErrInvalidInput))
				return
			}
			cfg.Targets = append(cfg.Targets, vault.QQBotTarget{
				ID:         "adhoc-test",
				Name:       "临时测试目标",
				TargetType: tt,
				TargetID:   targetSelector,
				Enabled:    true,
			})
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	sum, err := s.cfg.QQBot.SendTestNotification(ctx, cfg, targetSelector, req.CustomMessage)
	if err != nil {
		s.cfg.Store.RecordAudit("qqbot.test_push", "qqbot-websocket", "QQ 机器人测试推送失败: "+err.Error(), extractClientIP(r), false)
		writeDomainError(w, err)
		return
	}
	s.cfg.Store.RecordAudit("qqbot.test_push", "qqbot-websocket", fmt.Sprintf("QQ 机器人测试推送完成（成功 %d / 总计 %d）", sum.Sent, sum.Total), extractClientIP(r), true)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"summary": sum,
		"runtime": s.cfg.QQBot.Status(),
	})
}

func (s *Server) handleClearQQBotLogs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IncludeDiscovered bool `json:"include_discovered"`
	}
	_ = decodeJSON(r, &req, 16*1024)
	s.cfg.Store.ClearQQBotRuntimeLogs(req.IncludeDiscovered)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
	})
}
