package mcp

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/aiops"
	"github.com/icaruszezen/ServerNeedSafe/internal/monitor"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

type mcpToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func (s *Server) listToolsForToken(tok *vault.MCPToken) []mcpToolDef {
	tools := []mcpToolDef{
		{
			Name:        "list_servers",
			Description: "列出当前 MCP 令牌授权访问的所有受管服务器清单（含 server_id、分组、地址、OS、实时延迟，严格隔离 SSH 密码与私钥）。",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			Name:        "get_monitor_overview",
			Description: "获取 7×24 全维服务器状态监控总览：集群 KPI、各主机最新健康快照（CPU/内存/磁盘/负载/Docker/端口/安全态势）与活跃告警列表。",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			Name:        "get_server_detail",
			Description: "获取指定服务器的深度 7×24 监控详情：最新全维快照、端口基线、历史时序点与告警。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_id": map[string]any{"type": "string", "description": "目标服务器 server_id"},
					"range":     map[string]any{"type": "string", "description": "时序范围：15m / 1h / 6h / 24h / 7d（默认 1h）"},
				},
				"required": []string{"server_id"},
			},
		},
		{
			Name:        "list_alerts",
			Description: "查询 7×24 监控告警列表（默认返回 firing 活跃告警）。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"status":    map[string]any{"type": "string", "description": "告警状态过滤：firing / acknowledged / resolved / 留空为全部"},
					"server_id": map[string]any{"type": "string", "description": "可选：按 server_id 过滤"},
					"limit":     map[string]any{"type": "integer", "description": "最大返回条数（默认 50）"},
				},
			},
		},
		{
			Name:        "run_patrol",
			Description: "主动发起一次只读安全与健康巡检（采集 CPU/内存/磁盘、监听端口基线变化、SSH 近 1h 爆破次数、UID=0 特权账户、故障 systemd 服务），返回带 patrol_record_id 的巡检证据供你深度钻取并回写报告。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_ids": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "可选：指定巡检的 server_id 列表；留空则按巡检配置或令牌授权范围全量巡检",
					},
				},
			},
		},
		{
			Name:        "list_patrol_records",
			Description: "查询历史巡检记录或待外部 AI 接管研判的巡检队列（建议先传 pending_only=true 检查后台定时巡检留下的异常单）。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pending_only": map[string]any{"type": "boolean", "description": "为 true 时仅返回待外部 AI 研判 (pending_external / claimed) 的巡检任务"},
					"limit":        map[string]any{"type": "integer", "description": "返回最大条数（默认 15，最大 50）"},
				},
			},
		},
		{
			Name:        "claim_patrol",
			Description: "认领一条巡检记录并一次性获取其完整巡检发现、全局 AGENTS.md 规范、主机画像与相关长期运维记忆，准备展开深度排查。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"patrol_record_id": map[string]any{"type": "string", "description": "要认领分析的巡检记录 ID"},
				},
				"required": []string{"patrol_record_id"},
			},
		},
		{
			Name:        "submit_patrol_report",
			Description: "将你完成深度取证后的结构化巡检结论回写到 ServerNeedSafe 巡检记录中，展示在 Web 面板并按需触发飞书/钉钉/企微/自定义 Webhook 推送。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"patrol_record_id": map[string]any{"type": "string", "description": "对应的巡检记录 ID"},
					"summary":          map[string]any{"type": "string", "description": "一句话核心健康/风险总结（建议 80 字以内）"},
					"root_cause":       map[string]any{"type": "string", "description": "结合监控指标、只读取证证据、主机画像与安全基线的根因分析"},
					"recommendations": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "具体可执行的排查或加固建议列表",
					},
					"deep_evidence": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "可选：本次通过只读 SSH/SFTP 钻取到的关键取证线索摘要（严禁包含密码/密钥）",
					},
					"model_name":       map[string]any{"type": "string", "description": "可选：当前使用的模型名称（如 claude-sonnet-4-5 / gpt-5-codex / gemini-2.5-pro）"},
					"client_name":      map[string]any{"type": "string", "description": "可选：外部 AI 软件名称（如 Claude Code / Codex / Antigravity / Cursor）"},
					"dispatch_webhook": map[string]any{"type": "boolean", "description": "可选：是否立即推送巡检报告至已启用的告警 Webhook（异常记录默认 true）"},
				},
				"required": []string{"patrol_record_id", "summary"},
			},
		},
		{
			Name:        "probe_server",
			Description: "对单台受管主机执行实时无损 SSH 探针，获取连通延迟、OS 内核、负载、内存与根分区水位。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_id": map[string]any{"type": "string", "description": "目标服务器 server_id"},
				},
				"required": []string{"server_id"},
			},
		},
		{
			Name:        "exec_readonly_ssh",
			Description: "在受管服务器上执行严格只读的 Linux / macOS 诊断命令（强制经由 ServerNeedSafe ClassifyCommand 只读白名单校验，如 Linux 的 ss、journalctl、ps、df、free、systemctl status，以及 macOS 的 sw_vers、vm_stat、sysctl、netstat、lsof、launchctl list、log show、docker ps/logs、nginx -t 等；任何变更或高危命令都会被立即拒绝）。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_ids": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "要执行只读命令的目标 server_id 列表",
					},
					"command":     map[string]any{"type": "string", "description": "单行非交互式只读 Shell 命令"},
					"reason":      map[string]any{"type": "string", "description": "诊断目的说明（记录至审计日志）"},
					"timeout_sec": map[string]any{"type": "integer", "description": "超时秒数（默认 20，最大 60）"},
				},
				"required": []string{"server_ids", "command"},
			},
		},
		{
			Name:        "sftp_list_dir",
			Description: "通过 SFTP 只读浏览目标服务器指定目录的文件列表、权限与大小。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_id": map[string]any{"type": "string", "description": "目标服务器 server_id"},
					"path":      map[string]any{"type": "string", "description": "目录路径（如 /etc/nginx/conf.d）"},
				},
				"required": []string{"server_id", "path"},
			},
		},
		{
			Name:        "sftp_read_file",
			Description: "通过 SFTP 只读查看目标服务器上的配置文件或日志文本（硬禁止读取 /etc/shadow、SSH 私钥、保险库文件等敏感凭据）。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_id": map[string]any{"type": "string", "description": "目标服务器 server_id"},
					"path":      map[string]any{"type": "string", "description": "远程文件完整路径"},
				},
				"required": []string{"server_id", "path"},
			},
		},
		{
			Name:        "get_ops_context",
			Description: "获取全局 AGENTS.md 运维规范、指定主机的环境画像 (HostMemory)、高优长期运维记忆与 Runbook 目录索引。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_ids": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "可选：聚焦的主机 server_id 列表",
					},
				},
			},
		},
		{
			Name:        "search_memory",
			Description: "按关键词、分类或主机 ID 深度检索 ServerNeedSafe 长期记忆库与主机画像。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":     map[string]any{"type": "string", "description": "检索关键词（空格分隔多词）"},
					"server_id": map[string]any{"type": "string", "description": "可选：过滤特定主机"},
					"category":  map[string]any{"type": "string", "description": "可选：preference / topology / incident / change / lesson"},
					"limit":     map[string]any{"type": "integer", "description": "返回最大条数（默认 8，最大 20）"},
				},
			},
		},
		{
			Name:        "get_runbook",
			Description: "调阅已沉淀的排障 SOP (Runbook) 完整步骤、推荐修复命令与验证方案。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"runbook_id": map[string]any{"type": "string", "description": "Runbook ID"},
					"query":      map[string]any{"type": "string", "description": "按标题/症状/标签模糊检索"},
				},
			},
		},
		{
			Name:        "update_host_memory",
			Description: "增量更新某台受管主机的客观环境画像（角色摘要、OS/架构、关键服务、部署路径、端口用途、避坑红线与备注；自动脱敏严禁记录凭据）。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server_id":    map[string]any{"type": "string", "description": "目标服务器 server_id"},
					"summary":      map[string]any{"type": "string", "description": "主机角色与业务摘要"},
					"os_arch":      map[string]any{"type": "string", "description": "发行版与架构"},
					"key_services": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "运行的关键服务"},
					"deploy_paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "关键部署或配置路径"},
					"ports_note":   map[string]any{"type": "string", "description": "监听端口业务用途说明"},
					"constraints":  map[string]any{"type": "string", "description": "运维红线与禁忌"},
					"notes":        map[string]any{"type": "string", "description": "其他客观备注"},
				},
				"required": []string{"server_id"},
			},
		},
		{
			Name:        "save_memory",
			Description: "沉淀或更新一条跨会话长期运维记忆（故障根因、拓扑依赖、运维经验、变更结论等，系统自动脱敏）。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"scope":      map[string]any{"type": "string", "enum": []string{"global", "server"}, "description": "global 或 server"},
					"server_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "当 scope=server 时关联的主机列表"},
					"category":   map[string]any{"type": "string", "enum": []string{"preference", "topology", "incident", "change", "lesson"}, "description": "记忆分类"},
					"title":      map[string]any{"type": "string", "description": "简明标题（25 字以内）"},
					"content":    map[string]any{"type": "string", "description": "事实、根因或经验详情（严禁含密码/私钥/Token）"},
					"tags":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "检索标签"},
					"importance": map[string]any{"type": "integer", "description": "重要度 1-5（默认 3）"},
					"pinned":     map[string]any{"type": "boolean", "description": "是否置顶"},
				},
				"required": []string{"category", "title", "content"},
			},
		},
		{
			Name:        "save_runbook",
			Description: "将巡检或排障中总结出的可复用 SOP 沉淀到 ServerNeedSafe Runbook 技能库。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"title":            map[string]any{"type": "string", "description": "Runbook 标题"},
					"category":         map[string]any{"type": "string", "description": "分类（如 安全加固 / 故障恢复 / 性能优化）"},
					"tags":             map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"symptom":          map[string]any{"type": "string", "description": "适用症状或告警特征"},
					"root_cause":       map[string]any{"type": "string", "description": "典型根因"},
					"diagnostic_steps": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "标准排查步骤"},
					"fix_commands":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "推荐修复命令"},
					"verification":     map[string]any{"type": "string", "description": "修复后验证方法"},
				},
				"required": []string{"title", "symptom", "diagnostic_steps", "fix_commands"},
			},
		},
		{
			Name:        "list_approvals",
			Description: "列出外部 AI 提交的 HITL 变更审批记录（可按 pending/approved/rejected 过滤）。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"status": map[string]any{"type": "string", "description": "pending / approved / rejected / all（默认 pending）"},
					"limit":  map[string]any{"type": "integer", "description": "最大返回条数（默认 20）"},
				},
			},
		},
		{
			Name:        "get_approval_status",
			Description: "查询某条外部 AI 变更审批单 (approval_id) 的最新审批结论与远端执行回显 (stdout/stderr)，便于在管理员批准后执行二次核验。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"approval_id": map[string]any{"type": "string", "description": "审批单 ID"},
				},
				"required": []string{"approval_id"},
			},
		},
	}

	if tok != nil && tok.Scope == vault.MCPScopeOpsPropose {
		tools = append(tools,
			mcpToolDef{
				Name:        "propose_ssh_command",
				Description: "【受控变更 · HITL】提交一条状态变更类 SSH 修复/运维命令进入 ServerNeedSafe Web 端审批队列。命令绝不会自动执行，且毁灭性指令会被安全熔断器硬拦截。提交后会返回 approval_id，管理员在控制台点击批准后立即执行。",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"server_ids":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "目标服务器 server_id 列表"},
						"command":          map[string]any{"type": "string", "description": "拟执行的修复或控制命令（如 journalctl --vacuum-size=200M 或 systemctl reload nginx）"},
						"reason":           map[string]any{"type": "string", "description": "清晰说明变更目的、影响范围与回滚方案（将展示在审批卡片与通知中）"},
						"patrol_record_id": map[string]any{"type": "string", "description": "可选：关联的巡检记录 ID"},
					},
					"required": []string{"server_ids", "command", "reason"},
				},
			},
			mcpToolDef{
				Name:        "propose_sftp_write",
				Description: "【受控变更 · HITL】提交远程配置文件修改提案进入 ServerNeedSafe Web 端审批队列。服务端会自动拉取现网原文件计算 Unified Diff 供管理员逐行审查批准，绝不会绕过审批直接写盘。",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"server_id":        map[string]any{"type": "string", "description": "目标服务器 server_id"},
						"path":             map[string]any{"type": "string", "description": "远程配置文件完整路径"},
						"content":          map[string]any{"type": "string", "description": "完整的修改后文件内容"},
						"reason":           map[string]any{"type": "string", "description": "修改原因、影响与验证计划"},
						"patrol_record_id": map[string]any{"type": "string", "description": "可选：关联的巡检记录 ID"},
					},
					"required": []string{"server_id", "path", "content", "reason"},
				},
			},
		)
	}

	return tools
}

func (s *Server) listResources() []map[string]any {
	return []map[string]any{
		{
			"uri":         "serverneedsafe://agents-md",
			"name":        "Global AGENTS.md SRE Charter",
			"description": "ServerNeedSafe 全局运维智能体规范宪章（AGENTS.md）",
			"mimeType":    "text/markdown",
		},
		{
			"uri":         "serverneedsafe://patrol/pending",
			"name":        "Pending External Patrol Queue",
			"description": "等待外部 AI 认领与深度研判的巡检异常任务队列 (JSON)",
			"mimeType":    "application/json",
		},
		{
			"uri":         "serverneedsafe://monitor/overview",
			"name":        "7x24 Fleet Monitor Overview",
			"description": "全集群 7×24 监控实时态势、KPI 与活跃告警 (JSON)",
			"mimeType":    "application/json",
		},
		{
			"uri":         "serverneedsafe://approvals/pending",
			"name":        "Pending External AI HITL Approvals",
			"description": "待管理员在 Web 端审批的外部 AI 变更提案队列 (JSON)",
			"mimeType":    "application/json",
		},
	}
}

func (s *Server) readResource(tok *vault.MCPToken, uri string) (mime string, text string, err error) {
	switch uri {
	case "serverneedsafe://agents-md":
		cfg, err := s.store.GetAgentsMD()
		if err != nil {
			return "", "", err
		}
		return "text/markdown", cfg.Content, nil

	case "serverneedsafe://patrol/pending":
		recs, err := s.store.ListPendingExternalPatrols(20)
		if err != nil {
			return "", "", err
		}
		filtered := filterPatrolRecordsByToken(tok, recs)
		return "application/json", mustMarshalPretty(map[string]any{
			"pending_count": len(filtered),
			"records":       filtered,
		}), nil

	case "serverneedsafe://monitor/overview":
		ov, err := s.store.GetMonitorOverview()
		if err != nil {
			return "", "", err
		}
		ov = filterMonitorOverviewByToken(tok, ov)
		return "application/json", mustMarshalPretty(ov), nil

	case "serverneedsafe://approvals/pending":
		aps, pending, err := s.store.ListExternalApprovals("pending", 50)
		if err != nil {
			return "", "", err
		}
		aps = filterApprovalsByToken(tok, aps)
		return "application/json", mustMarshalPretty(map[string]any{
			"pending_count": pending,
			"approvals":     aps,
		}), nil

	default:
		return "", "", fmt.Errorf("未知资源 URI: %s", uri)
	}
}

func (s *Server) listPrompts() []map[string]any {
	return []map[string]any{
		{
			"name":        "patrol_triage",
			"description": "【推荐】认领 ServerNeedSafe 后台巡检队列中的待研判异常任务，结合 AGENTS.md 与只读取证完成根因分析并回写报告",
			"arguments": []map[string]any{
				{
					"name":        "patrol_record_id",
					"description": "可选：指定巡检记录 ID；留空则自动拉取全部待研判任务",
					"required":    false,
				},
			},
		},
		{
			"name":        "full_security_patrol",
			"description": "主动对受管服务器发起一次全面只读健康与安全基线巡检，钻取异常根因、回写巡检报告并沉淀主机记忆",
			"arguments": []map[string]any{
				{
					"name":        "server_ids",
					"description": "可选：逗号分隔的目标 server_id；留空则全量巡检",
					"required":    false,
				},
			},
		},
		{
			"name":        "host_deep_audit",
			"description": "对单台服务器执行深度只读安全基线与性能体检（SSH 配置、端口、进程、容器、磁盘日志）并更新主机画像",
			"arguments": []map[string]any{
				{
					"name":        "server_name",
					"description": "目标服务器名称或 server_id",
					"required":    true,
				},
			},
		},
	}
}

func (s *Server) getPrompt(name string, args map[string]string) (string, []map[string]any, error) {
	switch name {
	case "patrol_triage":
		targetHint := "先调用 `list_patrol_records(pending_only=true)` 获取所有待外部 AI 研判的巡检异常单"
		if id := strings.TrimSpace(args["patrol_record_id"]); id != "" {
			targetHint = fmt.Sprintf("先调用 `claim_patrol(patrol_record_id=%q)` 认领该巡检任务", id)
		}
		text := fmt.Sprintf(`请作为 ServerNeedSafe 资深 Linux SRE 接管本次 AI 巡检研判，严格按以下 SOP 执行：
1. %s（若无待研判任务，可汇报当前集群 7×24 态势是否健康）。
2. 对每条待研判任务调用 `+"`claim_patrol`"+`，仔细阅读返回的全局 AGENTS.md 运维规范、受检主机环境画像（含端口备注与避坑红线）及长期记忆，避免将已知正常业务端口或预期缓存误判为异常。
3. 针对每台出现告警或异常的主机，使用 `+"`exec_readonly_ssh`"+`（例如 `+"`journalctl`"+`、`+"`ss -tulnp`"+`、`+"`ps aux --sort=-%%cpu | head -n 15`"+`、`+"`df -h`"+`、`+"`systemctl status`"+`）或 `+"`sftp_read_file`"+` 进行深一层只读取证，拿到确凿根因证据。
4. 调用 `+"`submit_patrol_report`"+` 将结构化的 `+"`summary`"+`、`+"`root_cause`"+`、`+"`deep_evidence`"+` 与 `+"`recommendations`"+` 回写到 ServerNeedSafe 面板并推送告警。
5. 若发现新的主机服务、端口用途或典型故障根因，调用 `+"`update_host_memory`"+` / `+"`save_memory`"+` 沉淀知识（严禁写入任何明文凭据）。
6. 若确认需要线上修复或配置加固且拥有 `+"`ops_propose`"+` 权限，使用 `+"`propose_ssh_command`"+` 或 `+"`propose_sftp_write`"+` 提交 HITL 审批提案（关联 `+"`patrol_record_id`"+`），等待管理员在 Web 控制台批准后查询执行结果。`, targetHint)
		return "认领并完成 ServerNeedSafe 巡检队列的深度研判与回写", []map[string]any{
			{"role": "user", "content": map[string]any{"type": "text", "text": text}},
		}, nil

	case "full_security_patrol":
		scopeHint := "所有授权受管服务器"
		if sids := strings.TrimSpace(args["server_ids"]); sids != "" {
			scopeHint = fmt.Sprintf("指定服务器 (%s)", sids)
		}
		text := fmt.Sprintf(`请对 %s 执行一次主动全量只读安全与健康巡检：
1. 调用 `+"`get_ops_context`"+` 与 `+"`get_monitor_overview`"+` 了解当前运维规范、主机画像与 7×24 监控态势。
2. 调用 `+"`run_patrol`"+` 触发一次全量只读安全基线扫描，拿到 `+"`patrol_record_id`"+` 与各主机实时指标。
3. 对任何出现高负载、高内存/磁盘、新监听端口、SSH 爆破或异常 systemd 服务的主机，使用 `+"`exec_readonly_ssh`"+` 进行深度只读核查。
4. 调用 `+"`submit_patrol_report`"+` 将完整研判报告回写至 ServerNeedSafe 巡检中心，并在需要时更新主机画像或提交受控修复审批提案。`, scopeHint)
		return "主动发起 ServerNeedSafe 全量安全与健康巡检", []map[string]any{
			{"role": "user", "content": map[string]any{"type": "text", "text": text}},
		}, nil

	case "host_deep_audit":
		target := strings.TrimSpace(args["server_name"])
		if target == "" {
			return "", nil, fmt.Errorf("缺少必需参数 server_name")
		}
		text := fmt.Sprintf(`请对主机「%s」执行深度只读安全基线与性能体检：
1. 调用 `+"`list_servers`"+` 找到该主机的 `+"`server_id`"+`，再调用 `+"`get_server_detail`"+` 与 `+"`get_ops_context`"+` 查阅现有态势、端口基线与运维红线。
2. 使用 `+"`exec_readonly_ssh`"+` 与 `+"`sftp_read_file`"+` 检查系统负载、Top 进程、公网监听端口、SSH 登录安全配置 (/etc/ssh/sshd_config)、近期认证失败日志、磁盘/Inode 水位与失败服务。
3. 调用 `+"`update_host_memory`"+` 补齐最新服务与端口画像，并输出「结论先行 → 关键证据 → 加固建议」的中文报告；如需配置修改，通过 `+"`propose_sftp_write`"+` 生成 Diff 审批单。`, target)
		return "单主机深度只读安全基线体检", []map[string]any{
			{"role": "user", "content": map[string]any{"type": "text", "text": text}},
		}, nil

	default:
		return "", nil, fmt.Errorf("未知 Prompt 名称: %s", name)
	}
}

func (s *Server) callTool(c *mcpCallContext, clientName, name string, rawArgs json.RawMessage) (string, bool) {
	if len(rawArgs) == 0 {
		rawArgs = json.RawMessage(`{}`)
	}

	switch name {
	case "list_servers":
		servers, err := s.store.ListServers()
		if err != nil {
			return "获取服务器列表失败: " + err.Error(), true
		}
		allowed := filterServersByToken(c.token, servers)
		return mustMarshalPretty(map[string]any{
			"total":   len(allowed),
			"servers": allowed,
		}), false

	case "get_monitor_overview":
		ov, err := s.store.GetMonitorOverview()
		if err != nil {
			return "获取 7×24 监控总览失败: " + err.Error(), true
		}
		ov = filterMonitorOverviewByToken(c.token, ov)
		return mustMarshalPretty(ov), false

	case "get_server_detail":
		var args struct {
			ServerID string `json:"server_id"`
			Range    string `json:"range"`
		}
		_ = json.Unmarshal(rawArgs, &args)
		sid := strings.TrimSpace(args.ServerID)
		if sid == "" {
			return "缺少必填参数 server_id", true
		}
		if !isServerAllowed(c.token, sid) {
			return fmt.Sprintf("当前 MCP 令牌无权访问服务器 %s", sid), true
		}
		detail, err := s.store.GetServerMonitorDetail(sid, monitor.ParseHistoryRange(args.Range))
		if err != nil {
			return "获取服务器监控详情失败: " + err.Error(), true
		}
		return mustMarshalPretty(detail), false

	case "list_alerts":
		var args struct {
			Status   string `json:"status"`
			ServerID string `json:"server_id"`
			Limit    int    `json:"limit"`
		}
		_ = json.Unmarshal(rawArgs, &args)
		if args.Limit <= 0 || args.Limit > 200 {
			args.Limit = 50
		}
		if sid := strings.TrimSpace(args.ServerID); sid != "" && !isServerAllowed(c.token, sid) {
			return fmt.Sprintf("当前 MCP 令牌无权访问服务器 %s", sid), true
		}
		alerts, err := s.store.ListMonitorAlerts(strings.TrimSpace(args.Status), strings.TrimSpace(args.ServerID), args.Limit)
		if err != nil {
			return "获取告警列表失败: " + err.Error(), true
		}
		filtered := make([]vault.MonitorAlert, 0, len(alerts))
		for _, al := range alerts {
			if isServerAllowed(c.token, al.ServerID) {
				filtered = append(filtered, al)
			}
		}
		return mustMarshalPretty(map[string]any{
			"count":  len(filtered),
			"alerts": filtered,
		}), false

	case "run_patrol":
		var args struct {
			ServerIDs []string `json:"server_ids"`
		}
		_ = json.Unmarshal(rawArgs, &args)
		targetIDs := args.ServerIDs
		if len(targetIDs) > 0 {
			for _, sid := range targetIDs {
				if !isServerAllowed(c.token, sid) {
					return fmt.Sprintf("当前 MCP 令牌无权巡检服务器 %s", sid), true
				}
			}
		} else if len(c.token.AllowedServers) > 0 {
			targetIDs = slices.Clone(c.token.AllowedServers)
		}
		rec, err := s.ai.RunPatrolForServers(c.reqCtx, "external_mcp", true, targetIDs, clientName)
		if err != nil {
			return "触发只读巡检失败: " + err.Error(), true
		}
		srvIDs := make([]string, 0, len(rec.Findings))
		for _, f := range rec.Findings {
			srvIDs = append(srvIDs, f.ServerID)
		}
		return mustMarshalPretty(map[string]any{
			"patrol_record": rec,
			"ops_context":   s.ai.BuildPatrolContextBlock(srvIDs),
			"next_step":     "请结合 ops_context 与 findings 评估异常，必要时使用 exec_readonly_ssh / sftp_read_file 深度取证，然后调用 submit_patrol_report 回写结构化结论。",
		}), false

	case "list_patrol_records":
		var args struct {
			PendingOnly bool `json:"pending_only"`
			Limit       int  `json:"limit"`
		}
		_ = json.Unmarshal(rawArgs, &args)
		if args.Limit <= 0 || args.Limit > 50 {
			args.Limit = 15
		}
		var recs []vault.PatrolRecord
		var err error
		if args.PendingOnly {
			recs, err = s.store.ListPendingExternalPatrols(args.Limit)
		} else {
			recs, _, err = s.store.ListPatrolRecords(args.Limit, false)
		}
		if err != nil {
			return "获取巡检记录失败: " + err.Error(), true
		}
		filtered := filterPatrolRecordsByToken(c.token, recs)
		return mustMarshalPretty(map[string]any{
			"count":        len(filtered),
			"pending_only": args.PendingOnly,
			"records":      filtered,
		}), false

	case "claim_patrol":
		var args struct {
			PatrolRecordID string `json:"patrol_record_id"`
		}
		_ = json.Unmarshal(rawArgs, &args)
		recID := strings.TrimSpace(args.PatrolRecordID)
		if recID == "" {
			return "缺少必填参数 patrol_record_id", true
		}
		rec, err := s.store.ClaimPatrolRecord(recID, clientName, c.clientIP)
		if err != nil {
			return "认领巡检记录失败: " + err.Error(), true
		}
		filtered := filterSinglePatrolRecordByToken(c.token, *rec)
		srvIDs := make([]string, 0, len(filtered.Findings))
		for _, f := range filtered.Findings {
			srvIDs = append(srvIDs, f.ServerID)
		}
		return mustMarshalPretty(map[string]any{
			"patrol_record": filtered,
			"ops_context":   s.ai.BuildPatrolContextBlock(srvIDs),
			"instructions":  "任务已认领。请先核对 AGENTS.md 与主机画像（避免误报），使用 exec_readonly_ssh / sftp_read_file 钻取日志或端口证据后，调用 submit_patrol_report 回写研判报告。",
		}), false

	case "submit_patrol_report":
		var args struct {
			PatrolRecordID  string   `json:"patrol_record_id"`
			Summary         string   `json:"summary"`
			RootCause       string   `json:"root_cause"`
			Recommendations []string `json:"recommendations"`
			DeepEvidence    []string `json:"deep_evidence"`
			ModelName       string   `json:"model_name"`
			ClientName      string   `json:"client_name"`
			DispatchWebhook *bool    `json:"dispatch_webhook"`
		}
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return "参数解析失败: " + err.Error(), true
		}
		extClient := strings.TrimSpace(args.ClientName)
		if extClient == "" {
			extClient = clientName
		} else {
			extClient = friendlyClientName(extClient)
		}
		updated, err := s.ai.SubmitExternalPatrolReport(c.reqCtx, aiops.ExternalPatrolReportInput{
			PatrolRecordID:  args.PatrolRecordID,
			Summary:         args.Summary,
			RootCause:       args.RootCause,
			Recommendations: args.Recommendations,
			DeepEvidence:    args.DeepEvidence,
			ExternalClient:  extClient,
			AIModel:         strings.TrimSpace(args.ModelName),
			DispatchWebhook: args.DispatchWebhook,
			ClientIP:        c.clientIP,
		})
		if err != nil {
			return "回写巡检报告失败: " + err.Error(), true
		}
		return mustMarshalPretty(map[string]any{
			"ok":                  true,
			"patrol_record_id":    updated.ID,
			"analysis_state":      updated.AnalysisState,
			"external_client":     updated.ExternalClient,
			"ai_model":            updated.AIModel,
			"ai_webhook_notified": updated.AIWebhookNotified,
		}), false

	case "probe_server":
		var args struct {
			ServerID string `json:"server_id"`
		}
		_ = json.Unmarshal(rawArgs, &args)
		sid := strings.TrimSpace(args.ServerID)
		if sid == "" {
			return "缺少必填参数 server_id", true
		}
		if !isServerAllowed(c.token, sid) {
			return fmt.Sprintf("当前 MCP 令牌无权探测服务器 %s", sid), true
		}
		probe, err := s.ssh.ProbeServer(sid, "", c.clientIP)
		if err != nil {
			return "探针执行失败: " + err.Error(), true
		}
		s.store.RecordAudit("mcp.probe", probe.ServerName, fmt.Sprintf("外部 AI (%s) 执行只读连通探针", clientName), c.clientIP, true)
		return mustMarshalPretty(probe), false

	case "exec_readonly_ssh":
		var args struct {
			ServerIDs  []string `json:"server_ids"`
			Command    string   `json:"command"`
			Reason     string   `json:"reason"`
			TimeoutSec int      `json:"timeout_sec"`
		}
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return "参数解析失败: " + err.Error(), true
		}
		if len(args.ServerIDs) == 0 {
			return "缺少必填参数 server_ids", true
		}
		for _, sid := range args.ServerIDs {
			if !isServerAllowed(c.token, sid) {
				return fmt.Sprintf("当前 MCP 令牌无权访问服务器 %s", sid), true
			}
		}
		cmd := strings.TrimSpace(args.Command)
		risk, why := aiops.ClassifyCommand(cmd)
		if risk == aiops.RiskBlocked {
			s.store.RecordAudit("mcp.blocked", strings.Join(args.ServerIDs, ","), fmt.Sprintf("外部 AI (%s) 只读接口尝试执行毁灭性命令被拦截: %.80s", clientName, cmd), c.clientIP, false)
			return "安全熔断器硬拦截: " + why, true
		}
		if risk != aiops.RiskReadOnly {
			s.store.RecordAudit("mcp.readonly_denied", strings.Join(args.ServerIDs, ","), fmt.Sprintf("外部 AI (%s) 只读接口拒绝状态变更命令: %.80s (%s)", clientName, cmd, why), c.clientIP, false)
			return fmt.Sprintf("已拒绝在只读接口执行非只读命令（原因：%s）。如需执行状态变更或修复命令，请调用 propose_ssh_command 提交至 ServerNeedSafe Web 端 HITL 审批队列。", why), true
		}
		timeout := time.Duration(args.TimeoutSec) * time.Second
		if timeout <= 0 || timeout > 60*time.Second {
			timeout = 20 * time.Second
		}
		results := s.ssh.BatchExecute(args.ServerIDs, cmd, timeout, c.clientIP)
		s.store.RecordAudit("mcp.exec_readonly", strings.Join(args.ServerIDs, ","), fmt.Sprintf("外部 AI (%s) 执行只读取证: %.75s", clientName, cmd), c.clientIP, true)
		return aiops.FormatBatchExecOutput(results), false

	case "sftp_list_dir":
		var args struct {
			ServerID string `json:"server_id"`
			Path     string `json:"path"`
		}
		_ = json.Unmarshal(rawArgs, &args)
		sid := strings.TrimSpace(args.ServerID)
		if sid == "" {
			return "缺少必填参数 server_id", true
		}
		if !isServerAllowed(c.token, sid) {
			return fmt.Sprintf("当前 MCP 令牌无权访问服务器 %s", sid), true
		}
		resp, err := s.ssh.SFTPList(sid, strings.TrimSpace(args.Path), c.clientIP)
		if err != nil {
			return "SFTP 目录列举失败: " + err.Error(), true
		}
		s.store.RecordAudit("mcp.sftp_list", sid+":"+args.Path, fmt.Sprintf("外部 AI (%s) 只读列举目录", clientName), c.clientIP, true)
		return mustMarshalPretty(resp), false

	case "sftp_read_file":
		var args struct {
			ServerID string `json:"server_id"`
			Path     string `json:"path"`
		}
		_ = json.Unmarshal(rawArgs, &args)
		sid := strings.TrimSpace(args.ServerID)
		filePath := strings.TrimSpace(args.Path)
		if sid == "" || filePath == "" {
			return "缺少必填参数 server_id 或 path", true
		}
		if !isServerAllowed(c.token, sid) {
			return fmt.Sprintf("当前 MCP 令牌无权访问服务器 %s", sid), true
		}
		if isBlockedReadPath(filePath) {
			s.store.RecordAudit("mcp.blocked", sid+":"+filePath, fmt.Sprintf("外部 AI (%s) 尝试读取受保护敏感文件被硬拦截", clientName), c.clientIP, false)
			return fmt.Sprintf("安全护栏禁止读取敏感凭据/密钥文件 (%s)", filePath), true
		}
		content, err := s.ssh.SFTPReadText(sid, filePath, c.clientIP)
		if err != nil {
			return "SFTP 读取文件失败: " + err.Error(), true
		}
		s.store.RecordAudit("mcp.sftp_read", sid+":"+filePath, fmt.Sprintf("外部 AI (%s) 只读查看远程文件", clientName), c.clientIP, true)
		if len(content) > 24000 {
			content = content[:24000] + "\n... [文件内容过长已截断]"
		}
		return content, false

	case "get_ops_context":
		var args struct {
			ServerIDs []string `json:"server_ids"`
		}
		_ = json.Unmarshal(rawArgs, &args)
		sids := filterServerIDsByToken(c.token, args.ServerIDs)
		agentsMD, _ := s.store.GetAgentsMD()
		runbooks, _ := s.store.ListRunbooks()
		rbIndex := make([]map[string]any, 0, len(runbooks))
		for _, rb := range runbooks {
			rbIndex = append(rbIndex, map[string]any{
				"id":       rb.ID,
				"title":    rb.Title,
				"category": rb.Category,
				"symptom":  rb.Symptom,
				"tags":     rb.Tags,
			})
		}
		return mustMarshalPretty(map[string]any{
			"agents_md_enabled": agentsMD.Enabled,
			"agents_md":         agentsMD.Content,
			"patrol_context":    s.ai.BuildPatrolContextBlock(sids),
			"runbook_index":     rbIndex,
		}), false

	case "search_memory":
		var args struct {
			Query    string `json:"query"`
			ServerID string `json:"server_id"`
			Category string `json:"category"`
			Limit    int    `json:"limit"`
		}
		_ = json.Unmarshal(rawArgs, &args)
		if sid := strings.TrimSpace(args.ServerID); sid != "" && !isServerAllowed(c.token, sid) {
			return fmt.Sprintf("当前 MCP 令牌无权检索服务器 %s 的记忆", sid), true
		}
		out, _ := s.ai.SearchMemory(args.Query, args.ServerID, args.Category, args.Limit)
		return out, false

	case "get_runbook":
		var args struct {
			RunbookID string `json:"runbook_id"`
			Query     string `json:"query"`
		}
		_ = json.Unmarshal(rawArgs, &args)
		out, found := s.ai.GetRunbookText(args.RunbookID, args.Query)
		return out, !found

	case "update_host_memory":
		var args struct {
			ServerID    string   `json:"server_id"`
			Summary     string   `json:"summary"`
			OSArch      string   `json:"os_arch"`
			KeyServices []string `json:"key_services"`
			DeployPaths []string `json:"deploy_paths"`
			PortsNote   string   `json:"ports_note"`
			Constraints string   `json:"constraints"`
			Notes       string   `json:"notes"`
		}
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return "参数解析失败: " + err.Error(), true
		}
		sid := strings.TrimSpace(args.ServerID)
		if sid == "" {
			return "缺少必填参数 server_id", true
		}
		if !isServerAllowed(c.token, sid) {
			return fmt.Sprintf("当前 MCP 令牌无权更新服务器 %s 的画像", sid), true
		}
		mem, err := s.store.UpsertHostMemory(vault.HostMemory{
			ServerID:    sid,
			Summary:     args.Summary,
			OSArch:      args.OSArch,
			KeyServices: args.KeyServices,
			DeployPaths: args.DeployPaths,
			PortsNote:   args.PortsNote,
			Constraints: args.Constraints,
			Notes:       args.Notes,
		}, true, c.clientIP)
		if err != nil {
			return "更新主机画像失败: " + err.Error(), true
		}
		s.store.RecordAudit("mcp.host_memory_update", mem.ServerName, fmt.Sprintf("外部 AI (%s) 增量更新主机画像", clientName), c.clientIP, true)
		return mustMarshalPretty(map[string]any{"ok": true, "host_memory": mem}), false

	case "save_memory":
		var args struct {
			Scope      string   `json:"scope"`
			ServerIDs  []string `json:"server_ids"`
			Category   string   `json:"category"`
			Title      string   `json:"title"`
			Content    string   `json:"content"`
			Tags       []string `json:"tags"`
			Importance int      `json:"importance"`
			Pinned     bool     `json:"pinned"`
		}
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return "参数解析失败: " + err.Error(), true
		}
		for _, sid := range args.ServerIDs {
			if !isServerAllowed(c.token, sid) {
				return fmt.Sprintf("当前 MCP 令牌无权写入服务器 %s 的记忆", sid), true
			}
		}
		tags := append(slices.Clone(args.Tags), clientName)
		saved, err := s.store.UpsertAIMemory(vault.AIMemoryEntry{
			Scope:      args.Scope,
			ServerIDs:  args.ServerIDs,
			Category:   args.Category,
			Title:      args.Title,
			Content:    args.Content,
			Tags:       tags,
			Importance: args.Importance,
			Pinned:     args.Pinned,
			Source:     "ai",
		}, true, c.clientIP)
		if err != nil {
			return "保存长期记忆失败: " + err.Error(), true
		}
		return mustMarshalPretty(map[string]any{"ok": true, "memory": saved}), false

	case "save_runbook":
		var args struct {
			Title           string   `json:"title"`
			Category        string   `json:"category"`
			Tags            []string `json:"tags"`
			Symptom         string   `json:"symptom"`
			RootCause       string   `json:"root_cause"`
			DiagnosticSteps []string `json:"diagnostic_steps"`
			FixCommands     []string `json:"fix_commands"`
			Verification    string   `json:"verification"`
		}
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return "参数解析失败: " + err.Error(), true
		}
		rb, err := s.store.UpsertRunbook(vault.AIRunbook{
			Title:           args.Title,
			Category:        args.Category,
			Tags:            append(slices.Clone(args.Tags), clientName),
			Symptom:         args.Symptom,
			RootCause:       args.RootCause,
			DiagnosticSteps: args.DiagnosticSteps,
			FixCommands:     args.FixCommands,
			Verification:    args.Verification,
		}, false, c.clientIP)
		if err != nil {
			return "保存 Runbook 失败: " + err.Error(), true
		}
		return mustMarshalPretty(map[string]any{"ok": true, "runbook": rb}), false

	case "propose_ssh_command":
		if c.token.Scope != vault.MCPScopeOpsPropose {
			return "权限不足：当前 MCP 令牌作用域为 patrol_readonly，仅支持只读取证与报告回写；如需提交变更审批提案，请使用 ops_propose 作用域令牌。", true
		}
		var args struct {
			ServerIDs      []string `json:"server_ids"`
			Command        string   `json:"command"`
			Reason         string   `json:"reason"`
			PatrolRecordID string   `json:"patrol_record_id"`
		}
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return "参数解析失败: " + err.Error(), true
		}
		for _, sid := range args.ServerIDs {
			if !isServerAllowed(c.token, sid) {
				return fmt.Sprintf("当前 MCP 令牌无权对服务器 %s 提交变更提案", sid), true
			}
		}
		ap, err := s.ai.CreateExternalApprovalProposal(c.reqCtx, aiops.ExternalApprovalProposalInput{
			PatrolRecordID: args.PatrolRecordID,
			TokenID:        c.token.ID,
			TokenName:      c.token.Name,
			ClientName:     clientName,
			ToolName:       "exec_ssh_command",
			ServerIDs:      args.ServerIDs,
			Command:        args.Command,
			Reason:         args.Reason,
			ClientIP:       c.clientIP,
		})
		if err != nil {
			return "提交命令审批提案失败: " + err.Error(), true
		}
		return mustMarshalPretty(map[string]any{
			"ok":               true,
			"approval_id":      ap.ID,
			"status":           ap.Status,
			"webhook_notified": ap.WebhookNotified,
			"message":          "变更命令已提交至 ServerNeedSafe Web 端「外部 AI 接管 (MCP) → 变更审批队列」，等待管理员手工批准后执行。批准后可调用 get_approval_status 查询真实执行输出。",
		}), false

	case "propose_sftp_write":
		if c.token.Scope != vault.MCPScopeOpsPropose {
			return "权限不足：当前 MCP 令牌作用域为 patrol_readonly，仅支持只读取证与报告回写；如需提交配置文件修改提案，请使用 ops_propose 作用域令牌。", true
		}
		var args struct {
			ServerID       string `json:"server_id"`
			Path           string `json:"path"`
			Content        string `json:"content"`
			Reason         string `json:"reason"`
			PatrolRecordID string `json:"patrol_record_id"`
		}
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return "参数解析失败: " + err.Error(), true
		}
		sid := strings.TrimSpace(args.ServerID)
		if sid == "" {
			return "缺少必填参数 server_id", true
		}
		if !isServerAllowed(c.token, sid) {
			return fmt.Sprintf("当前 MCP 令牌无权对服务器 %s 提交配置修改提案", sid), true
		}
		ap, err := s.ai.CreateExternalApprovalProposal(c.reqCtx, aiops.ExternalApprovalProposalInput{
			PatrolRecordID: args.PatrolRecordID,
			TokenID:        c.token.ID,
			TokenName:      c.token.Name,
			ClientName:     clientName,
			ToolName:       "sftp_write_file",
			ServerIDs:      []string{sid},
			FilePath:       args.Path,
			NewContent:     args.Content,
			Reason:         args.Reason,
			ClientIP:       c.clientIP,
		})
		if err != nil {
			return "提交文件修改提案失败: " + err.Error(), true
		}
		return mustMarshalPretty(map[string]any{
			"ok":               true,
			"approval_id":      ap.ID,
			"status":           ap.Status,
			"diff_preview":     ap.DiffPreview,
			"webhook_notified": ap.WebhookNotified,
			"message":          "配置文件修改与 Unified Diff 已提交至 ServerNeedSafe Web 端审批队列，等待管理员批准后写盘。批准后可调用 get_approval_status 查询执行结果。",
		}), false

	case "list_approvals":
		var args struct {
			Status string `json:"status"`
			Limit  int    `json:"limit"`
		}
		_ = json.Unmarshal(rawArgs, &args)
		status := strings.TrimSpace(args.Status)
		if status == "" {
			status = "pending"
		}
		if args.Limit <= 0 || args.Limit > 100 {
			args.Limit = 20
		}
		aps, pending, err := s.store.ListExternalApprovals(status, args.Limit)
		if err != nil {
			return "获取审批列表失败: " + err.Error(), true
		}
		filtered := filterApprovalsByToken(c.token, aps)
		return mustMarshalPretty(map[string]any{
			"pending_total": pending,
			"count":         len(filtered),
			"approvals":     filtered,
		}), false

	case "get_approval_status":
		var args struct {
			ApprovalID string `json:"approval_id"`
		}
		_ = json.Unmarshal(rawArgs, &args)
		apID := strings.TrimSpace(args.ApprovalID)
		if apID == "" {
			return "缺少必填参数 approval_id", true
		}
		ap, err := s.store.GetExternalApproval(apID)
		if err != nil {
			return "查询审批单失败: " + err.Error(), true
		}
		for _, sid := range ap.ServerIDs {
			if !isServerAllowed(c.token, sid) {
				return "当前 MCP 令牌无权查看该审批单", true
			}
		}
		// Omit raw NewContent to keep response concise; DiffPreview & ExecutionOut carry full context.
		ap.NewContent = ""
		return mustMarshalPretty(ap), false

	default:
		return "未知工具名称: " + name, true
	}
}

func isServerAllowed(tok *vault.MCPToken, serverID string) bool {
	if tok == nil || len(tok.AllowedServers) == 0 {
		return true
	}
	return slices.Contains(tok.AllowedServers, serverID)
}

func filterServerIDsByToken(tok *vault.MCPToken, requested []string) []string {
	if tok == nil || len(tok.AllowedServers) == 0 {
		return requested
	}
	if len(requested) == 0 {
		return slices.Clone(tok.AllowedServers)
	}
	out := make([]string, 0, len(requested))
	for _, sid := range requested {
		if slices.Contains(tok.AllowedServers, sid) {
			out = append(out, sid)
		}
	}
	return out
}

func filterServersByToken(tok *vault.MCPToken, servers []vault.ServerView) []vault.ServerView {
	if tok == nil || len(tok.AllowedServers) == 0 {
		return servers
	}
	out := make([]vault.ServerView, 0, len(servers))
	for _, srv := range servers {
		if slices.Contains(tok.AllowedServers, srv.ID) {
			out = append(out, srv)
		}
	}
	return out
}

func filterMonitorOverviewByToken(tok *vault.MCPToken, ov *vault.MonitorOverviewData) *vault.MonitorOverviewData {
	if ov == nil || tok == nil || len(tok.AllowedServers) == 0 {
		return ov
	}
	cp := *ov
	nodes := make([]vault.ServerMonitorCardItem, 0, len(ov.Nodes))
	for _, n := range ov.Nodes {
		if slices.Contains(tok.AllowedServers, n.Server.ID) {
			nodes = append(nodes, n)
		}
	}
	alerts := make([]vault.MonitorAlert, 0, len(ov.Alerts))
	for _, al := range ov.Alerts {
		if slices.Contains(tok.AllowedServers, al.ServerID) {
			alerts = append(alerts, al)
		}
	}
	cp.Nodes = nodes
	cp.Alerts = alerts
	return &cp
}

func filterSinglePatrolRecordByToken(tok *vault.MCPToken, rec vault.PatrolRecord) vault.PatrolRecord {
	if tok == nil || len(tok.AllowedServers) == 0 {
		return rec
	}
	cp := rec
	findings := make([]vault.PatrolFinding, 0, len(rec.Findings))
	for _, f := range rec.Findings {
		if slices.Contains(tok.AllowedServers, f.ServerID) {
			findings = append(findings, f)
		}
	}
	cp.Findings = findings
	return cp
}

func filterPatrolRecordsByToken(tok *vault.MCPToken, recs []vault.PatrolRecord) []vault.PatrolRecord {
	if tok == nil || len(tok.AllowedServers) == 0 {
		return recs
	}
	out := make([]vault.PatrolRecord, 0, len(recs))
	for _, r := range recs {
		filtered := filterSinglePatrolRecordByToken(tok, r)
		if len(filtered.Findings) > 0 || len(r.Findings) == 0 {
			out = append(out, filtered)
		}
	}
	return out
}

func filterApprovalsByToken(tok *vault.MCPToken, aps []vault.ExternalApproval) []vault.ExternalApproval {
	if tok == nil || len(tok.AllowedServers) == 0 {
		return aps
	}
	out := make([]vault.ExternalApproval, 0, len(aps))
	for _, ap := range aps {
		ok := true
		for _, sid := range ap.ServerIDs {
			if !slices.Contains(tok.AllowedServers, sid) {
				ok = false
				break
			}
		}
		if ok {
			cp := ap
			cp.NewContent = ""
			out = append(out, cp)
		}
	}
	return out
}

func isBlockedReadPath(rawPath string) bool {
	clean := path.Clean(strings.ReplaceAll(strings.TrimSpace(rawPath), "\\", "/"))
	low := strings.ToLower(clean)
	base := strings.ToLower(path.Base(clean))
	if low == "/etc/shadow" || low == "/etc/gshadow" || low == "/etc/sudoers" {
		return true
	}
	if base == "secrets.enc" || base == "master.key" || base == ".vault.key" || base == "vault.sns" {
		return true
	}
	if strings.Contains(low, "/.ssh/") {
		switch base {
		case "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "identity":
			return true
		}
		if strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") {
			return true
		}
	}
	return false
}

func mustMarshalPretty(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err.Error())
	}
	return string(b)
}
