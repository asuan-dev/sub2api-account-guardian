package guardian

import (
	"bufio"
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type WebServer struct {
	cfg     Config
	store   *Store
	auditor *Auditor
	service *Service
}

func NewWebServer(cfg Config, store *Store, auditor *Auditor, service *Service) *WebServer {
	return &WebServer{cfg: cfg, store: store, auditor: auditor, service: service}
}

func (w *WebServer) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", w.handleIndex)
	mux.HandleFunc("/api/summary", w.handleSummary)
	mux.HandleFunc("/api/accounts", w.handleAccounts)
	mux.HandleFunc("/api/logs", w.handleLogs)
	mux.HandleFunc("/api/config", w.handleConfig)
	mux.HandleFunc("/api/revive-deleted", w.handleReviveDeleted)
	mux.HandleFunc("/api/revive-deleted-status", w.handleReviveDeletedStatus)
	srv := &http.Server{Addr: w.cfg.WebAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Printf("web panel listening addr=%s", w.cfg.WebAddr)
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (w *WebServer) handleReviveDeleted(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Workers int `json:"workers"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Workers <= 0 {
		req.Workers = 5
	}
	if req.Workers > 20 {
		req.Workers = 20
	}
	status, started := w.service.StartDeletedReviveAll(req.Workers)
	message := "软删除账号全量复活检测已在后台启动，并发 " + strconv.Itoa(req.Workers)
	if !started {
		message = "软删除账号全量复活检测已在运行，未重复启动"
	}
	writeJSON(rw, map[string]any{"ok": true, "started": started, "message": message, "status": reviveStatusJSON(status)})
}

func (w *WebServer) handleReviveDeletedStatus(rw http.ResponseWriter, r *http.Request) {
	writeJSON(rw, map[string]any{"ok": true, "status": reviveStatusJSON(w.service.DeletedReviveStatus())})
}

func (w *WebServer) handleIndex(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = panelTemplate.Execute(rw, nil)
}

func (w *WebServer) handleSummary(rw http.ResponseWriter, r *http.Request) {
	summary, err := w.store.AccountSummary(r.Context())
	writeJSON(rw, map[string]any{"ok": err == nil, "summary": summary, "error": errString(err)})
}

func (w *WebServer) handleAccounts(rw http.ResponseWriter, r *http.Request) {
	accounts, err := w.store.RecentAccounts(r.Context(), 200)
	if err != nil {
		writeJSON(rw, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	type row struct {
		ID           int64  `json:"id"`
		Name         string `json:"name"`
		Status       string `json:"status"`
		StatusCN     string `json:"status_cn"`
		Schedulable  bool   `json:"schedulable"`
		Deleted      bool   `json:"deleted"`
		ErrorMessage string `json:"error_message"`
		ErrorCN      string `json:"error_cn"`
		UpdatedAt    string `json:"updated_at"`
	}
	out := make([]row, 0, len(accounts))
	for _, acc := range accounts {
		out = append(out, row{
			ID:           acc.ID,
			Name:         acc.Name,
			Status:       acc.Status,
			StatusCN:     statusCN(acc),
			Schedulable:  acc.Schedulable,
			Deleted:      acc.Deleted,
			ErrorMessage: truncate(acc.ErrorMessage, 240),
			ErrorCN:      evidenceCN(ClassifyEvidence(acc.ErrorMessage)),
			UpdatedAt:    acc.UpdatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	writeJSON(rw, map[string]any{"ok": true, "accounts": out})
}

func (w *WebServer) handleLogs(rw http.ResponseWriter, r *http.Request) {
	records, err := readAuditRecords(w.auditor.Path(), 200)
	if err != nil {
		writeJSON(rw, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(rw, map[string]any{"ok": true, "logs": records})
}

func (w *WebServer) handleConfig(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(rw, map[string]any{"ok": true, "config": w.cfg.PanelConfig(), "config_path": w.cfg.ConfigPath})
	case http.MethodPost:
		var pc PanelConfig
		if err := json.NewDecoder(r.Body).Decode(&pc); err != nil {
			writeJSON(rw, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if strings.Contains(pc.Sub2APIKey, "...") || pc.Sub2APIKey == "***" {
			pc.Sub2APIKey = w.cfg.Sub2APIKey
		}
		if strings.Contains(pc.DatabaseURL, "***") {
			pc.DatabaseURL = w.cfg.DatabaseURL
		}
		if err := SavePanelConfig(w.cfg.ConfigPath, pc); err != nil {
			writeJSON(rw, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(rw, map[string]any{"ok": true, "message": "配置已保存，重启 guardian 后生效"})
	default:
		rw.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type ChineseAuditRecord struct {
	AccountID      int64  `json:"account_id"`
	AccountName    string `json:"account_name"`
	StartedAt      string `json:"started_at"`
	InitialStatus  string `json:"initial_status"`
	Classification string `json:"classification"`
	Refresh        string `json:"refresh"`
	Test           string `json:"test"`
	Action         string `json:"action"`
	Reason         string `json:"reason"`
	RawAction      string `json:"raw_action"`
}

func reviveStatusJSON(status DeletedReviveJobStatus) map[string]any {
	return map[string]any{
		"running":        status.Running,
		"started_at":     formatTime(status.StartedAt),
		"finished_at":    formatTime(status.FinishedAt),
		"total":          status.Total,
		"processed":      status.Processed,
		"restored":       status.Restored,
		"quota_restored": status.QuotaRestored,
		"kept_deleted":   status.KeptDeleted,
		"unknown":        status.Unknown,
		"failed":         status.Failed,
		"last_error":     reasonCN(status.LastError),
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}

func readAuditRecords(path string, limit int) ([]ChineseAuditRecord, error) {
	fh, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []ChineseAuditRecord{}, nil
		}
		return nil, err
	}
	defer fh.Close()
	var records []AuditRecord
	scanner := bufio.NewScanner(fh)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec AuditRecord
		if err := json.Unmarshal([]byte(line), &rec); err == nil {
			records = append(records, rec)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].StartedAt.After(records[j].StartedAt) })
	if len(records) > limit {
		records = records[:limit]
	}
	out := make([]ChineseAuditRecord, 0, len(records))
	for _, rec := range records {
		out = append(out, chineseAuditRecord(rec))
	}
	return out, nil
}

func chineseAuditRecord(rec AuditRecord) ChineseAuditRecord {
	return ChineseAuditRecord{
		AccountID:      rec.AccountID,
		AccountName:    rec.AccountName,
		StartedAt:      rec.StartedAt.Format("2006-01-02 15:04:05"),
		InitialStatus:  rec.InitialStatus,
		Classification: evidenceCN(rec.Classification),
		Refresh:        refreshCN(rec),
		Test:           testCN(rec),
		Action:         actionCN(rec.FinalAction),
		Reason:         reasonCN(rec.FinalReason),
		RawAction:      rec.FinalAction,
	}
}

func writeJSON(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(rw).Encode(v)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func statusCN(acc Account) string {
	if acc.Deleted {
		return "已软删除"
	}
	if acc.Status == "error" {
		return "错误"
	}
	if acc.Status == "active" && !acc.Schedulable {
		return "正常但调度关闭"
	}
	if acc.Status == "active" {
		return "正常"
	}
	return acc.Status
}

func evidenceCN(cls EvidenceClass) string {
	switch cls {
	case ClassEligibleAuth:
		return "账号认证错误，可处理"
	case ClassInfrastructure:
		return "网络/上游不稳定，不删除"
	case ClassQuota:
		return "限流/额度，不删除"
	case ClassRequestParameter:
		return "请求参数问题，不删除"
	case ClassNeedsRelogin:
		return "需要重新登录，关闭调度"
	default:
		return "非目标错误"
	}
}

func actionCN(action string) string {
	switch action {
	case "revived":
		return "复活成功，已恢复调度"
	case "kept_live":
		return "账号可用，已保留"
	case "kept_quota":
		return "限流/额度，保留给 Sub2API 处理"
	case "kept_unknown":
		return "结果不确定，未删除"
	case "soft_deleted":
		return "确认死亡，已软删除"
	case "skipped_infrastructure_failure":
		return "网络问题，跳过"
	case "skipped_not_eligible":
		return "不是账号内部错误，跳过"
	case "would_process":
		return "演练模式：仅记录未处理"
	case "needs_relogin":
		return "需要重新登录，已关闭调度"
	case "restored_deleted":
		return "软删除账号复活成功，已恢复"
	case "restored_deleted_quota":
		return "软删除账号可刷新但限流，已恢复"
	case "deleted_kept":
		return "软删除账号仍不可用，继续软删除"
	case "would_check_deleted_revive":
		return "演练模式：会检测软删除账号复活"
	default:
		if action == "" {
			return "处理中/无结果"
		}
		return action
	}
}

func refreshCN(rec AuditRecord) string {
	if !rec.RefreshAttempted {
		if rec.RefreshResult == "missing_refresh_token" {
			return "没有 refresh token"
		}
		return "未尝试刷新"
	}
	if rec.RefreshResult == "ok" {
		return "刷新 token 成功"
	}
	if rec.RefreshResult == "failed" {
		return "刷新 token 失败：" + truncate(rec.RefreshReason, 120)
	}
	return rec.RefreshResult
}

func testCN(rec AuditRecord) string {
	switch rec.TestResult {
	case TestOK:
		return "gpt-5.4-mini 测活成功"
	case TestDead:
		return "gpt-5.4-mini 确认死亡：" + truncate(rec.TestReason, 120)
	case TestQuota:
		return "测到限流/额度"
	case TestUnknown:
		return "测活不确定：" + truncate(rec.TestReason, 120)
	default:
		return "未测活"
	}
}

func reasonCN(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return ""
	}
	replacer := strings.NewReplacer(
		"deterministic auth death after revive/test", "复活/测活后仍是确定认证死亡",
		"live check succeeded", "测活成功",
		"test uncertain", "测活结果不确定",
		"quota/rate-limit belongs to Sub2API handling", "限流/额度由 Sub2API 自己处理",
		"needs manual relogin", "需要人工重新登录",
		"soft-deleted account revived and live check succeeded", "软删除账号复活并测活成功",
		"soft-deleted account still not live", "软删除账号仍不可用",
		"refresh failed for soft-deleted account", "软删除账号刷新失败",
	)
	return truncate(replacer.Replace(reason), 180)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}

var panelTemplate = template.Must(template.New("panel").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sub2API Account Guardian</title>
  <style>
    body{margin:0;background:#0f172a;color:#dbeafe;font-family:Arial,"Microsoft YaHei",sans-serif}
    header{padding:18px 24px;background:#111827;border-bottom:1px solid #334155}
    h1{margin:0;font-size:20px} main{padding:20px;display:grid;gap:18px}
    section{background:#111827;border:1px solid #334155;border-radius:10px;padding:16px}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}
    .card{background:#0b1220;border:1px solid #1e293b;border-radius:8px;padding:12px}
    .num{font-size:24px;font-weight:700;color:#5eead4}
    table{width:100%;border-collapse:collapse;font-size:13px}
    th,td{border-bottom:1px solid #263244;padding:9px;text-align:left;vertical-align:top}
    th{color:#93c5fd;background:#0b1220;position:sticky;top:0}
    input{width:100%;box-sizing:border-box;background:#0b1220;border:1px solid #334155;border-radius:6px;color:#e5e7eb;padding:8px}
    button{background:#14b8a6;border:0;border-radius:6px;color:#06231f;font-weight:700;padding:8px 14px;cursor:pointer}
    .muted{color:#94a3b8}.bad{color:#fca5a5}.ok{color:#86efac}.warn{color:#fde68a}
    .scroll{max-height:520px;overflow:auto}
  </style>
</head>
<body>
<header><h1>Sub2API Account Guardian 面板</h1><div class="muted">账号异常自动摘除调度、复活、测活、软删除审计</div></header>
<main>
  <section><h2>状态总览</h2><div id="summary" class="grid"></div></section>
  <section><h2>配置</h2><div class="grid" id="config"></div><p class="muted">保存后需要重启 guardian 生效。敏感值显示为脱敏；如需修改请填完整值。</p><button onclick="saveConfig()">保存配置</button> <span id="saveMsg"></span></section>
  <section><h2>最近账号</h2><div class="scroll"><table><thead><tr><th>ID</th><th>账号</th><th>状态</th><th>调度</th><th>错误分类</th><th>错误信息</th><th>更新时间</th></tr></thead><tbody id="accounts"></tbody></table></div></section>
  <section><h2>软删除账号复活检测</h2><p class="muted">手动功能：并发检测所有已软删除且有 refresh_token 的账号。正常就恢复成正常账号并打开调度；失败继续软删除。</p><label class="card" style="display:block;max-width:220px"><div class="muted">并发数</div><input id="reviveWorkers" value="5"></label><button onclick="reviveDeleted()">开始全量检测软删除账号</button> <span id="reviveMsg"></span><div id="reviveStatus" class="grid" style="margin-top:12px"></div></section>
  <section><h2>处理日志（中文）</h2><div class="scroll"><table><thead><tr><th>时间</th><th>ID</th><th>账号</th><th>分类</th><th>刷新</th><th>测活</th><th>最终动作</th><th>原因</th></tr></thead><tbody id="logs"></tbody></table></div></section>
</main>
<script>
let currentConfig={}
async function j(url, opts){const r=await fetch(url,opts);return await r.json()}
function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
async function loadSummary(){const d=await j('/api/summary'); const el=document.getElementById('summary'); el.innerHTML=''; if(!d.ok){el.textContent=d.error;return} Object.entries(d.summary).forEach(([k,v])=>{el.innerHTML+='<div class="card"><div class="muted">'+esc(k)+'</div><div class="num">'+esc(v)+'</div></div>'})}
async function loadConfig(){const d=await j('/api/config'); if(!d.ok)return; currentConfig=d.config; const keys=[['sub2api_url','Sub2API 地址'],['sub2api_key','Admin Key'],['database_url','数据库 URL'],['test_model','测活模型'],['openai_group_id','OpenAI 分组ID'],['monitor_interval_seconds','扫描间隔秒'],['monitor_batch_size','批量大小'],['test_workers','测活并发'],['refresh_workers','刷新并发'],['retry_attempts','重试次数'],['retry_delay_ms','重试间隔毫秒']]; const el=document.getElementById('config'); el.innerHTML=''; keys.forEach(([k,label])=>{el.innerHTML+='<label class="card"><div class="muted">'+esc(label)+'</div><input id="cfg_'+esc(k)+'" value="'+esc(currentConfig[k]??'')+'"></label>'})}
async function saveConfig(){const body={}; document.querySelectorAll('[id^=cfg_]').forEach(i=>{let k=i.id.slice(4),v=i.value; if(['openai_group_id','monitor_interval_seconds','monitor_batch_size','test_workers','refresh_workers','retry_attempts','retry_delay_ms'].includes(k)) v=parseInt(v||'0',10); body[k]=v}); const d=await j('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); document.getElementById('saveMsg').textContent=d.ok?d.message:d.error}
async function loadAccounts(){const d=await j('/api/accounts'); const el=document.getElementById('accounts'); el.innerHTML=''; if(!d.ok){el.textContent=d.error;return} d.accounts.forEach(a=>{el.innerHTML+='<tr><td>'+esc(a.id)+'</td><td>'+esc(a.name)+'</td><td>'+esc(a.status_cn)+'</td><td>'+(a.schedulable?'开启':'关闭')+'</td><td>'+esc(a.error_cn)+'</td><td>'+esc(a.error_message||'')+'</td><td>'+esc(a.updated_at)+'</td></tr>'})}
async function loadLogs(){const d=await j('/api/logs'); const el=document.getElementById('logs'); el.innerHTML=''; if(!d.ok){el.textContent=d.error;return} d.logs.forEach(x=>{el.innerHTML+='<tr><td>'+esc(x.started_at)+'</td><td>'+esc(x.account_id)+'</td><td>'+esc(x.account_name)+'</td><td>'+esc(x.classification)+'</td><td>'+esc(x.refresh)+'</td><td>'+esc(x.test)+'</td><td>'+esc(x.action)+'</td><td>'+esc(x.reason)+'</td></tr>'})}
async function loadReviveStatus(){const d=await j('/api/revive-deleted-status'); const el=document.getElementById('reviveStatus'); if(!d.ok){el.textContent=d.error;return} const s=d.status; const items={'运行中':s.running?'是':'否','总数':s.total,'已处理':s.processed,'成功恢复':s.restored,'限流恢复':s.quota_restored,'继续软删除':s.kept_deleted,'不确定':s.unknown,'失败':s.failed}; el.innerHTML=''; Object.entries(items).forEach(([k,v])=>{el.innerHTML+='<div class="card"><div class="muted">'+esc(k)+'</div><div class="num">'+esc(v)+'</div></div>'}); if(s.last_error){el.innerHTML+='<div class="card"><div class="muted">最近原因</div><div>'+esc(s.last_error)+'</div></div>'}}
async function reviveDeleted(){const workers=parseInt(document.getElementById('reviveWorkers').value||'5',10); document.getElementById('reviveMsg').textContent='已提交后台任务...'; const d=await j('/api/revive-deleted',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({workers})}); document.getElementById('reviveMsg').textContent=d.ok?d.message:d.error; await loadReviveStatus(); refresh()}
async function refresh(){await Promise.all([loadSummary(),loadAccounts(),loadLogs(),loadReviveStatus()])}
loadConfig(); refresh(); setInterval(refresh,5000)
</script>
</body></html>`))
