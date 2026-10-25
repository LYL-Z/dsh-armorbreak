/**
 * ArmorBreak browser half: an ambient composer-dock card that shows live mode
 * status and a small read-only research workbench (overview / tasks / tools).
 * Data comes from loopback-only Host routes `/armorbreak/state`, `/armorbreak/tasks`
 * and `/armorbreak/tools`; the card never starts analysis, never writes, and never
 * renders raw evidence excerpts or credentials.
 */
window.__ModuleLoader__.load({
  id: 'dsh-armorbreak',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const { useEffect, useState, useCallback } = React

    const DICT = {
      en: {
        title: 'ArmorBreak',
        subtitle: 'Authorized security research mode',
        loading: 'Loading mode status…',
        error: 'Status endpoint unavailable',
        refresh: 'Refresh',
        capabilities: 'capabilities',
        tasks: 'tasks',
        isolation: 'isolation',
        unavailable: 'unavailable',
        recentTasks: 'Recent tasks',
        noTasks: 'No tasks yet. Start one from the ArmorBreak mode chat.',
        open: 'Show ArmorBreak status',
        close: 'Hide ArmorBreak status',
        workspace: 'last used workspace',
        workspaceNote: 'The card reports the process MRU workspace; per-session workspace binding is not implemented yet.',
        risk: 'risk',
        evidence: 'evidence',
        findings: 'findings',
        l0: 'L0 offline',
        l1: 'L1 dynamic',
        l2: 'L2 active',
        l3: 'L3 denied',
        overview: 'Overview',
        taskCenter: 'Tasks',
        toolCenter: 'Tools',
        back: 'Back',
        detail: 'Task detail',
        steps: 'Steps',
        report: 'Report',
        noReport: 'No report yet',
        status: 'Status',
        queue: 'Background queue',
        idle: 'idle',
        externalTools: 'External tools',
        notProbed: 'not probed',
        domain: 'Domain',
        findingsTitle: 'Findings',
        noFindings: 'No findings recorded.',
        loadingDetail: 'Loading task…',
        workspaceBinding: 'Workspace binding',
        createTask: 'New L0 task',
        workflow: 'Workflow',
        targetPath: 'Target path (absolute)',
        taskTitle: 'Title (optional)',
        submit: 'Create task',
        cancel: 'Cancel task',
        retry: 'Retry failed steps',
        resume: 'Resume task',
        evidenceExplorer: 'Evidence',
        loadEvidence: 'Load evidence',
        reportPreview: 'Report preview',
        loadReport: 'Load report',
        environment: 'Environment',
        environmentHint: 'Isolation providers (detection is not isolation)',
        refreshEnvironment: 'Refresh environment',
        loadingEnvironment: 'Loading providers…',
        severity: 'Severity',
        verification: 'Verification',
        all: 'All',
        reportFormat: 'Format',
        actionFailed: 'Action failed',
        probe: 'Probe tools',
        probing: 'Probing…',
        toolsProbed: 'External tools',
        closePreview: 'Close',
        network: 'Network',
        networkState: 'Connectivity',
        connectors: 'Data connectors',
        resources: 'Read-only resources',
        failures: 'failures',
        successes: 'successes',
        breaker: 'breaker',
        offlineHint: 'Offline analysis remains available; resource updates are read-only and never grant L2.',
        evaluations: 'Evaluations',
        knowledge: 'Knowledge',
        catalog: 'Catalog',
        runEvaluation: 'Run authorized mock evaluation',
        evaluationPrompt: 'Prompt / scenario text',
        evaluationCategory: 'Category',
        noEvaluations: 'No evaluations yet.',
        searchKnowledge: 'Search knowledge',
        search: 'Search',
        noKnowledge: 'No matching knowledge.',
        catalogHint: 'Read-only connector metadata; installation is never automatic.',
        installations: 'Installations',
        reports: 'Evaluations report',
        missingTools: 'Missing external tools',
        recoveryPath: 'Recovery: install the named tool, or use the documented built-in alternative. Offline L0 remains available.',
        reportHint: 'Mock evaluation dashboard; live model calls are not claimed.',
        installHint: 'Plan → stage → verify → explicit approve → activate. Package scripts never run.',
        artifactPath: 'Artifact path (absolute)',
        planInstall: 'Plan install',
        noInstallations: 'No installation plans.',
      },
      zh: {
        title: '破甲模式',
        subtitle: '授权逆向工程与安全研究',
        loading: '正在读取模式状态…',
        error: '状态接口不可用',
        refresh: '刷新',
        capabilities: '项能力',
        tasks: '个任务',
        isolation: '隔离环境',
        unavailable: '不可用',
        recentTasks: '最近任务',
        noTasks: '还没有任务。在破甲模式对话中创建分析任务。',
        open: '展开破甲模式状态',
        close: '收起破甲模式状态',
        workspace: '最近使用的工作区',
        workspaceNote: '状态卡显示进程最近使用的工作区；会话级工作区绑定尚未实现。',
        risk: '风险',
        evidence: '证据',
        findings: '发现',
        l0: 'L0 离线',
        l1: 'L1 动态',
        l2: 'L2 主动',
        l3: 'L3 拒绝',
        overview: '概览',
        taskCenter: '任务',
        toolCenter: '工具',
        back: '返回',
        detail: '任务详情',
        steps: '步骤',
        report: '报告',
        noReport: '尚未生成报告',
        status: '状态',
        queue: '后台队列',
        idle: '空闲',
        externalTools: '外部工具',
        notProbed: '未探测',
        domain: '能力域',
        findingsTitle: '发现',
        noFindings: '尚未记录发现。',
        loadingDetail: '正在读取任务…',
        workspaceBinding: '工作区绑定',
        createTask: '新建 L0 任务',
        workflow: '工作流',
        targetPath: '目标路径（绝对路径）',
        taskTitle: '标题（可选）',
        submit: '创建任务',
        cancel: '取消任务',
        retry: '重试失败步骤',
        resume: '恢复任务',
        evidenceExplorer: '证据',
        loadEvidence: '加载证据',
        reportPreview: '报告预览',
        loadReport: '加载报告',
        environment: '隔离环境',
        environmentHint: '隔离提供者诊断（检测到 ≠ 已隔离）',
        refreshEnvironment: '刷新环境',
        loadingEnvironment: '正在探测提供者…',
        severity: '严重度',
        verification: '验证级别',
        all: '全部',
        reportFormat: '格式',
        actionFailed: '操作失败',
        probe: '探测工具',
        probing: '探测中…',
        toolsProbed: '外部工具',
        closePreview: '关闭',
        network: '网络',
        networkState: '连接状态',
        connectors: '数据连接器',
        resources: '只读资源',
        failures: '失败',
        successes: '成功',
        breaker: '熔断',
        offlineHint: '离线分析仍然可用；资源更新只读，且不会授予 L2。',
        evaluations: '评测',
        knowledge: '知识',
        catalog: '目录',
        runEvaluation: '运行授权 mock 评测',
        evaluationPrompt: 'Prompt / 场景文本',
        evaluationCategory: '类别',
        noEvaluations: '尚无评测。',
        searchKnowledge: '检索知识',
        search: '检索',
        noKnowledge: '没有匹配的知识。',
        catalogHint: '只读连接器元数据；安装永远不会自动执行。',
        installations: '安装',
        reports: '评测报告',
        missingTools: '缺失外部工具',
        recoveryPath: '恢复：安装对应工具，或使用文档中的内置替代；离线 L0 仍可用。',
        reportHint: 'Mock 评测仪表盘；不宣称实时模型调用。',
        installHint: '计划 → staging → 校验 → 显式批准 → 激活；不执行包脚本。',
        artifactPath: '安装包路径（绝对路径）',
        planInstall: '创建安装计划',
        noInstallations: '尚无安装计划。',
      },
    }

    /** @param {string} state */
    function stateColor(state) {
      if (state === 'COMPLETED') return 'var(--dsw-alias-state-success-primary)'
      if (state === 'PARTIAL_SUCCESS' || state === 'RECOVERABLE' || state === 'INTERRUPTED' || state === 'PAUSED' || state === 'WAITING') return 'var(--dsw-alias-state-warn-primary)'
      if (['FAILED', 'REJECTED', 'TIMED_OUT', 'CANCELLED'].includes(state)) return 'var(--dsw-alias-state-error-primary)'
      return 'var(--dsw-alias-brand-primary)'
    }

    /** @param {string} severity */
    function severityColor(severity) {
      if (severity === 'critical') return 'var(--dsw-alias-state-error-primary)'
      if (severity === 'high') return 'var(--dsw-alias-state-warn-primary)'
      if (severity === 'medium') return 'var(--dsw-alias-brand-primary)'
      return 'var(--dsw-alias-label-secondary)'
    }

    /** @param {any} value */
    function shortPath(value) {
      const text = String(value ?? '')
      if (text.length <= 64) return text
      return `…${text.slice(-61)}`
    }

    function StatusCard(props) {
      const { sessionId } = props
      const [t, setT] = useState(DICT.zh)
      const [open, setOpen] = useState(false)
      const [tab, setTab] = useState('overview')
      const [state, setState] = useState(null)
      const [error, setError] = useState(null)
      const [busy, setBusy] = useState(false)
      const [detail, setDetail] = useState(null)
      const [detailError, setDetailError] = useState(null)
      const [workflows, setWorkflows] = useState([])
      const [form, setForm] = useState({ workflow: '', target: '', title: '' })
      const [actionError, setActionError] = useState(null)
      const [evidence, setEvidence] = useState(null)
      const [report, setReport] = useState(null)
      const [toolProbe, setToolProbe] = useState(null)
      const [probing, setProbing] = useState(false)
      const [environment, setEnvironment] = useState(null)
      const [environmentLoading, setEnvironmentLoading] = useState(false)
      const [evidenceSeverity, setEvidenceSeverity] = useState('')
      const [evidenceVerification, setEvidenceVerification] = useState('')
      const [reportFormat, setReportFormat] = useState('markdown')
      const [evaluationItems, setEvaluationItems] = useState([])
      const [evaluationForm, setEvaluationForm] = useState({ prompt: '', category: 'prompt-injection' })
      const [evaluationBusy, setEvaluationBusy] = useState(false)
      const [knowledgeQuery, setKnowledgeQuery] = useState('')
      const [knowledgeResults, setKnowledgeResults] = useState(null)
      const [catalogItems, setCatalogItems] = useState(null)
      const [researchError, setResearchError] = useState(null)
      const [installItems, setInstallItems] = useState([])
      const [reportDashboard, setReportDashboard] = useState(null)
      const [installForm, setInstallForm] = useState({ artifactPath: '', license: 'MIT', commit: '', digest: 'sha256:local', components: '' })
      const [installBusy, setInstallBusy] = useState(false)
      const withSession = useCallback((url) => (sessionId ? `${url}${url.includes('?') ? '&' : '?'}session=${encodeURIComponent(String(sessionId))}` : url), [sessionId])

      const postAction = useCallback(async (payload) => {
        setActionError(null)
        try {
          const response = await fetch(withSession('/armorbreak/actions'), {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'x-armorbreak-ui': '1' },
            credentials: 'same-origin',
            body: JSON.stringify(payload),
          })
          const data = await response.json().catch(() => ({}))
          if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`)
          await load()
          return data
        } catch (cause) {
          setActionError(String(cause && cause.message ? cause.message : cause))
          return null
        }
      // `load` is declared below (a stable useCallback with no deps); postAction
      // only runs from user events, so referencing it in the body is safe. Keep
      // the dependency list empty to avoid a render-time TDZ crash.
      }, [])

      const load = useCallback(async () => {
        setBusy(true)
        try {
          const response = await fetch(withSession('/armorbreak/state'), { headers: { accept: 'application/json' }, credentials: 'same-origin' })
          if (!response.ok) throw new Error(`HTTP ${response.status}`)
          setState(await response.json())
          setError(null)
        } catch (cause) {
          setError(String(cause && cause.message ? cause.message : cause))
        } finally {
          setBusy(false)
        }
      }, [])

      useEffect(() => {
        if (!open) return undefined
        void load()
        const timer = setInterval(() => void load(), 15000)
        return () => clearInterval(timer)
      }, [open, load])

      useEffect(() => {
        let disposed = false
        try {
          const ctx = props.__ctx
          const locale = ctx && typeof ctx.get === 'function' ? ctx.get('locale') : undefined
          if (locale && typeof locale.getLocale === 'function') {
            const snapshot = locale.getLocale()
            const id = snapshot && (snapshot.id || snapshot.locale) ? String(snapshot.id || snapshot.locale) : 'zh'
            if (!disposed && DICT[id]) setT(DICT[id])
          }
        } catch {
          /* keep default */
        }
        return () => {
          disposed = true
        }
      }, [props.__ctx])

      const loadDetail = useCallback(async (taskId) => {
        setDetailError(null)
        setDetail({ loading: true })
        setEvidence(null)
        setReport(null)
        try {
          const response = await fetch(withSession(`/armorbreak/tasks?id=${encodeURIComponent(taskId)}`), { headers: { accept: 'application/json' }, credentials: 'same-origin' })
          if (!response.ok) throw new Error(`HTTP ${response.status}`)
          setDetail(await response.json())
        } catch (cause) {
          setDetail(null)
          setDetailError(String(cause && cause.message ? cause.message : cause))
        }
      }, [])

      const loadEvidence = useCallback(async (taskId, filters = {}) => {
        const severity = filters.severity ?? evidenceSeverity
        const verification = filters.verification ?? evidenceVerification
        const params = new URLSearchParams({ taskId: String(taskId) })
        if (severity) params.set('severity', severity)
        if (verification) params.set('verification', verification)
        try {
          const response = await fetch(withSession(`/armorbreak/evidence?${params.toString()}`), { headers: { accept: 'application/json' }, credentials: 'same-origin' })
          const data = await response.json().catch(() => ({}))
          if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`)
          setEvidence(data)
        } catch (cause) {
          setActionError(String(cause && cause.message ? cause.message : cause))
        }
      }, [withSession, evidenceSeverity, evidenceVerification])

      const applyEvidenceFilters = useCallback((taskId, severity, verification) => {
        setEvidenceSeverity(severity)
        setEvidenceVerification(verification)
        void loadEvidence(taskId, { severity, verification })
      }, [loadEvidence])

      const loadReport = useCallback(async (taskId, format = reportFormat) => {
        setReport({ loading: true })
        try {
          const response = await fetch(withSession(`/armorbreak/report?taskId=${encodeURIComponent(taskId)}&format=${encodeURIComponent(format)}`), { headers: { accept: 'application/json' }, credentials: 'same-origin' })
          const data = await response.json().catch(() => ({}))
          if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`)
          setReport(data)
        } catch (cause) {
          setReport({ error: String(cause && cause.message ? cause.message : cause) })
        }
      }, [withSession, reportFormat])

      const loadEnvironment = useCallback(async () => {
        setEnvironmentLoading(true)
        try {
          const response = await fetch(withSession('/armorbreak/environment'), { headers: { accept: 'application/json' }, credentials: 'same-origin' })
          if (response.ok) setEnvironment(await response.json())
        } catch {
          /* keep previous provider snapshot */
        } finally {
          setEnvironmentLoading(false)
        }
      }, [withSession])

      const loadWorkflows = useCallback(async () => {
        try {
          const response = await fetch(withSession('/armorbreak/tools'), { headers: { accept: 'application/json' }, credentials: 'same-origin' })
          if (!response.ok) return
          const data = await response.json()
          if (Array.isArray(data.workflows)) setWorkflows(data.workflows)
        } catch {
          /* workflow list is optional */
        }
      }, [])

      const loadEvaluations = useCallback(async () => {
        try {
          const response = await fetch(withSession('/armorbreak/evaluations?limit=20'), { headers: { accept: 'application/json' }, credentials: 'same-origin' })
          const data = await response.json().catch(() => ({}))
          if (!response.ok) throw new Error(data.error || String(response.status))
          setEvaluationItems(Array.isArray(data.items) ? data.items : [])
        } catch (cause) { setResearchError(String(cause && cause.message ? cause.message : cause)) }
      }, [withSession])
      const loadKnowledge = useCallback(async (query) => {
        try {
          const q = String(query || knowledgeQuery || "").trim()
          const response = await fetch(withSession('/armorbreak/knowledge?q=' + encodeURIComponent(q)), { headers: { accept: 'application/json' }, credentials: 'same-origin' })
          const data = await response.json().catch(() => ({}))
          if (!response.ok) throw new Error(data.error || String(response.status))
          setKnowledgeResults(data)
        } catch (cause) { setResearchError(String(cause && cause.message ? cause.message : cause)) }
      }, [withSession, knowledgeQuery])
      const loadReportDashboard = useCallback(async () => {
        try {
          const response = await fetch(withSession('/armorbreak/llm-report'), { headers: { accept: 'application/json' }, credentials: 'same-origin' })
          const data = await response.json().catch(() => ({}))
          if (!response.ok) throw new Error(data.error || String(response.status))
          setReportDashboard(data)
        } catch (cause) { setResearchError(String(cause && cause.message ? cause.message : cause)) }
      }, [withSession])
      const loadInstallations = useCallback(async () => {
        try {
          const response = await fetch(withSession('/armorbreak/installations'), { headers: { accept: 'application/json' }, credentials: 'same-origin' })
          const data = await response.json().catch(() => ({}))
          if (!response.ok) throw new Error(data.error || String(response.status))
          setInstallItems(Array.isArray(data.items) ? data.items : [])
        } catch (cause) { setResearchError(String(cause && cause.message ? cause.message : cause)) }
      }, [withSession])
      const loadCatalog = useCallback(async () => {
        try {
          const response = await fetch(withSession('/armorbreak/catalog'), { headers: { accept: 'application/json' }, credentials: 'same-origin' })
          const data = await response.json().catch(() => ({}))
          if (!response.ok) throw new Error(data.error || String(response.status))
          setCatalogItems(Array.isArray(data.items) ? data.items : [])
        } catch (cause) { setResearchError(String(cause && cause.message ? cause.message : cause)) }
      }, [withSession])

      useEffect(() => {
        if (!open) return
        if (tab === 'evaluations') void loadEvaluations()
        else if (tab === 'catalog') void loadCatalog()
        else if (tab === 'installations') void loadInstallations()
        else if (tab === 'reports') void loadReportDashboard()
      }, [open, tab, loadEvaluations, loadCatalog, loadInstallations, loadReportDashboard])
      useEffect(() => {
        if (open) void loadWorkflows()
      }, [open, loadWorkflows])

      useEffect(() => {
        if (open && tab === 'tools') void loadEnvironment()
      }, [open, tab, loadEnvironment])

      const capabilityCount = state && state.registry ? state.registry.capabilities : 0
      const taskCount = state && Array.isArray(state.tasks) ? state.tasks.length : 0
      const isolation = state && state.ui && state.ui.isolation ? state.ui.isolation : null
      const isolationOk = Boolean(state && state.isolation && state.isolation.available)
      const taskRows = state && state.ui && Array.isArray(state.ui.tasks) ? state.ui.tasks : []
      const policy = state && state.ui && state.ui.policy ? state.ui.policy : null
      const queue = state && Array.isArray(state.queue) ? state.queue : []
      const domains = state && state.ui && state.ui.tools && Array.isArray(state.ui.tools.domains) ? state.ui.tools.domains : []
      const connectivity = state && state.connectivity ? state.connectivity : null
      const networkSnapshot = connectivity && connectivity.state ? connectivity.state : null
      const connectors = connectivity && Array.isArray(connectivity.connectors) ? connectivity.connectors : []
      const resources = connectivity && Array.isArray(connectivity.resources) ? connectivity.resources : []

      const rootStyle = {
        border: '1px solid var(--dsw-alias-border-l1)',
        borderRadius: 10,
        background: 'var(--dsw-alias-bg-layer-1)',
        color: 'var(--dsw-alias-label-primary)',
        font: '12.5px/1.5 -apple-system,"Segoe UI",system-ui,"Microsoft YaHei",sans-serif',
        overflow: 'hidden',
      }
      const barStyle = {
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        width: '100%',
        padding: '6px 10px',
        background: 'transparent',
        border: 0,
        color: 'inherit',
        cursor: 'pointer',
        textAlign: 'left',
      }
      const dotStyle = { width: 7, height: 7, borderRadius: '50%', background: error ? 'var(--dsw-alias-state-error-primary)' : state ? 'var(--dsw-alias-state-success-primary)' : 'var(--dsw-alias-state-idle-primary)', flex: '0 0 auto' }
      const muted = { color: 'var(--dsw-alias-label-secondary)' }
      const pill = { border: '1px solid var(--dsw-alias-border-l1)', borderRadius: 999, padding: '0 8px', ...muted }
      const tabStyle = (active) => ({
        font: 'inherit',
        padding: '3px 10px',
        borderRadius: 6,
        border: '1px solid var(--dsw-alias-border-l1)',
        background: active ? 'var(--dsw-alias-bg-layer-2)' : 'transparent',
        color: 'inherit',
        cursor: 'pointer',
      })
      const sectionTitle = { fontWeight: 600, marginTop: 4 }

      function overviewView() {
        return h(
          'div',
          { style: { display: 'grid', gap: 8 } },
          h('div', { style: { display: 'grid', gap: 2 } },
            h('div', { style: muted }, `${t.workspace}: ${shortPath(state.workspace)}`),
            h('div', { style: { ...muted, fontSize: 11.5 } }, `${t.workspaceBinding}: ${state.workspaceBinding || 'MRU'}`),
          ),
          h('div', { style: { display: 'flex', gap: 6, flexWrap: 'wrap' } },
            h('span', { style: { ...pill, color: 'var(--dsw-alias-state-success-primary)' } }, t.l0 + ': ✓'),
            h('span', { style: { ...pill, color: policy && policy.l2.activeAuthorizations > 0 ? 'var(--dsw-alias-state-success-primary)' : 'var(--dsw-alias-label-secondary)' } }, policy ? policy.l2.label : `${t.l2}: ?`),
            h('span', { style: { ...pill, color: isolationOk ? 'var(--dsw-alias-state-success-primary)' : 'var(--dsw-alias-label-secondary)' } }, `${t.l1}: ${isolation ? isolation.label : t.unavailable}`),
            h('span', { style: { ...pill, color: 'var(--dsw-alias-state-error-primary)' } }, t.l3 + ': ✗'),
          ),
          h('div', { style: sectionTitle }, t.queue + `: ${queue.length === 0 ? t.idle : queue.length}`),
          ...queue.slice(0, 4).map((entry) => h('div', { key: entry.taskId, style: { ...muted, fontSize: 11.5 } }, `${entry.taskId} · ${entry.state}${entry.queued ? ' (waiting)' : ''}`)),
          h('div', { style: sectionTitle }, t.recentTasks),
          taskRows.length === 0 ? h('div', { style: muted }, t.noTasks) : null,
          ...taskRows.slice(0, 6).map((task) => h(
            'div',
            { key: task.id, style: { display: 'grid', gap: 1, borderLeft: `2px solid ${stateColor(task.state)}`, paddingLeft: 8 } },
            h('div', { style: { display: 'flex', gap: 6, alignItems: 'baseline' } },
              h('span', { style: { fontWeight: 600 } }, task.title),
              h('span', { style: { ...muted, fontSize: 11.5 } }, `${task.workflow || 'adhoc'} · ${task.state}`),
            ),
            h('div', { style: { ...muted, fontSize: 11.5 } }, `${t.evidence} ${task.evidence} · ${t.findings} ${task.findings}${task.report ? ` · ${task.report.format}` : ''}`),
          )),
        )
      }

      function evaluationsView() {
        return h(
          'div',
          { style: { display: 'grid', gap: 6 } },
          h('div', { style: sectionTitle }, t.runEvaluation),
          h('select', { value: evaluationForm.category, onChange: (event) => setEvaluationForm({ ...evaluationForm, category: event.target.value }), style: { font: 'inherit', padding: '2px 4px' } },
            ...['prompt-injection', 'tool-abuse', 'data-exfiltration', 'memory-poisoning', 'multimodal', 'jailbreak-research'].map((value) => h('option', { key: value, value }, value))),
          h('input', { value: evaluationForm.prompt, placeholder: t.evaluationPrompt, onChange: (event) => setEvaluationForm({ ...evaluationForm, prompt: event.target.value }), style: { font: 'inherit', padding: '2px 4px' } }),
          h('button', { type: 'button', style: tabStyle(false), disabled: evaluationBusy, onClick: async () => {
            setEvaluationBusy(true)
            setResearchError(null)
            const data = await postAction({ action: 'evaluate', prompt: evaluationForm.prompt, category: evaluationForm.category })
            setEvaluationBusy(false)
            if (data && data.evaluation) { setEvaluationForm({ ...evaluationForm, prompt: '' }); await loadEvaluations() }
          } }, evaluationBusy ? t.probing : t.runEvaluation),
          researchError ? h('div', { style: { color: 'var(--dsw-alias-state-error-primary)' } }, researchError) : null,
          h('div', { style: sectionTitle }, t.evaluations),
          evaluationItems.length === 0 ? h('div', { style: muted }, t.noEvaluations) : null,
          ...evaluationItems.slice(0, 20).map((item) => h('div', { key: item.traceId, style: { ...muted, fontSize: 11.5 } }, item.traceId + ' · ' + item.verdict + ' · ' + item.scenarioId)),
        )
      }
      function knowledgeView() {
        return h(
          'div',
          { style: { display: 'grid', gap: 6 } },
          h('div', { style: sectionTitle }, t.searchKnowledge),
          h('input', { value: knowledgeQuery, placeholder: t.searchKnowledge, onChange: (event) => setKnowledgeQuery(event.target.value), style: { font: 'inherit', padding: '2px 4px' } }),
          h('button', { type: 'button', style: tabStyle(false), onClick: () => void loadKnowledge() }, t.search),
          knowledgeResults ? h('div', { style: { ...muted, fontSize: 11.5 } }, (knowledgeResults.backend || '') + ' · ' + String(knowledgeResults.count ?? 0)) : null,
          knowledgeResults && Array.isArray(knowledgeResults.results) && knowledgeResults.results.length === 0 ? h('div', { style: muted }, t.noKnowledge) : null,
          ...((knowledgeResults && knowledgeResults.results) || []).slice(0, 20).map((item) => h('div', { key: item.id, style: { ...muted, fontSize: 11.5 } }, item.title + ' · ' + item.uri + ' · v' + item.version)),
        )
      }
      function catalogView() {
        return h(
          'div',
          { style: { display: 'grid', gap: 6 } },
          h('div', { style: sectionTitle }, t.catalog),
          h('div', { style: { ...muted, fontSize: 11.5 } }, t.catalogHint),
          catalogItems && catalogItems.length === 0 ? h('div', { style: muted }, t.unavailable) : null,
          ...(catalogItems || []).map((item) => h('div', { key: item.id, style: { ...muted, fontSize: 11.5 } }, item.id + ' · ' + item.title + ' · ' + (item.license || 'license?'))),
        )
      }

      function reportsView() {
        return h(
          'div',
          { style: { display: 'grid', gap: 6 } },
          h('div', { style: sectionTitle }, t.reports),
          h('div', { style: { ...muted, fontSize: 11.5 } }, t.reportHint),
          reportDashboard ? h('div', { style: { ...muted, fontSize: 11.5 } }, 'samples=' + String(reportDashboard.sampleCount) + ' · PASS=' + String(reportDashboard.byVerdict?.PASS ?? 0) + ' · FAIL=' + String(reportDashboard.byVerdict?.FAIL ?? 0) + ' · model=' + String(reportDashboard.model?.name) + '/' + String(reportDashboard.model?.version)) : null,
          reportDashboard ? h('div', { style: { ...muted, fontSize: 11.5 } }, 'dataset=' + String(reportDashboard.datasetFingerprint ?? '').slice(0, 24) + ' · mock=' + String(reportDashboard.mockModel)) : null,
          ...((reportDashboard && reportDashboard.failed) || []).slice(0, 20).map((item) => h('div', { key: item.traceId, style: { ...muted, fontSize: 11.5 } }, item.traceId + ' · ' + item.verdict + ' · ' + item.scenarioId)),
        )
      }

      function installationsView() {
        return h(
          'div',
          { style: { display: 'grid', gap: 6 } },
          h('div', { style: sectionTitle }, t.planInstall),
          h('div', { style: { ...muted, fontSize: 11.5 } }, t.installHint),
          h('input', { value: installForm.artifactPath, placeholder: t.artifactPath, onChange: (event) => setInstallForm({ ...installForm, artifactPath: event.target.value }), style: { font: 'inherit', padding: '2px 4px' } }),
          h('input', { value: installForm.license, placeholder: 'license', onChange: (event) => setInstallForm({ ...installForm, license: event.target.value }), style: { font: 'inherit', padding: '2px 4px' } }),
          h('input', { value: installForm.commit, placeholder: 'commit', onChange: (event) => setInstallForm({ ...installForm, commit: event.target.value }), style: { font: 'inherit', padding: '2px 4px' } }),
          h('button', { type: 'button', style: tabStyle(false), disabled: installBusy, onClick: async () => {
            setInstallBusy(true); setResearchError(null)
            const components = installForm.components ? [{ name: 'bundle', version: 'local', license: installForm.license, commit: installForm.commit, digest: installForm.digest, scripts: {} }] : [{ name: 'bundle', version: 'local', license: installForm.license, commit: installForm.commit, digest: installForm.digest, scripts: {} }]
            const data = await postAction({ action: 'install.plan', artifactPath: installForm.artifactPath, license: installForm.license, commit: installForm.commit, components })
            setInstallBusy(false); if (data) await loadInstallations()
          } }, installBusy ? t.probing : t.planInstall),
          researchError ? h('div', { style: { color: 'var(--dsw-alias-state-error-primary)' } }, researchError) : null,
          h('div', { style: sectionTitle }, t.installations),
          installItems.length === 0 ? h('div', { style: muted }, t.noInstallations) : null,
          ...installItems.slice(0, 20).map((item) => h('div', { key: item.planId, style: { display: 'grid', gap: 2, borderLeft: '2px solid var(--dsw-alias-border-l1)', paddingLeft: 8, marginBottom: 4 } },
            h('div', { style: { fontSize: 11.5 } }, item.planId + ' · ' + item.status + ' · ' + String(item.artifact?.sha256 ?? '').slice(0, 12)),
            h('div', { style: { display: 'flex', gap: 4, flexWrap: 'wrap' } },
              item.status === 'PLANNED' ? h('button', { type: 'button', style: tabStyle(false), onClick: async () => { await postAction({ action: 'install.stage', planId: item.planId }); await loadInstallations() } }, 'stage') : null,
              item.status === 'STAGED' ? h('button', { type: 'button', style: tabStyle(false), onClick: async () => { await postAction({ action: 'install.verify', planId: item.planId }); await loadInstallations() } }, 'verify') : null,
              item.status === 'VERIFIED' ? h('div', { style: { ...muted, fontSize: 11.5 } }, 'Approval requires the interactive host CLI.') : null,
              item.status === 'APPROVED' ? h('button', { type: 'button', style: tabStyle(false), onClick: async () => { await postAction({ action: 'install.activate', planId: item.planId }); await loadInstallations() } }, 'activate') : null,
              item.status === 'ACTIVE' ? h('button', { type: 'button', style: tabStyle(false), onClick: async () => { await postAction({ action: 'install.rollback', planId: item.planId }); await loadInstallations() } }, 'rollback') : null,
            ),
          )),
        )
      }

      function networkView() {
        return h(
          'div',
          { style: { display: 'grid', gap: 8 } },
          h('div', { style: sectionTitle }, t.networkState),
          h('div', { style: muted }, String(networkSnapshot ? networkSnapshot.state : t.unavailable) + ' · ' + t.failures + ' ' + String(networkSnapshot?.failures ?? '-') + ' · ' + t.successes + ' ' + String(networkSnapshot?.successes ?? '-')),
          ...(networkSnapshot?.history ?? []).slice(-5).map((entry, index) => h('div', { key: String(entry.at) + '-' + index, style: { ...muted, fontSize: 11.5 } }, String(entry.at ?? '') + ' ' + String(entry.from ?? '-') + ' → ' + String(entry.to) + (entry.reason ? ' · ' + entry.reason : ''))),
          h('div', { style: sectionTitle }, t.connectors),
          connectors.length === 0 ? h('div', { style: muted }, t.unavailable) : null,
          ...connectors.map((connector) => h('div', { key: connector.id, style: { ...muted, fontSize: 11.5 } }, connector.id + ' · ' + t.breaker + ' ' + connector.breaker + ' · ' + t.failures + ' ' + connector.failures)),
          h('div', { style: sectionTitle }, t.resources),
          resources.length === 0 ? h('div', { style: muted }, t.unavailable) : null,
          ...resources.slice(0, 8).map((resource) => h('div', { key: resource.id, style: { ...muted, fontSize: 11.5 } }, resource.id + ' · ' + resource.title + ' · ' + (resource.license || 'license?') + ' · ' + (resource.lastSyncedAt || 'never'))),
          h('div', { style: sectionTitle }, t.missingTools),
          ...domains.flatMap((domain) => (domain.externalTools ?? [])).filter((tool) => tool.availability !== 'available').slice(0, 12).map((tool) => h('div', { key: tool.name, style: { ...muted, fontSize: 11.5 } }, tool.name + ' · ' + tool.availability)),
          h('div', { style: { ...muted, fontSize: 11.5 } }, t.recoveryPath),
          h('div', { style: { ...muted, fontSize: 11.5 } }, t.offlineHint),
        )
      }

      function tasksView() {
        if (detail && detail.loading) return h('div', { style: muted }, t.loadingDetail)
        if (detailError) return h('div', { style: { color: 'var(--dsw-alias-state-error-primary)' } }, `${t.error}: ${detailError}`)
        if (detail && detail.task) {
          const task = detail.task
          return h(
            'div',
            { style: { display: 'grid', gap: 6 } },
            h('button', { type: 'button', style: tabStyle(false), onClick: () => { setDetail(null); setDetailError(null) } }, `← ${t.back}`),
            h('div', { style: { fontWeight: 600 } }, `${task.title} · ${task.state}`),
            h('div', { style: muted }, `${t.evidence} ${task.stats?.evidence ?? 0} · ${t.findings} ${task.stats?.findings ?? 0} · ${t.risk} ${task.riskMax ?? '-'}`),
            h('div', { style: muted }, `${t.report}: ${task.report ? shortPath(task.report.path) : t.noReport}`),
            h('div', { style: { display: 'flex', gap: 6, flexWrap: 'wrap' } },
              h('button', { type: 'button', style: tabStyle(false), onClick: () => void postAction({ action: 'cancel', taskId: task.id }) }, t.cancel),
              h('button', { type: 'button', style: tabStyle(false), onClick: () => void postAction({ action: 'retry', taskId: task.id }) }, t.retry),
              ['RECOVERABLE', 'INTERRUPTED', 'PAUSED'].includes(task.state)
                ? h('button', { type: 'button', style: tabStyle(false), onClick: () => void postAction({ action: 'resume', taskId: task.id }) }, t.resume)
                : null,
              task.stats?.evidence > 0 ? h('button', { type: 'button', style: tabStyle(false), onClick: () => void loadEvidence(task.id) }, t.loadEvidence) : null,
              task.report ? h('button', { type: 'button', style: tabStyle(false), onClick: () => void loadReport(task.id) }, t.loadReport) : null,
            ),
            h('div', { style: { display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' } },
              h('span', { style: muted }, `${t.severity}:`),
              ...['', 'critical', 'high', 'medium', 'low'].map((value) => h('button', {
                key: value || 'all',
                type: 'button',
                style: tabStyle(evidenceSeverity === value),
                onClick: () => applyEvidenceFilters(task.id, value, evidenceVerification),
              }, value || t.all)),
            ),
            h('div', { style: { display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' } },
              h('span', { style: muted }, `${t.verification}:`),
              ...['', 'observed', 'hypothesis'].map((value) => h('button', {
                key: value || 'all',
                type: 'button',
                style: tabStyle(evidenceVerification === value),
                onClick: () => applyEvidenceFilters(task.id, evidenceSeverity, value),
              }, value || t.all)),
            ),
            task.report ? h('div', { style: { display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' } },
              h('span', { style: muted }, `${t.reportFormat}:`),
              ...['markdown', 'html'].map((format) => h('button', {
                key: format,
                type: 'button',
                style: tabStyle(reportFormat === format),
                onClick: () => { setReportFormat(format); void loadReport(task.id, format) },
              }, format)),
            ) : null,
            actionError ? h('div', { style: { color: 'var(--dsw-alias-state-error-primary)' } }, `${t.actionFailed}: ${actionError}`) : null,
            evidence
              ? h('div', { style: { display: 'grid', gap: 2 } },
                  h('div', { style: sectionTitle }, `${t.evidenceExplorer} · ${evidence.counts?.evidence ?? 0}`),
                  h('div', { style: muted }, `chain: ${evidence.chain?.valid ? 'verified' : 'BROKEN'} · findings ${evidence.counts?.findings ?? 0}`),
                  ...(evidence.findings ?? []).slice(0, 15).map((finding) => h('div', { key: finding.id, style: { borderLeft: `2px solid ${severityColor(finding.severity)}`, paddingLeft: 8, ...muted, fontSize: 11.5 } }, `[${finding.severity}/${finding.verification}] ${finding.title}`)),
                )
              : null,
            report
              ? h('div', { style: { display: 'grid', gap: 2 } },
                  h('div', { style: sectionTitle }, t.reportPreview),
                  report.error
                    ? h('div', { style: { color: 'var(--dsw-alias-state-error-primary)' } }, report.error)
                    : h('pre', { style: { whiteSpace: 'pre-wrap', maxHeight: 180, overflow: 'auto', margin: 0, font: '11px/1.4 ui-monospace,Consolas,monospace', ...muted } }, String(report.text ?? '').slice(0, 4000)),
                )
              : null,
            h('div', { style: sectionTitle }, t.steps),
            ...(Array.isArray(task.steps) ? task.steps : []).map((step) => h('div', { key: step.id, style: { ...muted, fontSize: 11.5 } }, `${step.status.padEnd(8)} ${step.capability} · ${step.durationMs ?? '-'} ms${step.error ? ` · ${step.error}` : ''}`)),
            h('div', { style: sectionTitle }, t.findingsTitle),
            (detail.findings ?? []).length === 0 ? h('div', { style: muted }, t.noFindings) : null,
            ...(detail.findings ?? []).slice(0, 20).map((finding) => h('div', { key: finding.id, style: { borderLeft: `2px solid ${severityColor(finding.severity)}`, paddingLeft: 8, ...muted, fontSize: 11.5 } }, `[${finding.severity}/${finding.verification}] ${finding.title}`)),
          )
        }
        return h(
          'div',
          { style: { display: 'grid', gap: 6 } },
          h(
            'div',
            { style: { display: 'grid', gap: 4, borderTop: '1px solid var(--dsw-alias-border-l1)', paddingTop: 6 } },
            h('div', { style: { fontWeight: 600 } }, t.createTask),
            h('select', {
              value: form.workflow,
              onChange: (event) => setForm({ ...form, workflow: event.target.value }),
              style: { font: 'inherit', padding: '2px 4px' },
            }, h('option', { value: '' }, '—'), ...workflows.map((workflow) => h('option', { key: workflow.id, value: workflow.id }, `${workflow.id} (${workflow.steps} steps)`))),
            h('input', { value: form.target, placeholder: t.targetPath, onChange: (event) => setForm({ ...form, target: event.target.value }), style: { font: 'inherit', padding: '2px 4px' } }),
            h('input', { value: form.title, placeholder: t.taskTitle, onChange: (event) => setForm({ ...form, title: event.target.value }), style: { font: 'inherit', padding: '2px 4px' } }),
            h('button', {
              type: 'button',
              style: tabStyle(false),
              onClick: async () => {
                const result = await postAction({ action: 'create', workflow: form.workflow, target: form.target || null, title: form.title || undefined })
                if (result && result.task) void loadDetail(result.task.id)
              },
            }, t.submit),
            actionError ? h('div', { style: { color: 'var(--dsw-alias-state-error-primary)' } }, `${t.actionFailed}: ${actionError}`) : null,
          ),
          taskRows.length === 0 ? h('div', { style: muted }, t.noTasks) : null,
          ...taskRows.slice(0, 20).map((task) => h(
            'button',
            {
              key: task.id,
              type: 'button',
              onClick: () => void loadDetail(task.id),
              style: { textAlign: 'left', font: 'inherit', background: 'transparent', border: 0, borderLeft: `2px solid ${stateColor(task.state)}`, padding: '2px 0 2px 8px', color: 'inherit', cursor: 'pointer' },
            },
            h('div', { style: { fontWeight: 600 } }, `${task.title} · ${task.state}`),
            h('div', { style: { ...muted, fontSize: 11.5 } }, `${task.workflow || 'adhoc'} · ${t.evidence} ${task.evidence} · ${t.findings} ${task.findings}`),
          )),
        )
      }

      function toolsView() {
        return h(
          'div',
          { style: { display: 'grid', gap: 6 } },
          h('div', { style: muted }, `${t.isolation}: ${isolation ? isolation.label : t.unavailable}`),
          isolation && isolation.state ? h('div', { style: muted }, `${t.status}: ${isolation.state}${isolation.selfTested ? '' : ` · ${t.notProbed}`}`) : null,
          h('div', { style: { display: 'grid', gap: 2, borderTop: '1px solid var(--dsw-alias-border-l1)', paddingTop: 6 } },
            h('div', { style: { display: 'flex', gap: 6, alignItems: 'center' } },
              h('div', { style: sectionTitle }, t.environment),
              h('button', { type: 'button', style: tabStyle(false), disabled: environmentLoading, onClick: () => void loadEnvironment() }, environmentLoading ? t.loadingEnvironment : t.refreshEnvironment),
            ),
            environment
              ? h('div', { style: { display: 'grid', gap: 2 } },
                  ...(environment.providers ?? []).map((provider) => h('div', { key: provider.id, style: { ...muted, fontSize: 11.5 } }, `${provider.title}: ${provider.state}${provider.version ? ` · ${provider.version}` : ''} — ${provider.reason}`)),
                  h('div', { style: { ...muted, fontSize: 11.5 } }, `L1: ${environment.l1?.available ? '可用（已自检）' : `未就绪（${environment.l1?.state ?? 'unavailable'}）`} — ${environment.l1?.reason ?? ''}`),
                  environment.wsl2Note ? h('div', { style: { ...muted, fontSize: 11 } }, environment.wsl2Note) : null,
                )
              : h('div', { style: muted }, t.environmentHint),
          ),
          h('div', { style: { display: 'flex', gap: 6 } },
            h('button', {
              type: 'button',
              style: tabStyle(false),
              disabled: probing,
              onClick: async () => {
                setProbing(true)
                try {
                  const response = await fetch(withSession('/armorbreak/tools?probe=1'), { headers: { accept: 'application/json' }, credentials: 'same-origin' })
                  if (response.ok) setToolProbe(await response.json())
                } catch {
                  /* keep previous probe result */
                } finally {
                  setProbing(false)
                }
              },
            }, probing ? t.probing : t.probe),
          ),
          toolProbe && Array.isArray(toolProbe.externalTools)
            ? h('div', { style: { display: 'grid', gap: 2 } },
                h('div', { style: sectionTitle }, t.toolsProbed),
                ...toolProbe.externalTools.map((tool) => h('div', { key: tool.name, style: { ...muted, fontSize: 11.5 } }, `${tool.found ? '✅' : '—'} ${tool.name}${tool.version ? ` · ${tool.version}` : ''}${tool.path ? ` · ${shortPath(tool.path)}` : ''}`)),
              )
            : null,
          ...domains.map((domain) => h(
            'div',
            { key: domain.domain, style: { borderTop: '1px solid var(--dsw-alias-border-l1)', paddingTop: 4 } },
            h('div', { style: { fontWeight: 600 } }, `${domain.domain} · ${domain.capabilityCount}`),
            domain.externalTools && domain.externalTools.length > 0
              ? h('div', { style: { ...muted, fontSize: 11.5 } }, `${t.externalTools}: ${domain.externalTools.map((tool) => `${tool.name} (${t.notProbed})`).join(', ')}`)
              : null,
          )),
        )
      }

      return h(
        'div',
        { style: rootStyle, 'data-armorbreak': 'status-card', 'data-session': sessionId || '' },
        h(
          'button',
          { type: 'button', style: barStyle, 'aria-expanded': open, title: open ? t.close : t.open, onClick: () => setOpen((value) => !value) },
          h('span', { style: dotStyle, 'aria-hidden': true }),
          h('span', { style: { fontWeight: 600 } }, t.title),
          h('span', { style: muted }, t.subtitle),
          h('span', { style: { marginLeft: 'auto', display: 'flex', gap: 6, ...muted } },
            h('span', { style: pill }, `${capabilityCount} ${t.capabilities}`),
            h('span', { style: pill }, `${taskCount} ${t.tasks}`),
            h('span', { style: { ...pill, color: isolationOk ? 'var(--dsw-alias-state-success-primary)' : 'var(--dsw-alias-label-secondary)' } }, `${t.isolation}: ${isolation ? isolation.state : t.unavailable}`),
          ),
        ),
        open
          ? h(
              'div',
              { style: { padding: '0 10px 10px', display: 'grid', gap: 8 } },
              h('div', { style: { display: 'flex', gap: 6 } },
                h('button', { type: 'button', style: tabStyle(tab === 'overview'), onClick: () => { setTab('overview'); setDetail(null) } }, t.overview),
                h('button', { type: 'button', style: tabStyle(tab === 'tasks'), onClick: () => { setTab('tasks'); setDetail(null) } }, t.taskCenter),
                h('button', { type: 'button', style: tabStyle(tab === 'tools'), onClick: () => { setTab('tools'); setDetail(null) } }, t.toolCenter),
                h('button', { type: 'button', style: tabStyle(tab === 'network'), onClick: () => { setTab('network'); setDetail(null) } }, t.network),
                h('button', { type: 'button', style: tabStyle(tab === 'evaluations'), onClick: () => { setTab('evaluations'); setDetail(null) } }, t.evaluations),
                h('button', { type: 'button', style: tabStyle(tab === 'knowledge'), onClick: () => { setTab('knowledge'); setDetail(null) } }, t.knowledge),
                h('button', { type: 'button', style: tabStyle(tab === 'catalog'), onClick: () => { setTab('catalog'); setDetail(null) } }, t.catalog),
                h('button', { type: 'button', style: tabStyle(tab === 'installations'), onClick: () => { setTab('installations'); setDetail(null) } }, t.installations),
                h('button', { type: 'button', style: tabStyle(tab === 'reports'), onClick: () => { setTab('reports'); setDetail(null) } }, t.reports),
              ),
              error ? h('div', { style: { color: 'var(--dsw-alias-state-error-primary)' } }, `${t.error}: ${error}`) : null,
              !state && !error ? h('div', { style: muted }, t.loading) : null,
              state ? (tab === 'overview' ? overviewView() : tab === 'tasks' ? tasksView() : tab === 'network' ? networkView() : tab === 'evaluations' ? evaluationsView() : tab === 'knowledge' ? knowledgeView() : tab === 'catalog' ? catalogView() : tab === 'installations' ? installationsView() : tab === 'reports' ? reportsView() : toolsView()) : null,
              h('div', { style: { display: 'flex', justifyContent: 'flex-end' } },
                h('button', {
                  type: 'button',
                  onClick: () => void load(),
                  disabled: busy,
                  style: { font: 'inherit', padding: '2px 10px', borderRadius: 6, border: '1px solid var(--dsw-alias-border-l1)', background: 'var(--dsw-alias-bg-layer-2)', color: 'inherit', cursor: busy ? 'default' : 'pointer' },
                }, busy ? '…' : t.refresh),
              ),
            )
          : null,
      )
    }

    function ArmorBreakSlot(props) {
      return h(StatusCard, props)
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('conversation.composer.dock', () =>
          ctx.slots.register(
            { name: 'conversation.composer.dock', id: 'armorbreak-status', order: 30, label: '破甲模式' },
            (props) => h(ArmorBreakSlot, { ...props, __ctx: ctx }),
          ),
        )
      },
    }
  },
})
