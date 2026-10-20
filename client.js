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

      const load = useCallback(async () => {
        setBusy(true)
        try {
          const response = await fetch('/armorbreak/state', { headers: { accept: 'application/json' }, credentials: 'same-origin' })
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
        try {
          const response = await fetch(`/armorbreak/tasks?id=${encodeURIComponent(taskId)}`, { headers: { accept: 'application/json' }, credentials: 'same-origin' })
          if (!response.ok) throw new Error(`HTTP ${response.status}`)
          setDetail(await response.json())
        } catch (cause) {
          setDetail(null)
          setDetailError(String(cause && cause.message ? cause.message : cause))
        }
      }, [])

      const capabilityCount = state && state.registry ? state.registry.capabilities : 0
      const taskCount = state && Array.isArray(state.tasks) ? state.tasks.length : 0
      const isolation = state && state.ui && state.ui.isolation ? state.ui.isolation : null
      const isolationOk = Boolean(state && state.isolation && state.isolation.available)
      const taskRows = state && state.ui && Array.isArray(state.ui.tasks) ? state.ui.tasks : []
      const policy = state && state.ui && state.ui.policy ? state.ui.policy : null
      const queue = state && Array.isArray(state.queue) ? state.queue : []
      const domains = state && state.ui && state.ui.tools && Array.isArray(state.ui.tools.domains) ? state.ui.tools.domains : []

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
              ),
              error ? h('div', { style: { color: 'var(--dsw-alias-state-error-primary)' } }, `${t.error}: ${error}`) : null,
              !state && !error ? h('div', { style: muted }, t.loading) : null,
              state ? (tab === 'overview' ? overviewView() : tab === 'tasks' ? tasksView() : toolsView()) : null,
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
