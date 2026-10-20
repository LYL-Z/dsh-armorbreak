/**
 * ArmorBreak browser half: an ambient composer-dock card that shows the live
 * mode status (capabilities, isolation, policy, recent tasks) read from the
 * Host route `/armorbreak/state`. Read-only; it never starts analysis from the
 * browser and never renders evidence excerpts or credentials.
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
        policies: 'policy',
        recentTasks: 'Recent tasks',
        noTasks: 'No tasks yet. Start one from the ArmorBreak mode chat.',
        open: 'Show ArmorBreak status',
        close: 'Hide ArmorBreak status',
        workspace: 'last used workspace',
        risk: 'risk',
        evidence: 'evidence',
        findings: 'findings',
        l0: 'L0 offline',
        l1: 'L1 dynamic',
        l2: 'L2 active',
        l3: 'L3 denied',
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
        policies: '策略',
        recentTasks: '最近任务',
        noTasks: '还没有任务。在破甲模式对话中创建分析任务。',
        open: '展开破甲模式状态',
        close: '收起破甲模式状态',
        workspace: '最近使用的工作区',
        risk: '风险',
        evidence: '证据',
        findings: '发现',
        l0: 'L0 离线',
        l1: 'L1 动态',
        l2: 'L2 主动',
        l3: 'L3 拒绝',
      },
    }

    /** @param {string} state */
    function stateColor(state) {
      if (state === 'COMPLETED') return 'var(--dsw-alias-state-success-primary)'
      if (state === 'PARTIAL_SUCCESS') return 'var(--dsw-alias-state-warn-primary)'
      if (state === 'FAILED' || state === 'REJECTED' || state === 'TIMED_OUT' || state === 'CANCELLED') return 'var(--dsw-alias-state-error-primary)'
      return 'var(--dsw-alias-brand-primary)'
    }

    function StatusCard(props) {
      const { sessionId } = props
      const [t, setT] = useState(DICT.zh)
      const [open, setOpen] = useState(false)
      const [state, setState] = useState(null)
      const [error, setError] = useState(null)
      const [busy, setBusy] = useState(false)

      const load = useCallback(async () => {
        setBusy(true)
        try {
          const response = await fetch('/armorbreak/state', { headers: { accept: 'application/json' }, credentials: 'same-origin' })
          if (!response.ok) throw new Error(`HTTP ${response.status}`)
          const next = await response.json()
          setState(next)
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
          // Locale is optional: the card falls back to Chinese when the service is absent.
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

      const capabilityCount = state && state.registry ? state.registry.capabilities : 0
      const taskCount = state && Array.isArray(state.tasks) ? state.tasks.length : 0
      const isolationOk = Boolean(state && state.isolation && state.isolation.available)
      const taskList = state && Array.isArray(state.tasks) ? state.tasks.slice(0, 6) : []

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

      return h(
        'div',
        { style: rootStyle, 'data-armorbreak': 'status-card', 'data-session': sessionId || '' },
        h(
          'button',
          {
            type: 'button',
            style: barStyle,
            'aria-expanded': open,
            title: open ? t.close : t.open,
            onClick: () => setOpen((value) => !value),
          },
          h('span', { style: dotStyle, 'aria-hidden': true }),
          h('span', { style: { fontWeight: 600 } }, t.title),
          h('span', { style: muted }, t.subtitle),
          h('span', { style: { marginLeft: 'auto', display: 'flex', gap: 6, ...muted } },
            h('span', { style: pill }, `${capabilityCount} ${t.capabilities}`),
            h('span', { style: pill }, `${taskCount} ${t.tasks}`),
            h('span', { style: { ...pill, color: isolationOk ? 'var(--dsw-alias-state-success-primary)' : 'var(--dsw-alias-label-secondary)' } }, `${t.isolation}: ${isolationOk && state && state.isolation ? (state.isolation.provider || '✓') : t.unavailable}`),
          ),
        ),
        open
          ? h(
              'div',
              { style: { padding: '0 10px 10px', display: 'grid', gap: 8 } },
              error ? h('div', { style: { color: 'var(--dsw-alias-state-error-primary)' } }, `${t.error}: ${error}`) : null,
              !state && !error ? h('div', { style: muted }, t.loading) : null,
              state
                ? h(
                    'div',
                    { style: { display: 'grid', gap: 6 } },
                    h('div', { style: muted }, `${t.workspace}: ${state.workspace}`),
                    h('div', { style: { display: 'flex', gap: 6, flexWrap: 'wrap' } },
                      h('span', { style: pill }, t.l0 + ': ✓'),
                      h('span', { style: pill }, t.l2 + ': ' + (state.policy && state.policy.authorizations ? state.policy.authorizations.filter((item) => item.active).length : 0)),
                      h('span', { style: pill }, t.l1 + ': ' + (isolationOk ? '✓' : '✗')),
                      h('span', { style: { ...pill, color: 'var(--dsw-alias-state-error-primary)' } }, t.l3 + ': ✗'),
                    ),
                    h('div', { style: { fontWeight: 600, marginTop: 2 } }, t.recentTasks),
                    taskList.length === 0 ? h('div', { style: muted }, t.noTasks) : null,
                    ...taskList.map((task) =>
                      h(
                        'div',
                        { key: task.id, style: { display: 'grid', gap: 1, borderLeft: `2px solid ${stateColor(task.state)}`, paddingLeft: 8 } },
                        h('div', { style: { display: 'flex', gap: 6, alignItems: 'baseline' } },
                          h('span', { style: { fontWeight: 600 } }, task.title),
                          h('span', { style: { ...muted, fontSize: 11.5 } }, `${task.workflow || 'adhoc'} · ${task.state}`),
                        ),
                        h('div', { style: { ...muted, fontSize: 11.5 } }, `${t.evidence} ${task.stats ? task.stats.evidence : 0} · ${t.findings} ${task.stats ? task.stats.findings : 0}${task.report ? ` · ${task.report.format}` : ''}`),
                      ),
                    ),
                  )
                : null,
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
