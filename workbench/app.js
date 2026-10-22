const $ = (id) => document.getElementById(id)
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]))
const badge = (value, tone = '') => `<span class="badge ${tone}">${esc(value)}</span>`

let state = null

async function load() {
  const response = await fetch('/api/state')
  if (!response.ok) throw new Error(`state HTTP ${response.status}`)
  state = await response.json()
  render()
}

function toneFor(value) {
  const text = String(value)
  if (/PASS|L0_COMPLETED|HOST_VERIFIED|TESTED|REAL_VERIFIED/i.test(text)) return 'pass'
  if (/BLOCKED|NOT_RUN|NOT_STARTED|CONFIG/i.test(text)) return 'warn'
  if (/FAIL|UNSIGNED|MISSING/i.test(text)) return 'bad'
  return ''
}

function render() {
  $('status-dot').className = 'dot ok'
  $('status-label').textContent = 'connected'
  $('m-ready').textContent = state.readiness.ready ? 'READY' : 'BLOCKED'
  $('m-ready').className = state.readiness.ready ? 'pass-text' : ''
  $('m-ready-note').textContent = state.readiness.waived?.length ? `${state.readiness.waived.length} owner waivers` : 'no waivers'
  const l0 = state.hosts.filter((host) => host.taskRunState === 'L0_COMPLETED').length
  $('m-hosts').textContent = `${l0}/${state.hosts.length}`
  $('m-providers').textContent = String(state.providers.length)
  $('m-artifact').textContent = state.artifact?.signed ? 'SIGNED' : 'UNSIGNED'
  $('m-artifact-note').textContent = state.artifact?.sha256 ? state.artifact.sha256.slice(0, 12) : 'no artifact'
  $('generated').textContent = `generated ${state.generatedAt}`
  renderHosts()
  renderProviders()
  renderSkills()
  renderTasks()
  renderEvidence()
  const select = $('diag-provider')
  select.innerHTML = state.providers.map((provider) => `<option value="${esc(provider.id)}">${esc(provider.id)} · ${esc(provider.kind)}</option>`).join('')
}

function renderHosts() {
  $('hosts-body').innerHTML = state.hosts.map((host, index) => `
    <tr class="clickable" data-host="${index}">
      <td><strong>${esc(host.host)}</strong></td>
      <td>${esc(host.hostVersion ?? '—')}</td>
      <td>${badge(host.installState, toneFor(host.installState))}</td>
      <td>${badge(host.toolHandshake, toneFor(host.toolHandshake))}</td>
      <td>${badge(host.taskRunState, toneFor(host.taskRunState))}</td>
      <td>${badge(host.evidenceLevel, toneFor(host.evidenceLevel))}</td>
    </tr>`).join('')
  for (const row of document.querySelectorAll('[data-host]')) {
    row.addEventListener('click', () => {
      const host = state.hosts[Number(row.dataset.host)]
      $('host-detail').textContent = `${host.host} · ${host.integrationMethod}\nEvidence: ${host.evidenceId ?? '—'}\nLimitation: ${host.limitation ?? '—'}`
    })
  }
}

function renderProviders() {
  $('providers-body').innerHTML = state.providers.map((provider, index) => `
    <tr class="clickable" data-provider="${index}">
      <td><strong>${esc(provider.id)}</strong></td>
      <td>${esc(provider.kind)}</td>
      <td>${esc(provider.models.join(', '))}</td>
      <td>${provider.supportsTools ? badge('yes', 'pass') : badge('no', 'warn')}</td>
      <td>${provider.credentialEnv ? badge(provider.credentialPresent ? 'present' : 'missing', provider.credentialPresent ? 'pass' : 'bad') : badge('none')}</td>
      <td><button type="button" data-diagnose="${esc(provider.id)}">Diagnose</button></td>
    </tr>`).join('')
  for (const row of document.querySelectorAll('[data-provider]')) {
    row.addEventListener('click', (event) => {
      if (event.target.closest('button')) return
      const provider = state.providers[Number(row.dataset.provider)]
      $('provider-detail').textContent = `${provider.id} · ${provider.kind}\nBase URL: ${provider.baseUrl}\nCredential env: ${provider.credentialEnv ?? 'none'}\nVerification: ${provider.verification}`
    })
  }
  for (const button of document.querySelectorAll('[data-diagnose]')) {
    button.addEventListener('click', () => diagnose(button.dataset.diagnose))
  }
}

function renderSkills() {
  $('skills-list').innerHTML = state.skills.map((skill) => `<article class="card"><h3>${esc(skill.name)}</h3><p>${esc(skill.description)}</p></article>`).join('')
}

function renderTasks() {
  $('tasks-body').innerHTML = state.tasks.map((task) => `
    <tr><td><strong>${esc(task.id)}</strong></td><td>${badge(task.status, toneFor(task.status))}</td><td>${esc(task.acceptanceResult ?? '—')}</td><td>${badge(task.realEndpoint ?? 'not-required', toneFor(task.realEndpoint ?? 'not-required'))}</td></tr>`).join('')
}

function renderEvidence() {
  $('evidence-list').innerHTML = state.evidence.map((item) => `<article class="card"><h3>${esc(item.title)}</h3><p>${esc(item.detail)}</p></article>`).join('')
}

async function diagnose(providerId) {
  const response = await fetch('/api/diagnose', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ providerId }) })
  const result = await response.json()
  $('diag-output').textContent = JSON.stringify(result, null, 2)
}

$('refresh').addEventListener('click', () => load().catch((error) => { $('status-label').textContent = 'error'; $('status-dot').className = 'dot'; $('diag-output').textContent = String(error) }))
$('diag-run').addEventListener('click', () => diagnose($('diag-provider').value))
for (const tab of document.querySelectorAll('.tab')) {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((item) => item.classList.toggle('active', item === tab))
    document.querySelectorAll('.panel').forEach((panel) => panel.classList.toggle('active', panel.id === `panel-${tab.dataset.tab}`))
  })
}
load().catch((error) => { $('status-label').textContent = 'error'; $('diag-output').textContent = String(error) })
