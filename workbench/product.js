/* User-facing workflows; every result comes from the existing Core HTTP API. */
(() => {
  const el = id => document.getElementById(id)
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))
  let session, catalog, selected, running = false, advanced = false
  const modeKey = 'armorbreak.workbench.mode'
  const headers = () => ({'content-type':'application/json','x-armorbreak-session':session.csrf})
  async function request(path, input) {
    const response = await fetch('/api/product/'+path, {headers:headers(), ...(input === undefined ? {} : {method:'POST',body:JSON.stringify(input)})})
    const data = await response.json()
    if (!response.ok) throw new Error(data.detail || (response.status === 403 ? '会话已失效，请刷新页面后重试。' : '操作未完成，请检查输入后重试。'))
    return data
  }
  function availability() {
    el('product-example').disabled = running || !catalog?.exampleAvailable
    el('product-run').disabled = running || !selected
    el('product-target').disabled=running
    el('product-snapshot').disabled=running || !selected?.acceptsSnapshotId
    el('workbench-mode').disabled=running
    for(const button of el('product-actions').querySelectorAll('[data-action]'))button.disabled=running
  }
  function selectAction(action) {
    selected = action
    el('composer-title').textContent = selected?.title ?? '检查目标'
    el('product-description').textContent = selected?.description ?? '选择一项检查，或运行上方示例。'
    el('product-target').placeholder = selected?.placeholder ?? '例如：src 或 .'
    el('product-target').value = selected?.targetKind==='directory'&&!selected.explicitTarget?'.':''
    for (const id of ['product-snapshot-label','product-snapshot','product-snapshot-help']) el(id).hidden = !selected?.acceptsSnapshotId
    el('product-snapshot').value = ''
  }
  function setMode(value) {
    advanced = value === 'advanced'
    el('workbench-mode').value = advanced ? 'advanced' : 'guided'
    for (const item of document.querySelectorAll('[data-advanced]')) item.hidden = !advanced
    if (document.querySelector('.tab.active')?.hidden) window.activateWorkbenchTab('home')
    if (!advanced && selected && !selected.guided) selectAction(undefined)
    if (catalog) actions()
    availability()
  }
  window.initializeWorkbenchMode = () => {
    let preference
    try { preference = localStorage.getItem(modeKey) } catch {}
    setMode(preference)
  }
  el('workbench-mode').addEventListener('change', event => {
    if (running) return
    setMode(event.target.value)
    try { localStorage.setItem(modeKey, event.target.value) } catch {}
  })
  function actions() {
    const query = el('product-search').value.trim().toLowerCase()
    const visible = catalog.actions.filter(a => (advanced || a.guided) && (a.title+' '+a.description).toLowerCase().includes(query))
    el('product-actions').innerHTML = visible.length ? visible.map(a => `<button type="button" class="action-option ${selected?.id===a.id?'selected':''}" data-action="${escape(a.id)}" aria-pressed="${selected?.id===a.id}"><strong>${escape(a.title)}</strong><span>${escape(a.description)}</span><small>只读 · ${escape(a.targetLabel??(a.targetKind==='file'?'单个文件':'项目目录'))}</small></button>`).join('') : '<p>没有匹配的功能。试试“文件”“代码”“宿主”“插件”或“配置”。</p>'
    for(const button of el('product-actions').querySelectorAll('[data-action]'))button.disabled=running
    for (const button of el('product-actions').querySelectorAll('[data-action]')) button.addEventListener('click', () => {
      if(running)return
      selectAction(catalog.actions.find(a => a.id===button.dataset.action))
      actions();availability();el('product-target').focus()
    })
  }
  async function report(taskId, download = false) {
    try {
      const data = await request('report?taskId='+encodeURIComponent(taskId))
      if (download) {
        const url = URL.createObjectURL(new Blob([data.markdown],{type:'text/markdown;charset=utf-8'})), link = document.createElement('a')
        link.href=url;link.download=taskId+'.md';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000)
      } else { el('product-report').textContent=data.markdown;el('product-report').hidden=false;window.activateWorkbenchTab('results');el('product-report').scrollIntoView({block:'nearest'}) }
    } catch (error) { el('product-feedback').textContent=error.message;el('product-feedback').className='feedback error' }
  }
  function attachReports(container) {
    for (const b of container.querySelectorAll('[data-report]')) b.addEventListener('click',()=>report(b.dataset.report))
    for (const b of container.querySelectorAll('[data-download]')) b.addEventListener('click',()=>report(b.dataset.download,true))
  }
  async function retryTask(taskId) {
    if (running || !taskId) return
    running = true
    availability()
    el('product-feedback').className = 'feedback'
    el('product-feedback').textContent = '正在用原来的检查目标重新运行。失败记录会保留。'
    try {
      const result = await request('retry', { taskId })
      const complete = result.state === 'COMPLETED'
      el('product-feedback').textContent = complete ? `重新检查完成，用时 ${result.durationMs} ms。已记录 ${result.evidenceIds.length} 条证据。` : `重新检查后的状态：${result.state}。原失败记录未改写。`
      el('product-feedback').className = complete ? 'feedback success' : 'feedback error'
      await tasks()
    } catch (error) {
      el('product-feedback').textContent = error.message
      el('product-feedback').className = 'feedback error'
    } finally {
      running = false
      availability()
    }
  }
  async function tasks() {
    if (!session?.enabled) return
    try {
      const rows = await request('tasks')
      el('product-tasks').innerHTML=rows.length?rows.map(t=>`<article class="live-task"><div><h3>${escape(catalog.actions.find(a=>(t.workflowId&&a.workflow===t.workflowId)||a.capability===t.capability)?.title??t.title)}</h3><p>${escape(t.scope==='example'?'内置示例':'当前项目')} · ${escape(t.state)} · ${escape(t.createdAt)}</p><small>${escape(t.taskId)}${t.retryOf?` · 来自 ${escape(t.retryOf)}`:''}</small></div><div class="task-actions">${t.retryable?`<button type="button" data-retry="${escape(t.taskId)}">重新检查</button>`:''}${t.reportAvailable?`<button type="button" data-report="${escape(t.taskId)}">查看报告</button><button type="button" data-download="${escape(t.taskId)}">下载 Markdown</button>`:''}</div></article>`).join(''):'还没有任务。运行首页示例，或选择一个项目检查。'
      attachReports(el('product-tasks'))
      for (const b of el('product-tasks').querySelectorAll('[data-retry]')) b.addEventListener('click',()=>retryTask(b.dataset.retry))
    } catch { el('product-tasks').textContent='未能加载任务，请点击“刷新任务”重试。' }
  }
  function diagnosticSummary(data) {
    if(data?.schema==='armorbreak.backup-snapshot-verification/v1'){
      return '<h4>快照内容与清单一致</h4><p>已核对 '+escape(data.snapshotFiles)+' 个快照文件和 '+escape(data.referencedObjects)+' 个对象。清单来源与恢复能力仍待验证。</p>'
    }
    if(data?.schema==='armorbreak.backup-usage/v1'){
      const bytes=new Intl.NumberFormat('zh-CN',{maximumFractionDigits:1,style:'unit',unit:'megabyte'}).format(data.bytes/1_000_000)
      return '<h4>备份占用</h4><p>'+escape(data.count)+' 份清单标明完成的快照，'+escape(data.objectFiles)+' 个对象文件，共 '+escape(bytes)+'（'+escape(data.bytes)+' 字节）。'+escape(data.unconfirmedSnapshots)+' 份快照缺少有效完成标记。此检查仅测量体积，恢复能力待验证。</p>'
    }
    if(data?.schema==='armorbreak.host-health/v1'){
      const observed=data.observation==='DETECTED_ON_DISK'?'检测到磁盘包':'未确认磁盘包'
      return '<h4>宿主检查</h4><p>'+observed+' · 版本：'+escape(data.identity?.version??'未知')+'。未验证正在运行的宿主或模型连接。</p>'
    }
    if(data?.verificationStatus==='LOCAL_PACKAGE_CLOSURE_VERIFIED'){
      return '<h4>插件包完整性</h4><p>本地包闭包核对完成，共 '+escape(data.closure?.length??0)+' 个文件。未认证来源及权利、未授权激活、未安装或运行插件。</p>'
    }
    if(data?.schema==='armorbreak.config-preview/v2'){
      return '<h4>配置预览</h4><p>'+escape(data.changes?.length??0)+' 项变更，'+escape(data.conflicts?.length??0)+' 项冲突。只展示结构，未应用任何配置。</p>'
    }
    return ''
  }
  async function run(example) {
    if (running) return
    running=true;availability()
    el('product-feedback').className='feedback';el('product-feedback').textContent='Core 正在执行只读检查，完成后将在这里显示真实结果。'
    el('product-result').hidden=true
    el('product-example').textContent=example?'正在检查…':'运行安全示例'
    el('product-run').textContent=example?'开始检查':'正在检查…'
    try {
      const snapshotId=el('product-snapshot').value.trim()
      const input=example?{}:{action:selected.id,target:el('product-target').value}
      if (!example && selected.acceptsSnapshotId && snapshotId) input.snapshotId = snapshotId
      const result=await request(example?'example':'run',input)
      const complete=result.state==='COMPLETED'
      el('product-feedback').textContent=complete?`检查完成，用时 ${result.durationMs} ms。已记录 ${result.evidenceIds.length} 条证据。`:`任务状态：${result.state}。请查看报告中的原因。`
      el('product-feedback').className=complete?'feedback success':'feedback error'
      const digest=result.data?.digests?.sha256
      const steps=result.data?.workflowId&&Array.isArray(result.data.steps)?result.data.steps:null
      const workflowSummary=steps?`<p>完成 ${steps.filter(s=>s.status==='DONE').length} / ${steps.length} 项分析；记录 ${escape(result.data.findings)} 条待核对发现。</p><ol>${steps.map(s=>`<li><strong>${escape(s.title)}</strong> · ${escape(s.status)}${s.summary?`<p>${escape(s.summary)}</p>`:''}</li>`).join('')}</ol>`:''
      el('product-result').innerHTML=`<h3>${complete?'结果已保存':'检查未完成'}</h3><p>${example?'分析的是内置文本，没有读取你的项目文件。':'项目输入未被修改。此结果只覆盖所选能力的实际检查范围。'}</p>${digest?`<dl><dt>SHA-256</dt><dd><code>${escape(digest)}</code></dd></dl>`:''}<p>任务 <code>${escape(result.taskId)}</code></p>${result.reportAvailable?`<div class="task-actions"><button type="button" data-report="${escape(result.taskId)}">查看报告</button><button type="button" data-download="${escape(result.taskId)}">下载 Markdown</button></div>`:''}<details><summary>查看原始结果</summary><pre>${escape(JSON.stringify(result.data,null,2))}</pre></details>`
      const raw = el('product-result').querySelector('details')
      raw.dataset.advanced = ''
      raw.hidden = !advanced
      const diagnostic=diagnosticSummary(result.data)
      if(diagnostic)el('product-result').insertAdjacentHTML('beforeend',diagnostic)
      if(workflowSummary)el('product-result').insertAdjacentHTML('beforeend',workflowSummary)
      el('product-result').hidden=false;attachReports(el('product-result'));el('product-result').scrollIntoView({block:'start'});await tasks()
    } catch(error) { el('product-feedback').textContent=error.message;el('product-feedback').className='feedback error';el('product-feedback').scrollIntoView({block:'center'}) }
    finally { running=false;availability();el('product-example').textContent='运行安全示例';el('product-run').textContent='开始检查' }
  }
  window.initializeProduct = async nativeSession => {
    session=nativeSession
    if (!session.enabled) {el('product-connection').textContent='尚未选择工作区。请使用 armorbreak start --workspace <项目目录> 启动。';return}
    try {
      catalog=await request('catalog')
      el('product-connection').textContent=`ArmorBreak ${catalog.productVersion} · 当前项目：${catalog.workspaceName} · 本地 Core 已连接 · DSH / 模型未连接`
      el('product-unavailable').innerHTML=catalog.unavailable.map(x=>`<li><strong>${escape(x.title)}</strong>：${escape(x.reason)}</li>`).join('')
      actions();availability();await tasks()
    } catch {el('product-connection').textContent='未能读取可用功能，请刷新页面重试。'}
  }
  el('product-search').addEventListener('input',()=>{if(catalog)actions()})
  el('product-example').addEventListener('click',()=>run(true))
  el('product-form').addEventListener('submit',event=>{event.preventDefault();if(selected)run(false)})
  el('product-reload-tasks').addEventListener('click',tasks)
})()
