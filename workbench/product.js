/* User-facing workflows; every result comes from the existing Core HTTP API. */
(() => {
  const el = id => document.getElementById(id)
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))
  let session, catalog, selected, running = false
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
  }
  function actions() {
    const query = el('product-search').value.trim().toLowerCase()
    const visible = catalog.actions.filter(a => (a.title+' '+a.description).toLowerCase().includes(query))
    el('product-actions').innerHTML = visible.length ? visible.map(a => `<button type="button" class="action-option ${selected?.id===a.id?'selected':''}" data-action="${escape(a.id)}" aria-pressed="${selected?.id===a.id}"><strong>${escape(a.title)}</strong><span>${escape(a.description)}</span><small>只读 · ${a.targetKind==='file'?'单个文件':'项目目录'}</small></button>`).join('') : '<p>没有匹配的功能。试试“文件”“代码”或“依赖”。</p>'
    for (const button of el('product-actions').querySelectorAll('[data-action]')) button.addEventListener('click', () => {
      selected = catalog.actions.find(a => a.id===button.dataset.action)
      el('composer-title').textContent = selected.title
      el('product-description').textContent = selected.description
      el('product-target').placeholder = selected.placeholder
      el('product-target').value = selected.targetKind==='directory'?'.':''
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
  async function tasks() {
    if (!session?.enabled) return
    try {
      const rows = await request('tasks')
      el('product-tasks').innerHTML=rows.length?rows.map(t=>`<article class="live-task"><div><h3>${escape(catalog.actions.find(a=>(t.workflowId&&a.workflow===t.workflowId)||a.capability===t.capability)?.title??t.title)}</h3><p>${escape(t.scope==='example'?'内置示例':'当前项目')} · ${escape(t.state)} · ${escape(t.createdAt)}</p><small>${escape(t.taskId)}</small></div>${t.reportAvailable?`<div class="task-actions"><button type="button" data-report="${escape(t.taskId)}">查看报告</button><button type="button" data-download="${escape(t.taskId)}">下载 Markdown</button></div>`:''}</article>`).join(''):'还没有任务。运行首页示例，或选择一个项目检查。'
      attachReports(el('product-tasks'))
    } catch { el('product-tasks').textContent='未能加载任务，请点击“刷新任务”重试。' }
  }
  async function run(example) {
    if (running) return
    running=true;availability()
    el('product-feedback').className='feedback';el('product-feedback').textContent='Core 正在执行只读检查，完成后将在这里显示真实结果。'
    el('product-result').hidden=true
    el('product-example').textContent=example?'正在检查…':'运行安全示例'
    el('product-run').textContent=example?'开始检查':'正在检查…'
    try {
      const result=await request(example?'example':'run',example?{}:{action:selected.id,target:el('product-target').value})
      const complete=result.state==='COMPLETED'
      el('product-feedback').textContent=complete?`检查完成，用时 ${result.durationMs} ms。已记录 ${result.evidenceIds.length} 条证据。`:`任务状态：${result.state}。请查看报告中的原因。`
      el('product-feedback').className=complete?'feedback success':'feedback error'
      const digest=result.data?.digests?.sha256
      const steps=result.data?.workflowId&&Array.isArray(result.data.steps)?result.data.steps:null
      const workflowSummary=steps?`<p>完成 ${steps.filter(s=>s.status==='DONE').length} / ${steps.length} 项分析；记录 ${escape(result.data.findings)} 条待核对发现。</p><ol>${steps.map(s=>`<li><strong>${escape(s.title)}</strong> · ${escape(s.status)}${s.summary?`<p>${escape(s.summary)}</p>`:''}</li>`).join('')}</ol>`:''
      el('product-result').innerHTML=`<h3>${complete?'结果已保存':'检查未完成'}</h3><p>${example?'分析的是内置文本，没有读取你的项目文件。':'项目输入未被修改。此结果只覆盖所选能力的实际检查范围。'}</p>${digest?`<dl><dt>SHA-256</dt><dd><code>${escape(digest)}</code></dd></dl>`:''}<p>任务 <code>${escape(result.taskId)}</code></p>${result.reportAvailable?`<div class="task-actions"><button type="button" data-report="${escape(result.taskId)}">查看报告</button><button type="button" data-download="${escape(result.taskId)}">下载 Markdown</button></div>`:''}<details><summary>查看原始结果</summary><pre>${escape(JSON.stringify(result.data,null,2))}</pre></details>`
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
