/**
 * Syft SBOM adapter (v1.2.0).
 *
 * Runs `syft dir:<workspace> -o cyclonedx-json` and normalizes components into an
 * inventory. No CVE conclusion is drawn from component names/versions: OSV/NVD
 * offline data is not bundled, so findings stay informational.
 * @module dsh-armorbreak/lib/analyzers/sast/syft
 */
import { existsSync } from 'node:fs'
import { basename, resolve } from 'node:path'
import { executeTool, parseJsonOutput, resolveSyft, sha256, EXTERNAL_TOOL_GUIDANCE } from '../../core/externalTools.js'

function evidence(title, kind, excerpt, meta = {}) {
  return { title, kind, excerpt: String(excerpt).slice(0, 2000), meta }
}

/** @param {string} raw @param {{maxComponents?: number}} [options] */
export function parseSyftReport(raw, options = {}) {
  const report = parseJsonOutput(raw, 'syft')
  if (!report || typeof report !== 'object' || !Array.isArray(report.components)) {
    throw new Error('syft output JSON is not a CycloneDX report (missing components array)')
  }
  const maxComponents = Math.max(1, Math.min(Number(options.maxComponents ?? 500), 5000))
  const components = report.components.slice(0, maxComponents).map((component) => {
    const licenses = Array.isArray(component.licenses)
      ? component.licenses.map((item) => item?.license?.id ?? item?.license?.name ?? item?.expression).filter(Boolean).slice(0, 10)
      : []
    return {
      name: String(component.name ?? '').slice(0, 200),
      version: String(component.version ?? '').slice(0, 100) || null,
      type: String(component.type ?? '').slice(0, 40) || null,
      purl: String(component.purl ?? '').slice(0, 300) || null,
      cpes: Array.isArray(component.cpes) ? component.cpes.slice(0, 5).map((cpe) => String(cpe).slice(0, 300)) : [],
      licenses,
      hashes: Array.isArray(component.hashes) ? component.hashes.slice(0, 5).map((hash) => ({ algorithm: String(hash.alg ?? ''), value: String(hash.content ?? '').slice(0, 200) })) : [],
    }
  })
  const allComponents = report.components
  const missingVersion = allComponents.filter((component) => !component.version).length
  const types = {}
  for (const component of allComponents) types[component.type ?? 'unknown'] = (types[component.type ?? 'unknown'] ?? 0) + 1
  const findings = missingVersion > 0
    ? [{
        title: `SBOM 中有 ${missingVersion} 个组件缺少版本信息`,
        severity: 'info',
        description: '缺少版本会降低依赖追溯与漏洞映射的准确性；这是 SBOM 数据质量问题，不是漏洞。',
        verification: 'observed',
        method: 'Syft CycloneDX components[].version 检查',
        cwe: null,
        cvss: null,
        remediation: '在构建/打包流程中补齐 version 元数据，或提供 lockfile 后重新生成 SBOM。',
        target: null,
        evidence: [evidence('缺少版本的组件样本', 'syft-sbom', JSON.stringify(components.filter((component) => !component.version).slice(0, 10)))],
      }]
    : []
  const data = {
    source: String(report.metadata?.component?.name ?? basename(String(options.path ?? 'workspace'))).slice(0, 200),
    componentCount: report.components.length,
    returned: components.length,
    truncated: report.components.length > maxComponents,
    types,
    components,
    verification: 'observed',
    tool: 'syft',
    cveConclusion: false,
    note: 'Syft 只做组件盘点；未接入 OSV/NVD 离线库前不输出 CVE 结论。',
  }
  const summary = [
    `Syft SBOM：${data.componentCount} 个组件（返回 ${components.length}${data.truncated ? '，已截断' : ''}），类型 ${Object.entries(types).map(([type, count]) => `${type}:${count}`).join(', ') || '无'}。`,
    missingVersion > 0 ? `${missingVersion} 个组件缺少版本，依赖追溯需补齐。` : '所有返回组件均带版本信息。',
    '仅组件盘点，不代表存在漏洞；CVE 结论需要独立的离线漏洞库。',
  ].join('\n')
  return {
    summary,
    findings,
    evidence: [evidence('SBOM 组件清单', 'syft-sbom', JSON.stringify(components.slice(0, 20)), { componentCount: data.componentCount })],
    data,
  }
}

export const syftCapability = {
  id: 'sast.syft',
  title: 'Syft SBOM 盘点（外部工具）',
  description: '调用本机 Syft 对目录生成 CycloneDX SBOM，归一化组件名称/版本/许可证/CPE/purl。argv 数组、无 shell、输出有界；缺失工具 fail-closed。只做组件盘点，未接入离线漏洞库前不输出 CVE 结论。',
  riskLevel: 'L0',
  targetKind: 'directory',
  params: {
    type: 'object',
    properties: {
      maxComponents: { type: 'integer', minimum: 1, maximum: 5000, description: '返回的组件上限，默认 500。' },
    },
    additionalProperties: false,
  },
  async run(input) {
    const targetPath = input.targetPath ?? null
    if (!targetPath) throw new Error('sast.syft needs a directory target')
    if (!existsSync(targetPath)) throw new Error(`workspace directory not found: ${targetPath}`)
    const tool = typeof input.env?.execExternal === 'function'
      ? { command: 'syft', prefixArgs: [] }
      : { command: resolveSyft(process.env), prefixArgs: [] }
    const args = [`dir:${resolve(targetPath)}`, '-o', 'cyclonedx-json', '--quiet']
    let result
    try {
      result = await executeTool(input.env, tool, args, { timeoutMs: input.limits?.timeoutMs ?? 180_000, maxOutputBytes: 32 * 1024 * 1024 })
    } catch (error) {
      throw new Error(`sast.syft failed: ${String(error?.message ?? error)} ${EXTERNAL_TOOL_GUIDANCE.syft}`.trim())
    }
    if (!result.stdout.trim()) throw new Error('syft produced no JSON output; the directory may be empty or unreadable')
    const parsed = parseSyftReport(result.stdout, { ...input.options, path: targetPath })
    return {
      ...parsed,
      meta: {
        domain: 'sast', capability: 'sast.syft', tool: 'syft', target: targetPath,
        stdoutSha256: sha256(result.stdout), stdoutBytes: Buffer.byteLength(result.stdout), truncated: parsed.data.truncated,
      },
    }
  },
}
