// SPDX-FileCopyrightText: 2026 LYL-Z
// SPDX-License-Identifier: MIT
/** Work on a private copy of a validated document. Public results contain only operation counts. */
import { exportConfiguration, importConfiguration, parseStrictConfigurationData } from './configFormats.js'
import { canonicalConfig } from './configOverlay.js'

export const CONFIG_EDIT_SCHEMA = 'armorbreak.configuration-edit-request/v1'
const blockedKeys = new Set(['__proto__', 'constructor', 'prototype', '<<'])
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const operationFields = {
  add: ['op', 'path', 'value'],
  replace: ['expected', 'op', 'path', 'value'],
  remove: ['expected', 'op', 'path'],
}
const hasFields = (object, fields) =>
  Object.keys(object).length === fields.length && fields.every(field => Object.hasOwn(object, field))

export function parseConfigurationEdit(buffer) {
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buffer)
  } catch {
    throw new Error('CONFIG_EDIT_INVALID_JSON')
  }
  return parseStrictConfigurationData(text, true)
}

function validateOperation(change) {
  if (!isObject(change) || typeof change.op !== 'string' || !Object.hasOwn(operationFields, change.op) ||
      !hasFields(change, operationFields[change.op])) {
    throw new Error('CONFIG_EDIT_OPERATION_INVALID')
  }
  if (!Array.isArray(change.path) || change.path.length === 0 || change.path.length > 24 ||
      !change.path.every(part => typeof part === 'string' ? !blockedKeys.has(part) : Number.isSafeInteger(part) && part >= 0)) {
    throw new Error('CONFIG_EDIT_PATH_INVALID')
  }
}

function checkContainer(container, key) {
  if (Array.isArray(container) ? typeof key === 'number' : isObject(container) && typeof key === 'string') return
  throw new Error('CONFIG_EDIT_PATH_INVALID')
}

function update(data, { op, path, value, expected }) {
  let container = data
  for (const key of path.slice(0, -1)) {
    checkContainer(container, key)
    if (!Object.hasOwn(container, key)) throw new Error('CONFIG_EDIT_PATH_CONFLICT')
    container = container[key]
  }

  const key = path.at(-1)
  checkContainer(container, key)
  if (op === 'add') {
    if (Array.isArray(container)) {
      if (key > container.length) throw new Error('CONFIG_EDIT_PATH_CONFLICT')
      container.splice(key, 0, structuredClone(value))
    } else {
      if (Object.hasOwn(container, key)) throw new Error('CONFIG_EDIT_PATH_CONFLICT')
      container[key] = structuredClone(value)
    }
    return
  }

  if (!Object.hasOwn(container, key) || canonicalConfig(container[key]) !== canonicalConfig(expected)) {
    throw new Error('CONFIG_EDIT_VALUE_CONFLICT')
  }
  if (op === 'replace') container[key] = structuredClone(value)
  else if (Array.isArray(container)) container.splice(key, 1)
  else delete container[key]
}

export function prepareConfigurationEdit(request) {
  if (!isObject(request) || request.schema !== CONFIG_EDIT_SCHEMA ||
      !hasFields(request, ['configuration', 'operations', 'schema']) ||
      !Array.isArray(request.operations) || request.operations.length === 0 || request.operations.length > 128) {
    throw new Error('CONFIG_EDIT_REQUEST_INVALID')
  }
  canonicalConfig(request)
  const { configuration, operations } = request
  const { document } = importConfiguration(configuration)
  const initial = canonicalConfig(document.data)
  const counts = { add: 0, replace: 0, remove: 0 }
  for (const operation of operations) {
    validateOperation(operation)
    update(document.data, operation)
    counts[operation.op]++
  }

  // Serialize before reporting success, so preview and staging agree on format validity.
  const candidate = exportConfiguration(document, { preserveSource: configuration.source })
  const final = canonicalConfig(document.data)
  const changed = initial !== final
  if (changed) {
    const verified = importConfiguration({ ...configuration, source: candidate }).document
    if (canonicalConfig(verified.data) !== final) throw new Error('CONFIG_EDIT_CANDIDATE_MISMATCH')
  }
  return {
    candidate,
    preview: {
      schema: 'armorbreak.configuration-edit-preview/v1',
      status: changed ? 'PREVIEW_READY' : 'NO_CHANGES',
      format: document.format,
      mode: 'READ_ONLY',
      operations: counts,
      applied: false,
    },
  }
}
