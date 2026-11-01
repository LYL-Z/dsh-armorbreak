import test from 'node:test'
import assert from 'node:assert/strict'
import { isFilesystemPathWithin, sameFilesystemPath } from '../lib/core/pathBoundary.js'

test('Windows extended drive paths compare and remain within their canonical path boundary', () => {
  assert.equal(sameFilesystemPath('C:\\work\\task', '\\\\?\\C:\\work\\task', 'win32'), true)
  assert.equal(isFilesystemPathWithin('C:\\work\\task', '\\\\?\\C:\\work\\task\\reports\\report.md', 'win32'), true)
  assert.equal(isFilesystemPathWithin('C:\\work\\task', '\\\\?\\C:\\work\\task-escape\\report.md', 'win32'), false)
  assert.equal(isFilesystemPathWithin('C:\\work\\task', 'D:\\work\\task\\report.md', 'win32'), false)
})

test('Windows extended UNC paths compare with their ordinary UNC equivalents', () => {
  assert.equal(sameFilesystemPath('\\\\server\\share\\task', '\\\\?\\UNC\\server\\share\\task', 'win32'), true)
  assert.equal(isFilesystemPathWithin('\\\\server\\share\\task', '\\\\?\\UNC\\server\\share\\task\\reports\\report.md', 'win32'), true)
  assert.equal(isFilesystemPathWithin('\\\\server\\share\\task', '\\\\?\\UNC\\server\\other\\task\\report.md', 'win32'), false)
})
