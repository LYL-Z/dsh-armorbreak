import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { PRODUCT_VERSION } from '../lib/core/productVersion.js'
import { createProductApi } from '../workbench/product.mjs'
test('product identity follows root version and both dependency locks without changing Core protocol version',async()=>{
 const read=path=>JSON.parse(readFileSync(new URL('../'+path,import.meta.url),'utf8'))
 const pkg=read('package.json');assert.equal(PRODUCT_VERSION,pkg.version)
 for(const name of ['package-lock.json','npm-shrinkwrap.json']){const lock=read(name);assert.equal(lock.version,pkg.version);assert.equal(lock.packages[''].version,pkg.version);assert.deepEqual(lock.packages[''].dependencies,pkg.dependencies)}
 const api=createProductApi({engine:{capabilities:async()=>[]},ctx:{workspaceId:process.cwd()}})
 assert.equal((await api.catalog()).productVersion,pkg.version)
})
