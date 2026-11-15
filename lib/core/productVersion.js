/** Distribution identity is separate from the stable protocol/Core facade contract. */
import { readFileSync } from 'node:fs'
export const PRODUCT_VERSION = JSON.parse(readFileSync(new URL('../../package.json',import.meta.url),'utf8')).version
