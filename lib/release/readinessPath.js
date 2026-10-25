export const HISTORICAL_FULL_GA_READINESS_PATH = 'docs/v2/release/readiness.json'
export const STABLE_READINESS_PATH = 'docs/v2/release/stable-readiness.json'
export const STABLE_PACKAGE_VERSION = '2.2.0'

/** Keep the historical readiness snapshot immutable for the 2.2.0 Stable package. */
export function readinessOutputPath({ packageVersion } = {}) {
  // Do not let a missing or malformed policy redirect a Stable run into the
  // historical RC/Full GA file. The Stable Gate validates policy separately.
  if (packageVersion === STABLE_PACKAGE_VERSION) {
    return STABLE_READINESS_PATH
  }
  return HISTORICAL_FULL_GA_READINESS_PATH
}
