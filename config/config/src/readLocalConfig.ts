import path from 'path'
import util from 'util'
import camelcaseKeys from 'camelcase-keys'
import { envReplace } from '@pnpm/config.env-replace'
import { PnpmError } from '@pnpm/error'
import { readIniFile } from 'read-ini-file'
import { parseField } from '@pnpm/npm-conf/lib/util'
import { types } from './types'

export type LocalConfig = Record<string, string> & { hoist?: boolean }

function containsEnvVariable (value: string): boolean {
  // Check for ${VAR} or ${VAR:-default} patterns
  if (/\$\{[^}]+\}/.test(value)) {
    return true
  }
  // Check for $VAR patterns (but not $$ which is escaped)
  if (/(?<!\$)\$[A-Za-z_][A-Za-z0-9_]*/.test(value)) {
    return true
  }
  return false
}

export async function readLocalConfig (prefix: string): Promise<LocalConfig> {
  try {
    const ini = await readIniFile(path.join(prefix, '.npmrc')) as Record<string, string>
    for (let [key, val] of Object.entries(ini)) {
      if (typeof val === 'string') {
        // Security fix for CVE-2025-69262: Prevent command injection via tokenHelper
        // Check before envReplace to detect environment variables in raw config
        const originalKey = key
        if ((originalKey === 'tokenHelper' || originalKey.endsWith(':tokenHelper')) && containsEnvVariable(val)) {
          throw new PnpmError(
            'ENV_VAR_IN_TOKEN_HELPER',
            `The "${originalKey}" setting cannot contain environment variables for security reasons. ` +
            'Please use an absolute path without environment variable substitution.'
          )
        }
        try {
          key = envReplace(key, process.env)
          ini[key] = parseField(types, envReplace(val, process.env), key) as any // eslint-disable-line
        } catch {}
      }
    }
    const config = camelcaseKeys(ini) as LocalConfig
    if (config.shamefullyFlatten) {
      config.hoistPattern = '*'
      // TODO: print a warning
    }
    if (config.hoist === false) {
      config.hoistPattern = ''
    }
    return config
  } catch (err: unknown) {
    if (util.types.isNativeError(err) && 'code' in err && err.code === 'ENOENT') return {}
    throw err
  }
}
