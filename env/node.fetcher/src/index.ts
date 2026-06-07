import fs from 'fs'
import path from 'path'
import { PnpmError } from '@pnpm/error'
import {
  type FetchFromRegistry,
  type RetryTimeoutOptions,
} from '@pnpm/fetching-types'
import { pickFetcher } from '@pnpm/pick-fetcher'
import { createCafsStore } from '@pnpm/create-cafs-store'
import { createTarballFetcher } from '@pnpm/tarball-fetcher'
import AdmZip from 'adm-zip'
import isSubdir from 'is-subdir'
import renameOverwrite from 'rename-overwrite'
import tempy from 'tempy'
import { isNonGlibcLinux } from 'detect-libc'
import { getNodeTarball } from './getNodeTarball'

export interface FetchNodeOptions {
  storeDir: string
  fetchTimeout?: number
  nodeMirrorBaseUrl?: string
  retry?: RetryTimeoutOptions
}

export async function fetchNode (fetch: FetchFromRegistry, version: string, targetDir: string, opts: FetchNodeOptions): Promise<void> {
  if (await isNonGlibcLinux()) {
    throw new PnpmError('MUSL', 'The current system uses the "MUSL" C standard library. Node.js currently has prebuilt artifacts only for the "glibc" libc, so we can install Node.js only for glibc')
  }
  const nodeMirrorBaseUrl = opts.nodeMirrorBaseUrl ?? 'https://nodejs.org/download/release/'
  const { tarball, pkgName } = getNodeTarball(version, nodeMirrorBaseUrl, process.platform, process.arch)
  if (tarball.endsWith('.zip')) {
    await downloadAndUnpackZip(fetch, tarball, targetDir, pkgName)
    return
  }
  const getAuthHeader = () => undefined
  const fetchers = createTarballFetcher(fetch, getAuthHeader, {
    retry: opts.retry,
    timeout: opts.fetchTimeout,
    // These are not needed for fetching Node.js
    rawConfig: {},
    unsafePerm: false,
  })
  const cafs = createCafsStore(opts.storeDir)
  const fetchTarball = pickFetcher(fetchers, { tarball })
  const { filesIndex } = await fetchTarball(cafs, { tarball } as any, { // eslint-disable-line @typescript-eslint/no-explicit-any
    filesIndexFile: path.join(opts.storeDir, encodeURIComponent(tarball)), // TODO: change the name or don't save an index file for node.js tarballs
    lockfileDir: process.cwd(),
    pkg: {},
  })
  cafs.importPackage(targetDir, {
    filesResponse: {
      filesIndex: filesIndex as Record<string, string>,
      resolvedFrom: 'remote',
      requiresBuild: false,
    },
    force: true,
  })
}

/**
 * Downloads and extracts a ZIP file to a target directory.
 *
 * @param fetchFromRegistry - Function to fetch the ZIP file
 * @param zipUrl - URL of the ZIP file to download
 * @param targetDir - Directory where contents should be extracted
 * @param pkgName - Base name of the package (without extension)
 * @throws {PnpmError} When extraction fails or path traversal is detected
 */
async function downloadAndUnpackZip (
  fetchFromRegistry: FetchFromRegistry,
  zipUrl: string,
  targetDir: string,
  pkgName: string
): Promise<void> {
  const response = await fetchFromRegistry(zipUrl)
  const tmp = path.join(tempy.directory(), 'pnpm.zip')
  const dest = fs.createWriteStream(tmp)
  await new Promise((resolve, reject) => {
    response.body!.pipe(dest).on('error', reject).on('close', resolve)
  })
  const zip = new AdmZip(tmp)
  const nodeDir = path.dirname(targetDir)

  // Validate pkgName doesn't escape the target directory
  if (pkgName !== '') {
    validatePathSecurity(nodeDir, pkgName)
  }

  // Extract each entry with path validation to prevent path traversal attacks
  for (const entry of zip.getEntries()) {
    const entryPath = entry.entryName
    validatePathSecurity(nodeDir, entryPath)
    zip.extractEntryTo(entry, nodeDir, true, true)
  }

  await renameOverwrite(path.join(nodeDir, pkgName), targetDir)
  await fs.promises.unlink(tmp)
}

/**
 * Validates that a path does not escape the base directory via path traversal.
 *
 * @param basePath - The base directory that should contain the target
 * @param targetPath - The relative path to validate
 * @throws {PnpmError} When path traversal is detected
 */
function validatePathSecurity (basePath: string, targetPath: string): void {
  // Explicitly reject absolute paths - they should never be allowed as prefixes or entry names
  if (path.isAbsolute(targetPath)) {
    throw new PnpmError('PATH_TRAVERSAL',
      `Refusing to extract path "${targetPath}" - absolute paths are not allowed`)
  }
  const normalizedTarget = path.resolve(basePath, targetPath)
  if (!isSubdir(basePath, normalizedTarget) && normalizedTarget !== basePath) {
    throw new PnpmError('PATH_TRAVERSAL',
      `Refusing to extract path "${targetPath}" outside of target directory`)
  }
}
