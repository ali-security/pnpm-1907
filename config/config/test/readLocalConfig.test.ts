import { fixtures } from '@pnpm/test-fixtures'
import { readLocalConfig } from '@pnpm/config'

const f = fixtures(__dirname)

test('readLocalConfig parse number field', async () => {
  const config = await readLocalConfig(f.find('has-number-setting'))
  expect(typeof config.childConcurrency).toBe('number')
})

test('readLocalConfig throws error when tokenHelper contains environment variable ${VAR}', async () => {
  await expect(
    readLocalConfig(f.find('tokenhelper-with-env-var'))
  ).rejects.toThrow('cannot contain environment variables for security reasons')
})

test('readLocalConfig throws error when scoped tokenHelper contains environment variable $VAR', async () => {
  await expect(
    readLocalConfig(f.find('tokenhelper-scoped-with-env-var'))
  ).rejects.toThrow('cannot contain environment variables for security reasons')
})
