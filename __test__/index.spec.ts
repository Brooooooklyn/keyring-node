import os from 'node:os'

import test from 'ava'

import { Entry, findCredentials, findCredentialsAsync, AsyncEntry } from '../index'

const testPassword = 'napi.rs'
const testService = 'keyring-node-test-service'
const testUser = 'test-user'

test('Should create and get password back', (t) => {
  const entry = new Entry(testService, testUser)
  t.notThrows(() => entry.setPassword(testPassword))
  t.is(entry.getPassword(), testPassword)
  const [{ password: pass, account }] = findCredentials(testService)
  t.is(pass, testPassword)
  t.is(account, testUser)
  t.notThrows(() => entry.deletePassword())
})

test('Should create and get password back async', async (t) => {
  const entry = new AsyncEntry(testService, testUser)
  await t.notThrowsAsync(() => entry.setPassword(testPassword))
  t.is(await entry.getPassword(), testPassword)
  const [{ password: pass, account }] = await findCredentialsAsync(testService)
  t.is(pass, testPassword)
  t.is(account, testUser)
  await t.notThrowsAsync(() => entry.deletePassword())
})

let testTarget: string | undefined

const platform = os.platform()
switch (platform) {
  // macOS uses target to choose between one of the following keychains: 'User', 'System', 'Common', 'Dynamic'. Default: 'User'
  case 'darwin':
    testTarget = 'User'
    break
  // Windows uses target as the only keyring identifier. Default: {service}.{user}
  case 'win32':
    testTarget = `keyring-node-test-target.${testService}.${testUser}`
    break
  // Linux uses target as the only keyring identifier. Default: keyring-rs:{user}@{service}
  case 'linux':
  case 'freebsd':
    testTarget = `keyring-node-test-target:${testUser}@${testService}`
    break
  default:
    console.info(`Unsupported OS to test [${platform}]`)
}

if (testTarget && !(process.env.CI && (platform === 'linux' || platform === 'freebsd'))) {
  test('Entry.withTarget() should use valid target', (t) => {
    const entry = Entry.withTarget(testTarget!, testService, testUser)
    t.notThrows(() => entry.setPassword(testPassword))
    t.is(entry.getPassword(), testPassword)
    const [{ password: pass, account }] = findCredentials(testService, testTarget!)
    t.is(pass, testPassword)
    t.is(account, testUser)
    t.notThrows(() => entry.deletePassword())
  })

  test('AsyncEntry.withTarget() should use valid target', async (t) => {
    const entry = AsyncEntry.withTarget(testTarget!, testService, testUser)
    await t.notThrowsAsync(() => entry.setPassword(testPassword))
    t.is(await entry.getPassword(), testPassword)
    const [{ password: pass, account }] = await findCredentialsAsync(testService, testTarget!)
    t.is(pass, testPassword)
    t.is(account, testUser)
    await t.notThrowsAsync(() => entry.deletePassword())
  })
} else {
  test.skip(`Skip testing Entry.withTarget() because of non-supported operating system: ${platform}`, (t) => {
    t.fail()
  })
}
