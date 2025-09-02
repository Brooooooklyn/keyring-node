import os from 'node:os'

import test from 'ava'

import { Entry, findCredentials, findCredentialsAsync, AsyncEntry } from '../index'

const testPassword = 'napi.rs'
const testService = 'keyring-node-test-service'
const testUser = 'test-user'
const testSecret = new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]) // "hello" in bytes

test('Should create and get password back', (t) => {
  const entry = new Entry(testService, testUser)
  t.notThrows(() => entry.setPassword(testPassword))
  t.is(entry.getPassword(), testPassword)
  const [{ password: pass, account }] = findCredentials(testService)
  t.is(pass, testPassword)
  t.is(account, testUser)
  t.notThrows(() => entry.deleteCredential())
})

test('Should create and get password back async', async (t) => {
  const entry = new AsyncEntry(testService, testUser)
  await t.notThrowsAsync(() => entry.setPassword(testPassword))
  t.is(await entry.getPassword(), testPassword)
  const [{ password: pass, account }] = await findCredentialsAsync(testService)
  t.is(pass, testPassword)
  t.is(account, testUser)
  await t.notThrowsAsync(() => entry.deleteCredential())
})

test('Should create and set secret', (t) => {
  const entry = new Entry(testService, testUser)
  t.notThrows(() => entry.setSecret(testSecret))
  // Test that we can retrieve the secret back
  const retrievedSecret = entry.getSecret()
  t.truthy(retrievedSecret)
  t.deepEqual(new Uint8Array(retrievedSecret!), testSecret)
  t.notThrows(() => entry.deleteCredential())
})

test('Should create and set secret async', async (t) => {
  const entry = new AsyncEntry(testService, testUser)
  await t.notThrowsAsync(() => entry.setSecret(testSecret))
  // Test that we can retrieve the secret back
  const retrievedSecret = await entry.getSecret()
  t.truthy(retrievedSecret)
  // NAPI returns Vec<u8> as JavaScript array, so we need to convert for comparison
  t.deepEqual(new Uint8Array(retrievedSecret!), testSecret)
  await t.notThrowsAsync(() => entry.deleteCredential())
})

test('Should handle binary data correctly with setSecret/getSecret', (t) => {
  const entry = new Entry(testService, testUser)
  // Test with binary data that includes null bytes and high values
  const binaryData = new Uint8Array([0x00, 0x01, 0x7F, 0x80, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF])
  t.notThrows(() => entry.setSecret(binaryData))
  const retrievedSecret = entry.getSecret()
  t.truthy(retrievedSecret)
  t.deepEqual(new Uint8Array(retrievedSecret!), binaryData)
  t.notThrows(() => entry.deleteCredential())
})

test('Should handle binary data correctly with setSecret/getSecret async', async (t) => {
  const entry = new AsyncEntry(testService, testUser)
  // Test with binary data that includes null bytes and high values  
  const binaryData = new Uint8Array([0x00, 0x01, 0x7F, 0x80, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF])
  await t.notThrowsAsync(() => entry.setSecret(binaryData))
  const retrievedSecret = await entry.getSecret()
  t.truthy(retrievedSecret)
  t.deepEqual(new Uint8Array(retrievedSecret!), binaryData)
  await t.notThrowsAsync(() => entry.deleteCredential())
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
    t.notThrows(() => entry.deleteCredential())
  })

  test('AsyncEntry.withTarget() should use valid target', async (t) => {
    const entry = AsyncEntry.withTarget(testTarget!, testService, testUser)
    await t.notThrowsAsync(() => entry.setPassword(testPassword))
    t.is(await entry.getPassword(), testPassword)
    const [{ password: pass, account }] = await findCredentialsAsync(testService, testTarget!)
    t.is(pass, testPassword)
    t.is(account, testUser)
    await t.notThrowsAsync(() => entry.deleteCredential())
  })
} else {
  test.skip(`Skip testing Entry.withTarget() because of non-supported operating system: ${platform}`, (t) => {
    t.fail()
  })
}
