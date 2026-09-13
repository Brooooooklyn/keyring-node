import os from 'node:os'

import test from 'ava'

import { Entry, findCredentials, findCredentialsAsync, AsyncEntry } from '../index'

const testPassword = 'napi.rs'
const testService = 'keyring-node-test-service'
const testUser = 'test-user'
const testSecret = new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]) // "hello" in bytes
const testDeleteUser = 'test-delete-user'
const testMissingSecretUser = 'test-missing-secret-user'

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

test('deleteCredential should report whether a credential was removed', (t) => {
  const entry = new Entry(testService, testDeleteUser)
  t.notThrows(() => entry.setPassword(testPassword))
  t.true(entry.deleteCredential(), 'deleting an existing credential reports true')
  t.false(entry.deleteCredential(), 'deleting a missing credential reports false')
})

test('deleteCredential should report whether a credential was removed async', async (t) => {
  const entry = new AsyncEntry(testService, testDeleteUser)
  await t.notThrowsAsync(() => entry.setPassword(testPassword))
  t.true(await entry.deleteCredential(), 'deleting an existing credential resolves true')
  t.false(await entry.deleteCredential(), 'deleting a missing credential resolves false')
})

test('deletePassword should behave like deleteCredential', (t) => {
  const entry = new Entry(testService, testDeleteUser)
  t.notThrows(() => entry.setPassword(testPassword))
  t.true(entry.deletePassword())
  t.false(entry.deletePassword())
})

test('deletePassword should behave like deleteCredential async', async (t) => {
  const entry = new AsyncEntry(testService, testDeleteUser)
  await t.notThrowsAsync(() => entry.setPassword(testPassword))
  t.true(await entry.deletePassword())
  t.false(await entry.deletePassword())
})

test('Should return no secret value when the entry is missing async', async (t) => {
  const entry = new AsyncEntry(testService, testMissingSecretUser)
  // These resolve `null` at runtime while being declared as `undefined`.
  t.is((await entry.getSecret()) ?? null, null)
})

test('Should return no secret value when the entry is missing', (t) => {
  const entry = new Entry(testService, testMissingSecretUser)
  t.is(entry.getSecret(), null)
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

  test('Entry.withTarget() accepts the options bag', (t) => {
    const entry = Entry.withTarget(testTarget!, testService, testUser, { linux: { store: 'keyutils' } })
    t.notThrows(() => entry.setPassword(testPassword))
    t.is(entry.getPassword(), testPassword)
    t.notThrows(() => entry.deleteCredential())
  })
} else {
  test.skip(`Skip testing Entry.withTarget() because of non-supported operating system: ${platform}`, (t) => {
    t.fail()
  })
}

const testLinuxSecretServiceService = 'keyring-node-test-service-linux-secret-service'
const testLinuxKeyutilsService = 'keyring-node-test-service-linux-keyutils'

if (platform === 'linux') {
  test('linux store option: secret-service round-trips', (t) => {
    const entry = new Entry(testLinuxSecretServiceService, testUser, { linux: { store: 'secret-service' } })
    t.notThrows(() => entry.setPassword(testPassword))
    t.is(entry.getPassword(), testPassword)
    t.true(entry.deleteCredential(), 'clean up the pinned-store credential')
  })

  test('linux store option: keyutils round-trips', (t) => {
    const entry = new Entry(testLinuxKeyutilsService, testUser, { linux: { store: 'keyutils' } })
    t.notThrows(() => entry.setPassword(testPassword))
    t.is(entry.getPassword(), testPassword)
    t.true(entry.deleteCredential(), 'clean up the pinned-store credential')
  })

  test('linux store option: AsyncEntry secret-service round-trips', async (t) => {
    const entry = new AsyncEntry(testLinuxSecretServiceService, testUser, {
      linux: { store: 'secret-service' },
    })
    await t.notThrowsAsync(() => entry.setPassword(testPassword))
    t.is(await entry.getPassword(), testPassword)
    t.true(await entry.deleteCredential(), 'clean up the pinned-store credential')
  })

  test('linux store option: keyutils targets stay isolated', (t) => {
    // The kernel keyring has no `target` modifier; withTarget maps the target
    // to the key `description` so distinct targets must address distinct
    // kernel credentials even when service and username are identical.
    const first = Entry.withTarget('keyring-node-test-keyutils-t1', testLinuxKeyutilsService, testUser, {
      linux: { store: 'keyutils' },
    })
    const second = Entry.withTarget('keyring-node-test-keyutils-t2', testLinuxKeyutilsService, testUser, {
      linux: { store: 'keyutils' },
    })
    t.notThrows(() => first.setPassword(testPassword))
    t.is(first.getPassword(), testPassword)
    t.is(second.getPassword(), null, 'a different target must not see the credential')
    t.false(second.deleteCredential(), 'deleting another target must not remove the credential')
    t.true(first.deleteCredential(), 'clean up the pinned-store credential')
  })
} else {
  test('linux store option is accepted and ignored on non-Linux platforms', (t) => {
    const entry = new Entry(testService, testUser, { linux: { store: 'keyutils' } })
    t.notThrows(() => entry.setPassword(testPassword))
    t.is(entry.getPassword(), testPassword)
    t.notThrows(() => entry.deleteCredential())
  })

  test('linux store option is accepted and ignored on non-Linux platforms async', async (t) => {
    const entry = new AsyncEntry(testService, testUser, { linux: { store: 'secret-service' } })
    await t.notThrowsAsync(() => entry.setPassword(testPassword))
    t.is(await entry.getPassword(), testPassword)
    await t.notThrowsAsync(() => entry.deleteCredential())
  })
}

test('linux store option: unknown store values are rejected', (t) => {
  // napi-rs validates the string_enum at the JS boundary, before any
  // platform-specific logic runs.
  t.throws(
    () => new Entry(testService, testUser, { linux: { store: 'made-up-store' } } as any),
    { message: /does not match any variant of enum/ },
    'throws on a store value outside the LinuxStore union',
  )
})

test('linux store option: store value is constrained to the LinuxStore union at compile time', (t) => {
  if (false) {
    // @ts-expect-error 'made-up-store' is not a member of the LinuxStore union
    new Entry(testService, testUser, { linux: { store: 'made-up-store' } })
  }
  t.pass()
})
