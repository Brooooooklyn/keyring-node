import os from 'node:os'

import test from 'ava'

import { Entry, findCredentials, findCredentialsAsync, AsyncEntry } from '../index'
import * as keytarCompat from '../keytar-compat.js'
import * as keytarShim from '../keytar.js'

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
  t.true(Array.isArray(retrievedSecret))
  t.deepEqual(new Uint8Array(retrievedSecret!), testSecret)
  await t.notThrowsAsync(() => entry.deleteCredential())
})

test('Should handle binary data correctly with setSecret/getSecret', (t) => {
  const entry = new Entry(testService, testUser)
  // Test with binary data that includes null bytes and high values
  const binaryData = new Uint8Array([0x00, 0x01, 0x7f, 0x80, 0xff, 0xde, 0xad, 0xbe, 0xef])
  t.notThrows(() => entry.setSecret(binaryData))
  const retrievedSecret = entry.getSecret()
  t.truthy(retrievedSecret)
  t.deepEqual(new Uint8Array(retrievedSecret!), binaryData)
  t.notThrows(() => entry.deleteCredential())
})

test('Should handle binary data correctly with setSecret/getSecret async', async (t) => {
  const entry = new AsyncEntry(testService, testUser)
  // Test with binary data that includes null bytes and high values
  const binaryData = new Uint8Array([0x00, 0x01, 0x7f, 0x80, 0xff, 0xde, 0xad, 0xbe, 0xef])
  await t.notThrowsAsync(() => entry.setSecret(binaryData))
  const retrievedSecret = await entry.getSecret()
  t.truthy(retrievedSecret)
  t.true(Array.isArray(retrievedSecret))
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
  t.is(await entry.getSecret(), null)
  t.is(await entry.getPassword(), null)
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

const testMacosKeychainService = 'keyring-node-test-service-macos-keychain'
const testMacosProtectedService = 'keyring-node-test-service-macos-protected'

if (platform === 'darwin') {
  test('macos store option: keychain round-trips', (t) => {
    const entry = new Entry(testMacosKeychainService, testUser, { macos: { store: 'keychain' } })
    t.notThrows(() => entry.setPassword(testPassword))
    t.is(entry.getPassword(), testPassword)
    t.true(entry.deleteCredential(), 'clean up the pinned-store credential')
  })

  test('macos store option: AsyncEntry keychain round-trips', async (t) => {
    const entry = new AsyncEntry(testMacosKeychainService, testUser, { macos: { store: 'keychain' } })
    await t.notThrowsAsync(() => entry.setPassword(testPassword))
    t.is(await entry.getPassword(), testPassword)
    t.true(await entry.deleteCredential(), 'clean up the pinned-store credential')
  })

  test('macos store option: protected round-trips when the process is entitled', (t) => {
    const entry = new Entry(testMacosProtectedService, testUser, { macos: { store: 'protected' } })
    try {
      entry.setPassword(testPassword)
    } catch (err) {
      // The data-protection keychain requires the caller to be code-signed
      // with an application identifier; plain node processes are not, and
      // get `errSecMissingEntitlement` from the OS instead.
      t.regex((err as Error).message, /entitlement/i, 'unentitled processes get the entitlement error')
      return
    }
    t.is(entry.getPassword(), testPassword)
    t.true(entry.deleteCredential(), 'clean up the pinned-store credential')
  })

  test('macos store option: AsyncEntry protected round-trips when the process is entitled', async (t) => {
    const entry = new AsyncEntry(testMacosProtectedService, testUser, { macos: { store: 'protected' } })
    try {
      await entry.setPassword(testPassword)
    } catch (err) {
      // The data-protection keychain requires the caller to be code-signed
      // with an application identifier; plain node processes are not, and
      // get `errSecMissingEntitlement` from the OS instead.
      t.regex((err as Error).message, /entitlement/i, 'unentitled processes get the entitlement error')
      return
    }
    t.is(await entry.getPassword(), testPassword)
    t.true(await entry.deleteCredential(), 'clean up the pinned-store credential')
  })

  test('macos store option: protected store rejects target', (t) => {
    // target maps to the file-based keychain's `keychain` modifier (a legacy
    // keychain file name), which has no meaning in the protected store, so it
    // is rejected rather than silently ignored.
    t.throws(
      () => Entry.withTarget(testTarget!, testMacosProtectedService, testUser, { macos: { store: 'protected' } }),
      { message: /target is not supported/ },
    )
    t.throws(
      () => AsyncEntry.withTarget(testTarget!, testMacosProtectedService, testUser, { macos: { store: 'protected' } }),
      { message: /target is not supported/ },
    )
  })
} else {
  test('macos store option is accepted and ignored on non-macOS platforms', (t) => {
    const entry = new Entry(testService, testUser, { macos: { store: 'protected' } })
    t.notThrows(() => entry.setPassword(testPassword))
    t.is(entry.getPassword(), testPassword)
    t.notThrows(() => entry.deleteCredential())
  })

  test('macos store option is accepted and ignored on non-macOS platforms async', async (t) => {
    const entry = new AsyncEntry(testService, testUser, { macos: { store: 'keychain' } })
    await t.notThrowsAsync(() => entry.setPassword(testPassword))
    t.is(await entry.getPassword(), testPassword)
    await t.notThrowsAsync(() => entry.deleteCredential())
  })
}

test('macos store option: unknown store values are rejected', (t) => {
  // napi-rs validates the string_enum at the JS boundary, before any
  // platform-specific logic runs.
  t.throws(
    () => new Entry(testService, testUser, { macos: { store: 'made-up-store' } } as any),
    { message: /does not match any variant of enum/ },
    'throws on a store value outside the MacosStore union',
  )
})

test('macos store option: store value is constrained to the MacosStore union at compile time', (t) => {
  if (false) {
    // @ts-expect-error 'made-up-store' is not a member of the MacosStore union
    new Entry(testService, testUser, { macos: { store: 'made-up-store' } })
  }
  t.pass()
})

const testKeytarService = 'keyring-node-test-service-keytar'
const testKeytarUser = 'keytar-user'

test('keytar compat: setPassword/getPassword round-trips', async (t) => {
  await t.notThrowsAsync(() => keytarCompat.setPassword(testKeytarService, testKeytarUser, testPassword))
  t.is(await keytarCompat.getPassword(testKeytarService, testKeytarUser), testPassword)
  t.true(await keytarCompat.deletePassword(testKeytarService, testKeytarUser), 'clean up the keytar credential')
})

test('keytar compat: getPassword returns null when missing', async (t) => {
  t.is(await keytarCompat.getPassword(testKeytarService, 'keytar-missing-user'), null)
})

test('keytar compat: deletePassword reports whether a credential was removed', async (t) => {
  await keytarCompat.setPassword(testKeytarService, testKeytarUser, testPassword)
  t.true(await keytarCompat.deletePassword(testKeytarService, testKeytarUser))
  t.false(await keytarCompat.deletePassword(testKeytarService, testKeytarUser))
})

test('keytar compat: findCredentials and findPassword see keytar writes', async (t) => {
  await keytarCompat.setPassword(testKeytarService, testKeytarUser, testPassword)
  const credentials = await keytarCompat.findCredentials(testKeytarService)
  t.deepEqual(credentials, [{ account: testKeytarUser, password: testPassword }])
  t.is(await keytarCompat.findPassword(testKeytarService), testPassword)
  t.true(await keytarCompat.deletePassword(testKeytarService, testKeytarUser), 'clean up the keytar credential')
})

test('keytar compat: setPassword overwrites an existing credential', async (t) => {
  await keytarCompat.setPassword(testKeytarService, testKeytarUser, 'old-password')
  await keytarCompat.setPassword(testKeytarService, testKeytarUser, testPassword)
  t.is(await keytarCompat.getPassword(testKeytarService, testKeytarUser), testPassword)
  const credentials = await keytarCompat.findCredentials(testKeytarService)
  t.is(credentials.length, 1, 'overwriting must not create a second credential')
  t.true(await keytarCompat.deletePassword(testKeytarService, testKeytarUser), 'clean up the keytar credential')
})

if (platform === 'darwin') {
  // On macOS keytar and the default keychain store share the same storage
  // identity, so the two APIs must see each other's credentials.
  test('keytar compat: interoperates with Entry on macOS', async (t) => {
    await keytarCompat.setPassword(testKeytarService, testKeytarUser, testPassword)
    t.is(new Entry(testKeytarService, testKeytarUser).getPassword(), testPassword)
    const entry = new Entry(testKeytarService, 'keytar-entry-user')
    entry.setPassword(testPassword)
    t.is(await keytarCompat.getPassword(testKeytarService, 'keytar-entry-user'), testPassword)
    t.true(await keytarCompat.deletePassword(testKeytarService, testKeytarUser), 'clean up the keytar credential')
    t.true(entry.deleteCredential(), 'clean up the entry credential')
  })

  // Secrets are arbitrary bytes, so enumerating them must not assume UTF-8.
  test('findCredentials survives a non-UTF-8 secret on macOS', async (t) => {
    const binaryService = 'keyring-node-test-service-binary-find'
    const entry = new Entry(binaryService, testUser)
    entry.setSecret(new Uint8Array([0x80, 0xff, 0x41, 0x42]))
    const credentials = findCredentials(binaryService)
    t.is(credentials.length, 1)
    t.is(credentials[0].account, testUser)
    const keytarCredentials = await keytarCompat.findCredentials(binaryService)
    t.is(keytarCredentials.length, 1)
    t.true(entry.deleteCredential(), 'clean up the binary credential')
  })
}

test("keytar compat: validates parameters with keytar's exact error messages", (t) => {
  // node-keytar's own test suite asserts these messages verbatim; the compat
  // layer passes that suite, so the messages are part of the contract.
  const bad = {} as any
  t.throws(() => keytarCompat.getPassword(bad, 'u'), { message: "Parameter 'service' must be a string" })
  t.throws(() => keytarCompat.getPassword('s', bad), { message: "Parameter 'username' must be a string" })
  t.throws(() => keytarCompat.setPassword('s', 'u', bad), { message: "Parameter 'password' must be a string" })
  t.throws(() => keytarCompat.deletePassword(bad, 'u'), { message: "Parameter 'service' must be a string" })
  t.throws(() => keytarCompat.findPassword(bad), { message: "Parameter 'service' must be a string" })
  t.throws(() => keytarCompat.findCredentials(bad), { message: "Parameter 'service' must be a string" })
})

const testKeytarShimService = 'keyring-node-test-service-keytar-shim'

test('keytar shim: round-trips through Entry storage on every platform', async (t) => {
  // The original keytar.js keeps keytar's API shape but stores through
  // AsyncEntry, so it must interoperate with Entry everywhere, exactly as
  // in 2.1.x.
  await t.notThrowsAsync(() => keytarShim.setPassword(testKeytarShimService, testKeytarUser, testPassword))
  t.is(await keytarShim.getPassword(testKeytarShimService, testKeytarUser), testPassword)
  t.is(new Entry(testKeytarShimService, testKeytarUser).getPassword(), testPassword)
  t.true(await keytarShim.deletePassword(testKeytarShimService, testKeytarUser))
  t.is(await keytarShim.getPassword(testKeytarShimService, testKeytarUser), null)
})
