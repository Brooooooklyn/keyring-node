import test from 'ava'

import * as keytar from '../keytar-compat.js'

// Ported from node-keytar's own test suite (MIT):
// https://github.com/atom/node-keytar/blob/master/spec/keytar-spec.js
// Differences from the original:
// - mocha/chai is translated to AVA.
// - The error-handling cases assert that the call throws with keytar's exact
//   message; the original's bare try/catch would also pass when nothing threw.
// - Service names are namespaced so a developer's real keychain entries and
//   the other test file (which runs in a parallel AVA worker) are never hit.

const service = 'keyring-node-keytar-spec tests'
const service2 = 'keyring-node-keytar-spec other tests'
const account = 'buster'
const password = 'secret'
const account2 = 'buster2'
const password2 = 'secret2'

const object = {
  toString() {
    throw new Error('Whoops! Time to seg fault')
  },
} as any

const cleanup = async () => {
  await keytar.deletePassword(service, account)
  await keytar.deletePassword(service, account2)
  await keytar.deletePassword(service2, account)
}

test.beforeEach(cleanup)
test.afterEach.always(cleanup)

const byAccount = (a: { account: string }, b: { account: string }) => a.account.localeCompare(b.account)

test('setPassword/getPassword: sets and yields the password for the service and account', async (t) => {
  await keytar.setPassword(service, account, password)
  t.is(await keytar.getPassword(service, account), password)
  await keytar.setPassword(service, account, password2)
  t.is(await keytar.getPassword(service, account), password2)
})

test('getPassword: yields null when the password was not found', async (t) => {
  t.is(await keytar.getPassword(service, account), null)
})

test('setPassword: error handling', (t) => {
  t.throws(() => keytar.setPassword(object, account, password), { message: "Parameter 'service' must be a string" })
  t.throws(() => keytar.setPassword(service, object, password), { message: "Parameter 'username' must be a string" })
  t.throws(() => keytar.setPassword(service, account, object), { message: "Parameter 'password' must be a string" })
})

test('getPassword: error handling', (t) => {
  t.throws(() => keytar.getPassword(object, account), { message: "Parameter 'service' must be a string" })
  t.throws(() => keytar.getPassword(service, object), { message: "Parameter 'username' must be a string" })
})

test('setPassword/getPassword: handles unicode strings everywhere', async (t) => {
  const unicodeService = 'se®viÇe'
  const unicodeAccount = 'shiƑ†ke¥'
  const unicodePassword = 'påsswØ®∂'
  await keytar.setPassword(unicodeService, unicodeAccount, unicodePassword)
  t.is(await keytar.getPassword(unicodeService, unicodeAccount), unicodePassword)
  t.true(await keytar.deletePassword(unicodeService, unicodeAccount))
})

test('deletePassword: yields true when the password was deleted', async (t) => {
  await keytar.setPassword(service, account, password)
  t.is(await keytar.deletePassword(service, account), true)
})

test("deletePassword: yields false when the password didn't exist", async (t) => {
  t.is(await keytar.deletePassword(service, account), false)
})

test('deletePassword: error handling', (t) => {
  t.throws(() => keytar.deletePassword(object, account), { message: "Parameter 'service' must be a string" })
  t.throws(() => keytar.deletePassword(service, object), { message: "Parameter 'username' must be a string" })
})

test('findPassword: yields a password for the service', async (t) => {
  await keytar.setPassword(service, account, password)
  await keytar.setPassword(service, account2, password2)
  t.true([password, password2].includes((await keytar.findPassword(service))!))
})

test('findPassword: yields null when no password can be found', async (t) => {
  t.is(await keytar.findPassword(service), null)
})

test('findPassword: error handling', (t) => {
  t.throws(() => keytar.findPassword(object), { message: "Parameter 'service' must be a string" })
})

test('findCredentials: yields an array of the credentials', async (t) => {
  await keytar.setPassword(service, account, password)
  await keytar.setPassword(service, account2, password2)
  await keytar.setPassword(service2, account, password)

  const found = await keytar.findCredentials(service)
  t.deepEqual(found.sort(byAccount), [
    { account, password },
    { account: account2, password: password2 },
  ])
})

test('findCredentials: returns an empty array when no credentials are found', async (t) => {
  t.deepEqual(await keytar.findCredentials(service), [])
})

test('findCredentials: error handling', (t) => {
  t.throws(() => keytar.findCredentials(object), { message: "Parameter 'service' must be a string" })
})

test('findCredentials: handles unicode strings everywhere', async (t) => {
  const unicodeService = 'se®viÇe find'
  const unicodeAccount = 'shiƑ†ke¥'
  const unicodePassword = 'påsswØ®∂'
  await keytar.setPassword(unicodeService, unicodeAccount, unicodePassword)
  await keytar.setPassword(unicodeService, account2, password2)

  const found = await keytar.findCredentials(unicodeService)
  const expected = [
    { account: unicodeAccount, password: unicodePassword },
    { account: account2, password: password2 },
  ]
  t.deepEqual(found.sort(byAccount), expected.sort(byAccount))

  t.true(await keytar.deletePassword(unicodeService, unicodeAccount))
  t.true(await keytar.deletePassword(unicodeService, account2))
})
