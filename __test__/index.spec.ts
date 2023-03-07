import test from 'ava'

import { Entry, findCredentials } from '../index'

test('Should create and get password back', (t) => {
  const password = 'napi.rs'
  const service = 'gnome-keyring'
  const entry = new Entry(service, 'napi')
  t.notThrows(() => entry.setPassword(password))
  t.is(entry.getPassword(), password)
  const [{ password: pass, user }] = findCredentials(service)
  t.is(pass, password)
  t.is(user, 'napi')
  t.notThrows(() => entry.deletePassword())
})
