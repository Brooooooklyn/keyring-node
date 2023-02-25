import test from 'ava'

import { Entry } from '../index'

test('Should create and get password back', (t) => {
  const password = 'napi.rs'
  const entry = new Entry('gnome-keyring', 'napi')
  t.notThrows(() => entry.setPassword(password))
  t.is(entry.getPassword(), password)
  t.notThrows(() => entry.deletePassword())
})
