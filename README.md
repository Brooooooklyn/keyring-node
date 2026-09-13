# `@napi-rs/keyring`

![https://github.com/Brooooooklyn/keyring-node/actions](https://github.com/Brooooooklyn/keyring-node/workflows/CI/badge.svg)
[![install size](https://packagephobia.com/badge?p=@napi-rs/keyring)](https://packagephobia.com/result?p=@napi-rs/keyring)
[![Downloads](https://img.shields.io/npm/dm/@napi-rs/keyring.svg?sanitize=true)](https://npmcharts.com/compare/@napi-rs/keyring?minimal=true)

> https://github.com/hwchen/keyring-rs Node.js binding via https://napi.rs

# Usage

```js
import { Entry } from '@napi-rs/keyring'

const entry = new Entry('my_service', 'my_name')
entry.setPassword('topS3cr3tP4$$w0rd')
const password = entry.getPassword()
console.log('My password is ', password)
entry.deletePassword()
```

# Linux backend selection

On Linux, `Entry` and `AsyncEntry` pick a credential store automatically: the
[Secret Service](https://crates.io/crates/dbus-secret-service-keyring-store) (gnome-keyring, KWallet,
keepassxc, ...) is tried first, and the binding silently falls back to the
[kernel keyutils keyring](https://crates.io/crates/linux-keyutils-keyring-store) when no Secret Service
is available.

You can pin an entry to one specific store by passing the options bag as the last argument (the
option is accepted on every platform but only meaningful on Linux):

```js
new Entry('my_service', 'my_name', { linux: { store: 'secret-service' } }) // require Secret Service
new Entry('my_service', 'my_name', { linux: { store: 'keyutils' } }) // require the kernel keyring
Entry.withTarget('target', 'my_service', 'my_name', { linux: { store: 'keyutils' } })
```

When a store is required, the constructor throws if that store is unavailable — there is no silent
fallback. When `withTarget` is combined with the keyutils store, the target is used as the kernel key
description, so distinct targets keep distinct credentials.

> **Note:** the keyutils store keeps credentials in kernel memory: per the
> [linux-keyutils-keyring-store](https://crates.io/crates/linux-keyutils-keyring-store) docs, the key
> management facility "is completely in-memory and will not persist across reboots". Prefer
> `secret-service` for credentials that must survive a restart.
