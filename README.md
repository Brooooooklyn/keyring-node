# `@napi-rs/keyring`

![https://github.com/Brooooooklyn/keyring-node/actions](https://github.com/Brooooooklyn/keyring-node/workflows/CI/badge.svg)
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

# Error codes

Errors from the credential store carry a machine-readable `code` property: the name of the
[`keyring_core::Error`](https://docs.rs/keyring-core/latest/keyring_core/error/enum.Error.html) variant, or
`GenericFailure` for anything else.

| `code`                | Meaning                                                                                                                      |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `NoStorageAccess`     | The store is locked, access was denied, or an unlock prompt was dismissed.                                                   |
| `PlatformFailure`     | The platform store returned an error (for example no D-Bus session).                                                         |
| `NoEntry`             | Not thrown by `get*`/`delete*` (they return `null`/`false`). `set*` can throw it on keyutils if the session keyring expired. |
| `Ambiguous`           | More than one platform credential matches the entry.                                                                         |
| `BadEncoding`         | `getPassword` found a secret that is not valid text. `getSecret` returns the raw bytes.                                      |
| `BadDataFormat`       | A stored secret blob is not in the format the store expects.                                                                 |
| `BadStoreFormat`      | The store's own persisted data is malformed.                                                                                 |
| `TooLong`             | A value is longer than the platform allows.                                                                                  |
| `Invalid`             | The store rejected a value (for example an empty service name on macOS).                                                     |
| `NoDefaultStore`      | No default store is set. Not expected from this package.                                                                     |
| `NotSupportedByStore` | The store does not support the operation.                                                                                    |
| `GenericFailure`      | The error did not come from `keyring_core`, for example a `findCredentials` failure.                                         |

Errors raised by napi-rs itself keep their own codes. A bad argument throws `InvalidArg`, `StringExpected`, and so on.
When an `AbortSignal` cancels a call, the promise rejects with an `AbortError` whose `code` is `Cancelled`. A call
that has already started is not cancelled.

The code strings will not be renamed. Which code a platform condition maps to follows the keyring-core store crates.
`error.message` is human-readable text and may change, so branch on `code`, not on the message.

```js
import { AsyncEntry } from '@napi-rs/keyring'

const entry = new AsyncEntry('my_service', 'my_name')
try {
  const password = await entry.getPassword()
  // use password
} catch (err) {
  if (err.code === 'NoStorageAccess') {
    console.error('Unlock your keychain and try again')
  } else {
    throw err
  }
}
```

# Bundled Rust dependencies

The prebuilt `.node` binaries are built with `--locked` from the committed [`Cargo.lock`](./Cargo.lock), and with
[`cargo auditable`](https://github.com/rust-secure-code/cargo-auditable), which embeds the exact list of Rust crates
compiled into each binary. Recover it for license compliance or vulnerability scanning with:

```sh
cargo install rust-audit-info
rust-audit-info node_modules/@napi-rs/keyring-darwin-arm64/keyring.darwin-arm64.node

# or scan for known vulnerabilities
cargo audit bin node_modules/@napi-rs/keyring-darwin-arm64/keyring.darwin-arm64.node
```

[syft](https://github.com/anchore/syft), [trivy](https://github.com/aquasecurity/trivy) and
[grype](https://github.com/anchore/grype) read the same data.

Each platform package also ships a `LICENSE.third-party.md` with the license texts of those crates, generated by
[`cargo-about`](https://github.com/EmbarkStudios/cargo-about). After changing `Cargo.lock`, regenerate them with
`yarn licenses` (needs `cargo install --locked cargo-about --features cli`); CI fails while they are stale.

> **Note:** the Linux binaries statically link `libdbus` (built from the sources vendored by
> [`libdbus-sys`](https://crates.io/crates/libdbus-sys)), which is licensed under `AFL-2.1 OR GPL-2.0-or-later`
> rather than the crate's own `MIT OR Apache-2.0`. The Linux `LICENSE.third-party.md` files include its license and
> copyright notices.
