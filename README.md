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
