const { keytarGetPassword, keytarSetPassword, keytarDeletePassword, keytarFindCredentials } = require('./index.js')

// Drop-in replacement for node-keytar. Credentials are read and written in
// keytar's exact on-store format on every platform, so switching an existing
// application from keytar to this module requires no data migration: old
// credentials stay readable, and credentials written here stay readable by
// keytar.

// node-keytar's native layer validated its arguments with these exact
// messages (and its own test suite asserts them), so they are replicated
// here ahead of the native call.
function checkString(value, name) {
  if (typeof value !== 'string') {
    throw new TypeError(`Parameter '${name}' must be a string`)
  }
}

module.exports.getPassword = function getPassword(service, account) {
  checkString(service, 'service')
  checkString(account, 'username')
  return keytarGetPassword(service, account)
}

module.exports.setPassword = function setPassword(service, account, password) {
  checkString(service, 'service')
  checkString(account, 'username')
  checkString(password, 'password')
  return keytarSetPassword(service, account, password)
}

module.exports.deletePassword = function deletePassword(service, account) {
  checkString(service, 'service')
  checkString(account, 'username')
  return keytarDeletePassword(service, account)
}

// Deliberately not `async`: node-keytar validates arguments synchronously, so
// a bad `service` must throw rather than return a rejected promise.
module.exports.findPassword = function findPassword(service) {
  checkString(service, 'service')
  return keytarFindCredentials(service).then((credentials) => (credentials.length ? credentials[0].password : null))
}

module.exports.findCredentials = function findCredentials(service) {
  checkString(service, 'service')
  return keytarFindCredentials(service)
}
