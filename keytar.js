const { AsyncEntry, findCredentialsAsync } = require('./index.js')

module.exports.getPassword = function getPassword(service, account) {
  const entry = new AsyncEntry(service, account)
  return entry.getPassword()
}

module.exports.setPassword = function setPassword(service, account, password) {
  const entry = new AsyncEntry(service, account)
  return entry.setPassword(password)
}

module.exports.deletePassword = function deletePassword(service, account) {
  const entry = new AsyncEntry(service, account)
  return entry.deletePassword()
}

module.exports.findPassword = async function findPassword(service) {
  const credentials = await findCredentialsAsync(service)
  if (!credentials.length) {
    return null
  }
  return credentials[0].password
}

module.exports.findCredentials = findCredentialsAsync
