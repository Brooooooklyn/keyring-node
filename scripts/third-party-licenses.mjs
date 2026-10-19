// Generates npm/<platform>/LICENSE.third-party.md for every napi target from the
// committed Cargo.lock: the license texts of all Rust crates compiled into that
// platform's .node binary, plus the vendored libdbus C sources on Linux.
//
//   node scripts/third-party-licenses.mjs           regenerate the files
//   node scripts/third-party-licenses.mjs --check   fail if any file is stale
//
// Requires cargo-about (version pinned in CI.yml) and the crate sources, e.g.
// via `cargo fetch --locked`. It runs offline, so the output only depends on
// Cargo.lock.

import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { parseTriple } from '@napi-rs/cli'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const check = process.argv.includes('--check')
const FILE_NAME = 'LICENSE.third-party.md'

const packageJson = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const { binaryName, targets } = packageJson.napi

const run = (command, args) =>
  execFileSync(command, args, {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'inherit'],
  })

const rootCrateName = JSON.parse(run('cargo', ['metadata', '--frozen', '--no-deps', '--format-version', '1']))
  .packages[0].name

const normalize = (text) =>
  text
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map((line) => line.trimEnd())
    .join('\n')
    .replace(/^\n+|\n+$/g, '')

const codeBlock = (text) => {
  const longestRun = Math.max(2, ...(text.match(/`+/g) ?? []).map((backticks) => backticks.length))
  const fence = '`'.repeat(longestRun + 1)
  return `${fence}text\n${text}\n${fence}`
}

const byNameVersion = (a, b) =>
  a.name.localeCompare(b.name) || a.version.localeCompare(b.version, 'en', { numeric: true })

function activatedFeatures(triple, crate) {
  const output = run('cargo', [
    'tree',
    '--frozen',
    '--target',
    triple,
    '--edges',
    'normal',
    '--invert',
    crate,
    '--depth',
    '0',
    '--format',
    '{p}|{f}',
  ]).trim()
  return new Set(output ? output.split('|')[1].split(',').filter(Boolean) : [])
}

// With its `vendored` feature, libdbus-sys compiles the libdbus C library from
// the sources it vendors and links it statically. The crate's MIT/Apache-2.0
// metadata does not cover those sources, so cargo-about cannot report them.
function vendoredLibdbusSection(triple, crates) {
  const libdbusSys = crates.find((crate) => crate.name === 'libdbus-sys')
  if (!libdbusSys || !activatedFeatures(triple, 'libdbus-sys').has('vendored')) return ''
  const crateDir = dirname(libdbusSys.manifest_path)
  const dbusDir = join(crateDir, 'vendor', 'dbus')
  const configure = readFileSync(join(dbusDir, 'configure.ac'), 'utf8')
  const dbusVersion = ['major', 'minor', 'micro']
    .map((part) => configure.match(new RegExp(`m4_define\\(\\[dbus_${part}_version\\], \\[(\\d+)\\]\\)`))[1])
    .join('.')
  // Only the files listed in the crate's vendored build are compiled in.
  const sources = [
    ...readFileSync(join(crateDir, 'build_vendored.rs'), 'utf8').matchAll(/"\.\/(vendor\/dbus\/[^"]+\.c)"/g),
  ].map((match) => match[1])
  const copyrights = new Set()
  for (const source of sources) {
    for (const line of readFileSync(join(crateDir, source), 'utf8').split('\n').slice(0, 40)) {
      const copyright = line.match(/Copyright\b.*\d{4}.*/i)
      if (copyright) copyrights.add(normalize(copyright[0]))
    }
  }
  return [
    `## libdbus ${dbusVersion} (vendored C library)`,
    '',
    `On this target \`libdbus-sys ${libdbusSys.version}\` compiles the libdbus C library from the sources it`,
    'vendors and links it statically into the binary. Those sources are licensed under',
    '`AFL-2.1 OR GPL-2.0-or-later`, not under the crate license listed above.',
    '',
    `Copyright notices of the ${sources.length} compiled source files:`,
    '',
    codeBlock([...copyrights].sort().join('\n')),
    '',
    'License (`vendor/dbus/COPYING`):',
    '',
    codeBlock(normalize(readFileSync(join(dbusDir, 'COPYING'), 'utf8'))),
  ].join('\n')
}

function render(triple, platformArchABI) {
  const about = JSON.parse(
    run('cargo', ['about', 'generate', '--format', 'json', '--frozen', '--fail', '--target', triple]),
  )
  const isThirdParty = (crate) => crate.name !== rootCrateName
  const crates = about.crates
    .map(({ package: crate }) => crate)
    .filter(isThirdParty)
    .sort(byNameVersion)
  const licenses = about.licenses
    .map((license) => ({
      id: license.id,
      name: license.name,
      text: normalize(license.text),
      usedBy: license.used_by
        .map(({ crate }) => crate)
        .filter(isThirdParty)
        .sort(byNameVersion),
    }))
    .filter((license) => license.usedBy.length > 0)
    .sort((a, b) => a.id.localeCompare(b.id) || byNameVersion(a.usedBy[0], b.usedBy[0]) || a.text.localeCompare(b.text))

  const lines = [
    '# Third-party licenses',
    '',
    `\`${binaryName}.${platformArchABI}.node\` (\`${triple}\`) is built from the Rust crates below, at the versions`,
    'pinned in [`Cargo.lock`](https://github.com/Brooooooklyn/keyring-node/blob/main/Cargo.lock). The list includes',
    'procedural-macro crates that only run at compile time. The binary embeds the same list, readable with',
    '`rust-audit-info` or `cargo audit bin`.',
    '',
    '<!-- Generated by scripts/third-party-licenses.mjs. Do not edit; run `yarn licenses` instead. -->',
    '',
    '## Crates',
    '',
    '| Crate | Version | License |',
    '| --- | --- | --- |',
    ...crates.map((crate) => `| ${crate.name} | ${crate.version} | ${crate.license ?? crate.license_file} |`),
    '',
    '## License texts',
    '',
    'Where a crate offers a choice of licenses, the text below is the license elected for it.',
    '',
  ]
  for (const license of licenses) {
    lines.push(
      `### ${license.name} (\`${license.id}\`)`,
      '',
      `Used by: ${license.usedBy.map((crate) => `\`${crate.name} ${crate.version}\``).join(', ')}`,
      '',
      codeBlock(license.text),
      '',
    )
  }
  lines.push(vendoredLibdbusSection(triple, crates))
  return `${lines.join('\n').trimEnd()}\n`
}

const stale = []
for (const triple of targets) {
  const { platformArchABI } = parseTriple(triple)
  const relativePath = `npm/${platformArchABI}/${FILE_NAME}`
  const file = join(root, relativePath)
  const content = render(triple, platformArchABI)
  if (check) {
    if (!existsSync(file) || readFileSync(file, 'utf8') !== content) stale.push(relativePath)
  } else {
    mkdirSync(dirname(file), { recursive: true })
    writeFileSync(file, content)
    console.info(`wrote ${relativePath}`)
  }
}

if (stale.length) {
  console.error(
    `Stale third-party license files, run \`yarn licenses\` and commit the result:\n  ${stale.join('\n  ')}`,
  )
  process.exit(1)
}
