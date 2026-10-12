'use strict';

const { spawnSync } = require('node:child_process');

// Runtime credentials stay in this action and its trusted Python child only.
const allowed = new Set([
  'PATH', 'SYSTEMROOT', 'WINDIR', 'SYSTEMDRIVE', 'COMSPEC', 'PATHEXT',
  'HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'PROGRAMDATA',
  'PROGRAMFILES', 'PROGRAMFILES(X86)', 'PROGRAMW6432',
  'GITHUB_WORKSPACE', 'GITHUB_OUTPUT', 'GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME',
  'GITHUB_REF', 'BUILD_DEFAULT_BRANCH', 'RUNNER_OS', 'RUNNER_ARCH',
  'ACTIONS_CACHE_SERVICE_V2', 'ACTIONS_RUNTIME_TOKEN', 'ACTIONS_RESULTS_URL'
]);
const env = {};
for (const [name, value] of Object.entries(process.env)) {
  if (allowed.has(name.toUpperCase())) {
    env[name] = value;
  }
}
env.CACHE_PATH = process.env.INPUT_PATH;
env.CACHE_KEY = process.env.INPUT_KEY;
env.CACHE_RESTORE_KEYS = process.env['INPUT_RESTORE-KEYS'] || '';
try {
  const result = spawnSync('python', ['-B', 'control/scripts/cache_restore.py'], {
    cwd: process.env.GITHUB_WORKSPACE,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 90 * 60 * 1000,
    maxBuffer: 1024 * 1024,
    windowsHide: true
  });
  if (result.error || result.status !== 0) {
    throw new Error('restore failed');
  }
} catch (_) {
  // Child errors may contain transport credentials. Do not replay them.
  process.stderr.write('Secure cache restore failed\n');
  process.exitCode = 1;
}
