// Starts the actual Rust UI backend with isolated SQLite files and a local DNS fixture.
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../../', import.meta.url));
export async function server() {
  const directory = await mkdtemp(join(tmpdir(), 'dns-deny-web-'));
  const process = spawn(join(repo, 'target/debug/examples/web_fixture'), [], {
    cwd: repo, env: { ...globalThis.process.env, DNS_UI_TEST_DIR: directory }, stdio: ['ignore', 'pipe', 'pipe']
  });
  let output = '';
  let errors = '';
  process.stderr.on('data', data => { errors += data; });
  try {
    const base = await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error(`UI fixture did not start: ${errors}`)), 15000);
      process.on('error', reject);
      process.on('exit', code => { clearTimeout(timeout); reject(new Error(`UI fixture exited (${code}): ${errors}`)); });
      process.stdout.on('data', data => {
        output += data;
        const url = output.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
        if (url) { clearTimeout(timeout); resolve(url); }
      });
    });
    return { base, get logs() { return errors; },
      async api(path, options = {}) {
        return fetch(`${base}/api/v1${path}`, { ...options, headers: { Authorization: 'Bearer test-secret-key', 'Content-Type': 'application/json', ...options.headers } });
      },
      async close() {
        if (process.exitCode === null) {
          const done = new Promise(resolve => process.once('exit', resolve));
          process.kill('SIGTERM');
          await done;
        }
        await rm(directory, { recursive: true, force: true, maxRetries: 5 });
      }
    };
  } catch (error) {
    process.kill('SIGTERM');
    await rm(directory, { recursive: true, force: true, maxRetries: 5 });
    throw error;
  }
}
