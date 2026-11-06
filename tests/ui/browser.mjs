import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

// Minimal Chrome DevTools transport over child-process pipes; no debug port.
export async function browser() {
  const executable = process.env.CHROME_BIN || [
    '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  ].find(existsSync);
  assert.ok(executable, 'Install Chrome/Chromium or set CHROME_BIN');
  const profile = await mkdtemp(join(tmpdir(), 'dns-deny-ui-'));
  const chrome = spawn(executable, [
    '--headless', '--no-sandbox', '--disable-gpu', '--no-first-run',
    '--disable-background-networking', '--disable-component-update',
    '--disable-extensions', '--remote-debugging-pipe', `--user-data-dir=${profile}`
  ], { stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'] });
  let sequence = 0;
  let buffer = '';
  const pending = new Map();
  const errors = [];
  let stderr = '';
  chrome.stderr.on('data', data => { stderr += data; });
  chrome.on('error', error => errors.push(String(error)));
  chrome.stdio[4].on('data', data => {
    buffer += data.toString();
    let end;
    while ((end = buffer.indexOf('\0')) >= 0) {
      const message = JSON.parse(buffer.slice(0, end));
      buffer = buffer.slice(end + 1);
      if (message.id) {
        const request = pending.get(message.id);
        if (!request) continue;
        pending.delete(message.id);
        clearTimeout(request.timer);
        if (message.error) request.reject(new Error(JSON.stringify(message.error)));
        else request.resolve(message.result);
      } else if (message.method === 'Runtime.exceptionThrown') {
        errors.push(message.params.exceptionDetails.exception?.description || message.params.exceptionDetails.text);
      } else if (message.method === 'Log.entryAdded' && message.params.entry.source === 'security') {
        errors.push(message.params.entry.text);
      }
    }
  });
  function send(method, params = {}, sessionId) {
    return new Promise((resolve, reject) => {
      const id = ++sequence;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`Chrome timed out: ${method}\n${stderr.slice(-2000)}`));
      }, 15000);
      pending.set(id, { resolve, reject, timer });
      chrome.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + '\0');
    });
  }
  try {
    const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
    const command = (method, params) => send(method, params, sessionId);
    await command('Runtime.enable');
    await command('Log.enable');
    await command('Page.enable');
    return {
      command, errors,
      async evaluate(expression) {
        const result = await command('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
        if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
        return result.result.value;
      },
      async close() {
        chrome.kill();
        await new Promise(resolve => chrome.once('exit', resolve));
        await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    };
  } catch (error) {
    chrome.kill();
    await rm(profile, { recursive: true, force: true });
    throw error;
  }
}

export async function waitFor(page, expression) {
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    if (await page.evaluate(expression)) return;
    await pause(30);
  }
  throw new Error(`Condition timed out: ${expression}\nBrowser errors: ${page.errors.join('\n')}`);
}

export function controls(page) {
  return {
    click: selector => page.evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`),
    input: (selector, value) => page.evaluate(`(() => {
      const el = document.querySelector(${JSON.stringify(selector)});
      el.value = ${JSON.stringify(value)};
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    })()`),
    submit: selector => page.evaluate(`document.querySelector(${JSON.stringify(selector)}).requestSubmit()`)
  };
}
