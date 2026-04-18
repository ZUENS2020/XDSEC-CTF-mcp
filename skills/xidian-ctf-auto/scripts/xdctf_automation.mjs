#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import crypto from 'node:crypto';
import childProcess from 'node:child_process';
import { createRequire } from 'node:module';

const DEFAULT_BASE_URL = 'https://ctf.xidian.edu.cn';
const DEFAULT_API_PREFIX = '/api';
const DEFAULT_TOKEN_FILE = '.xdctf_token';
const DEFAULT_SETTING_FILE = 'setting.md';
const DEFAULT_WSRX_LOG = path.join(process.env.HOME || '', 'Library/Application Support/org.xdsec.wsrx/logs/wsrx.log');

function parseKVText(text) {
  const kv = {};
  const patterns = [
    /(^|\n)\s*[-*]?\s*([A-Za-z0-9_.-]+)\s*[:=]\s*(.+?)\s*(?=\n|$)/g,
    /(^|\n)\s*([A-Za-z0-9_.-]+)\s*\|\s*(.+?)\s*(?=\n|$)/g,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(text)) !== null) {
      const k = String(m[2] || '').trim().toLowerCase();
      let v = String(m[3] || '').trim();
      v = v.replace(/^['"`]/, '').replace(/['"`]$/, '');
      if (k && v) kv[k] = v;
    }
  }
  return kv;
}

function readSettings(settingPath) {
  const full = path.resolve(settingPath);
  if (!fs.existsSync(full)) return {};
  const text = fs.readFileSync(full, 'utf8');
  const kv = parseKVText(text);
  const pick = (...keys) => {
    for (const k of keys) {
      if (kv[k.toLowerCase()]) return kv[k.toLowerCase()];
    }
    return undefined;
  };
  return {
    account: pick('xdctf_account', 'account', 'username', 'user', 'email'),
    password: pick('xdctf_password', 'password', 'pass', 'passwd'),
    token: pick('xdctf_token', 'token', 'jwt'),
    captchaAnswer: pick('xdctf_captcha_answer', 'captcha_answer', 'captcha'),
  };
}

function parseArgs(argv) {
  const positional = [];
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    const v = argv[i];
    if (v.startsWith('--')) {
      const eq = v.indexOf('=');
      if (eq !== -1) {
        options[v.slice(2, eq)] = v.slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (!next || next.startsWith('--')) {
          options[v.slice(2)] = true;
        } else {
          options[v.slice(2)] = next;
          i += 1;
        }
      }
    } else {
      positional.push(v);
    }
  }
  return { positional, options };
}

function num(v, name) {
  const n = Number.parseInt(String(v), 10);
  if (!Number.isFinite(n)) throw new Error(`invalid number for ${name}: ${v}`);
  return n;
}

function mustOpt(opts, key) {
  const v = opts[key];
  if (v === undefined || v === null || v === true || v === '') {
    throw new Error(`missing required option --${key}`);
  }
  return String(v);
}

function toJSON(data) {
  process.stdout.write(`${JSON.stringify(data, null, 2)}\n`);
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function solvePowChallenge(challenge) {
  const raw = String(challenge || '');
  const idx = raw.indexOf('#');
  if (idx === -1) throw new Error(`invalid pow challenge: ${raw}`);
  const difficulty = Number.parseInt(raw.slice(0, idx), 10);
  const prefix = raw.slice(idx + 1);
  if (!Number.isFinite(difficulty) || !prefix) throw new Error(`invalid pow payload: ${raw}`);
  const target = '0'.repeat(Math.max(0, difficulty));
  let i = 0;
  while (true) {
    i += 1;
    const answer = `${prefix}${i.toString(16)}`;
    if (sha256Hex(answer).startsWith(target)) return answer;
    if (i > 20_000_000) throw new Error('pow solve exceeded iteration limit');
  }
}

async function importPlaywright() {
  const require = createRequire(import.meta.url);
  try {
    return require('playwright');
  } catch {
    const npmRootG = shellOut('npm root -g');
    if (npmRootG) {
      try {
        return require(path.join(npmRootG, 'playwright'));
      } catch {
        // fall through to error below
      }
    }
    throw new Error('playwright not found. Install globally: npm i -g playwright && npx playwright install chromium');
  }
}

class BrowserApiClient {
  constructor({ baseUrl, apiPrefix, tokenFile }) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.apiPrefix = `/${String(apiPrefix).replace(/^\/+|\/+$/g, '')}`;
    this.tokenFile = path.resolve(tokenFile);
    this.browser = null;
    this.context = null;
    this.page = null;
    this.token = null;
  }

  apiUrl(p) {
    return `${this.baseUrl}${this.apiPrefix}${p}`;
  }

  loadTokenFromFile() {
    if (fs.existsSync(this.tokenFile)) {
      const t = fs.readFileSync(this.tokenFile, 'utf8').trim();
      if (t) this.token = t;
    }
  }

  saveToken(token) {
    this.token = token;
    fs.writeFileSync(this.tokenFile, `${token}\n`, 'utf8');
  }

  async open() {
    const { chromium } = await importPlaywright();
    const chromePath = process.env.XDCTF_CHROME_PATH;
    if (chromePath) {
      this.browser = await chromium.launch({ headless: true, executablePath: chromePath });
    } else {
      try {
        // Prefer system Chrome so users don't need Playwright-managed browser downloads.
        this.browser = await chromium.launch({ headless: true, channel: 'chrome' });
      } catch {
        this.browser = await chromium.launch({ headless: true });
      }
    }
    this.context = await this.browser.newContext();
    this.page = await this.context.newPage();
    await this.page.goto(this.baseUrl, { waitUntil: 'domcontentloaded' });
  }

  async close() {
    if (this.context) await this.context.close();
    if (this.browser) await this.browser.close();
    this.context = null;
    this.browser = null;
    this.page = null;
  }

  async browserFetch({ method, url, headers = {}, params = null, body = null, wantBinary = false }) {
    const payload = await this.page.evaluate(
      async ({ method, url, headers, params, body, wantBinary }) => {
        const u = new URL(url, window.location.origin);
        if (params && typeof params === 'object') {
          for (const [k, v] of Object.entries(params)) {
            if (v === undefined || v === null) continue;
            u.searchParams.set(k, String(v));
          }
        }
        const resp = await fetch(u.toString(), {
          method,
          headers,
          body: body == null ? undefined : JSON.stringify(body),
        });
        const outHeaders = {};
        resp.headers.forEach((v, k) => {
          outHeaders[k.toLowerCase()] = v;
        });

        if (wantBinary) {
          const bytes = new Uint8Array(await resp.arrayBuffer());
          let binary = '';
          for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
          const base64 = btoa(binary);
          return { status: resp.status, headers: outHeaders, base64 };
        }

        const text = await resp.text();
        return { status: resp.status, headers: outHeaders, text };
      },
      { method, url, headers, params, body, wantBinary },
    );

    return payload;
  }

  async request(method, apiPath, { params = null, body = null, wantBinary = false } = {}) {
    const headers = { Accept: 'application/json' };
    if (body != null) headers['Content-Type'] = 'application/json';
    if (this.token) headers.Authorization = `Bearer ${this.token}`;

    const res = await this.browserFetch({
      method,
      url: this.apiUrl(apiPath),
      headers,
      params,
      body,
      wantBinary,
    });

    const maybeToken = res.headers['set-token'];
    if (maybeToken) this.saveToken(maybeToken);

    if (res.status >= 400) {
      const detail = res.text ? res.text.slice(0, 400) : '[binary response]';
      throw new Error(`HTTP ${res.status} ${method} ${apiPath}: ${detail}`);
    }

    if (wantBinary) {
      return {
        headers: res.headers,
        buffer: Buffer.from(res.base64 || '', 'base64'),
      };
    }

    const t = (res.text || '').trim();
    if (!t) return null;
    try {
      return JSON.parse(t);
    } catch {
      return { raw: t };
    }
  }

  async loginWithSetting({ account, password, captchaAnswer }) {
    if (!account || !password) throw new Error('missing account/password in setting.md');

    const captcha = await this.request('GET', '/account/captcha');
    const captchaId = captcha?.id || captcha?.captcha_id || captcha?.data?.id;
    const validator = captcha?.validator || captcha?.data?.validator;
    const challenge = captcha?.challenge || captcha?.data?.challenge;
    let answer = captchaAnswer;

    if (!answer && (captcha?.answer || captcha?.data?.answer)) {
      answer = captcha.answer || captcha.data.answer;
    }

    if (!answer && validator === 'pow' && challenge) {
      answer = solvePowChallenge(challenge);
    }
    if (!answer && validator === 'none') {
      answer = '0xDEADBEEF';
    }

    if (!captchaId) {
      throw new Error('failed to fetch captcha_id from /api/account/captcha');
    }
    if (!answer) {
      throw new Error('captcha_answer missing. Put `captcha_answer: ...` in setting.md (or provide xdctf_token).');
    }

    await this.request('POST', '/account/login', {
      body: {
        account,
        password,
        captcha_id: captchaId,
        captcha_answer: answer,
      },
    });

    if (!this.token) {
      const token = await this.page.evaluate(() => {
        try {
          const raw = localStorage.getItem('account');
          if (!raw) return null;
          const obj = JSON.parse(raw);
          return obj?.token || null;
        } catch {
          return null;
        }
      });
      if (token) this.saveToken(token);
    }

    if (!this.token) throw new Error('login succeeded but no token found in response/localStorage');
    return { ok: true };
  }
}

function flattenFiles(payload) {
  let nodes = [];
  if (Array.isArray(payload)) {
    nodes = Array.isArray(payload[0]) ? payload[0] : payload;
  } else if (payload && typeof payload === 'object') {
    nodes = payload.files || payload.items || payload.data || [];
  }
  const out = [];
  for (const n of nodes) {
    if (!n || typeof n !== 'object') continue;
    const folder = String(n.folder || n.path || n.name || '.');
    if (Array.isArray(n.files)) {
      for (const f of n.files) {
        if (typeof f === 'string') out.push({ folder, file: f });
        if (f && typeof f === 'object' && (f.name || f.file)) out.push({ folder, file: String(f.name || f.file) });
      }
      continue;
    }
    if (n.file || n.filename || n.name) out.push({ folder, file: String(n.file || n.filename || n.name) });
  }
  const seen = new Set();
  return out.filter((x) => {
    const k = `${x.folder}/${x.file}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function isHttpErrorFor(err, code, method, apiPathPart) {
  const msg = String(err?.message || err || '');
  return msg.includes(`HTTP ${code}`) && msg.includes(`${method.toUpperCase()}`) && msg.includes(apiPathPart);
}

function pickChallengeDescription(challenge) {
  if (!challenge || typeof challenge !== 'object') return null;
  const fields = [
    'content',
    'description',
    'desc',
    'statement',
    'body',
    'detail',
    'markdown',
    'text',
  ];
  for (const k of fields) {
    const v = challenge[k];
    if (typeof v === 'string' && v.trim()) {
      return { field: k, text: v };
    }
  }
  return null;
}

function parseInstanceStatusPayload(payload) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === 'object') {
    if (Array.isArray(payload.instances)) return payload.instances;
    if (Array.isArray(payload.data)) return payload.data;
  }
  return [];
}

function shellOut(cmd) {
  try {
    return childProcess.execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  } catch {
    return '';
  }
}

function parseWsrxCandidatesFromLog({ logPath, traffic, remotePort }) {
  const full = path.resolve(logPath || DEFAULT_WSRX_LOG);
  if (!fs.existsSync(full)) return { log_path: full, candidates: [], tail: [] };
  const lines = fs.readFileSync(full, 'utf8').split(/\r?\n/).filter(Boolean);
  const sig = traffic && remotePort ? `/api/traffic/${traffic}?port=${remotePort}` : null;
  const candidates = [];
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (!sig || !line.includes(sig)) continue;
    const endpoint = line.match(/instance\s+(127\.0\.0\.1:\d+)/)?.[1] || null;
    const ts = line.match(/"timestamp":"([^"]+)"/)?.[1] || null;
    candidates.push({ endpoint, timestamp: ts, line: i + 1 });
  }
  const tail = lines.slice(-200);
  return { log_path: full, candidates, tail };
}

function pickEndpointFromTail(tailLines) {
  const hits = [];
  for (let i = 0; i < tailLines.length; i += 1) {
    const line = tailLines[i];
    const endpoint = line.match(/instance\s+(127\.0\.0\.1:\d+)/)?.[1];
    if (!endpoint) continue;
    const ts = line.match(/"timestamp":"([^"]+)"/)?.[1] || null;
    hits.push({ endpoint, timestamp: ts, relative_line: i + 1 });
  }
  return hits;
}

function parseListenPorts(listenText) {
  const out = [];
  const lines = String(listenText || '').split(/\r?\n/);
  for (const line of lines) {
    const m = line.match(/127\.0\.0\.1:(\d+)\s+\(LISTEN\)/);
    if (!m) continue;
    out.push(Number.parseInt(m[1], 10));
  }
  return out.filter((x) => Number.isFinite(x));
}

function usage() {
  console.log(`xdctf_automation.mjs

Usage:
  node xdctf_automation.mjs auth login [--setting-file setting.md]
  node xdctf_automation.mjs games list [--page 1 --page-size 20 --host-type N --weight N]
  node xdctf_automation.mjs challenges list --game-id N [--page 1 --page-size 200]
  node xdctf_automation.mjs challenges get --game-id N --challenge-id N
  node xdctf_automation.mjs challenges description --game-id N --challenge-id N
  node xdctf_automation.mjs files list --game-id N --challenge-id N [--folder F] [--all]
  node xdctf_automation.mjs files download --game-id N --challenge-id N [--all-files|--file NAME --folder F] [--dest attachments] [--all]
  node xdctf_automation.mjs instance status|env|start|renew|extend|stop|shutdown|endpoint --game-id N --challenge-id N [--wsrx-log PATH]
  node xdctf_automation.mjs submit --game-id N --challenge-id N --flag 'flag{...}' [--check-after]

Global options:
  --base-url https://ctf.xidian.edu.cn
  --api-prefix /api
  --token-file .xdctf_token
  --setting-file setting.md
`);
}

async function main() {
  const { positional, options } = parseArgs(process.argv.slice(2));
  if (positional.length < 2) {
    usage();
    process.exit(2);
  }

  const [scope, action] = positional;
  const baseUrl = String(options['base-url'] || DEFAULT_BASE_URL);
  const apiPrefix = String(options['api-prefix'] || DEFAULT_API_PREFIX);
  const tokenFile = String(options['token-file'] || DEFAULT_TOKEN_FILE);
  const settingFile = String(options['setting-file'] || DEFAULT_SETTING_FILE);

  const client = new BrowserApiClient({ baseUrl, apiPrefix, tokenFile });
  await client.open();
  try {
    const settings = readSettings(settingFile);

    const authIfNeeded = async () => {
      if (settings.token) client.saveToken(settings.token);
      if (!client.token && options.token) client.saveToken(String(options.token));
      if (!client.token) client.loadTokenFromFile();
      if (!client.token) {
        await client.loginWithSetting(settings);
      }
    };

    if (scope === 'auth' && action === 'login') {
      if (settings.token) client.saveToken(settings.token);
      if (!client.token) {
        await client.loginWithSetting(settings);
      }
      toJSON({ ok: true, token_file: path.resolve(tokenFile) });
      return;
    }

    if (scope === 'games' && action === 'list') {
      const page = num(options.page || 1, 'page');
      const pageSize = num(options['page-size'] || 20, 'page-size');
      const hostType = options['host-type'] !== undefined ? num(options['host-type'], 'host-type') : undefined;
      const weight = options.weight !== undefined ? num(options.weight, 'weight') : undefined;
      const out = await client.request('GET', '/game', {
        params: { page, page_size: pageSize, host_type: hostType, weight },
      });
      toJSON(out);
      return;
    }

    if (scope === 'challenges' && action === 'list') {
      await authIfNeeded();
      const gameId = num(mustOpt(options, 'game-id'), 'game-id');
      const page = num(options.page || 1, 'page');
      const pageSize = num(options['page-size'] || 200, 'page-size');
      const out = await client.request('GET', `/game/${gameId}/challenge`, { params: { page, page_size: pageSize } });
      toJSON(out);
      return;
    }

    if (scope === 'challenges' && action === 'get') {
      await authIfNeeded();
      const gameId = num(mustOpt(options, 'game-id'), 'game-id');
      const challengeId = num(mustOpt(options, 'challenge-id'), 'challenge-id');
      const out = await client.request('GET', `/game/${gameId}/challenge/${challengeId}`);
      toJSON(out);
      return;
    }

    if (scope === 'challenges' && action === 'description') {
      await authIfNeeded();
      const gameId = num(mustOpt(options, 'game-id'), 'game-id');
      const challengeId = num(mustOpt(options, 'challenge-id'), 'challenge-id');
      const challenge = await client.request('GET', `/game/${gameId}/challenge/${challengeId}`);
      const picked = pickChallengeDescription(challenge);
      if (!picked) {
        toJSON({
          game_id: gameId,
          challenge_id: challengeId,
          found: false,
          message: 'description field not found in challenge payload',
          available_keys: challenge && typeof challenge === 'object' ? Object.keys(challenge) : [],
        });
        return;
      }
      toJSON({
        game_id: gameId,
        challenge_id: challengeId,
        found: true,
        field: picked.field,
        description: picked.text,
      });
      return;
    }

    if (scope === 'files' && action === 'list') {
      await authIfNeeded();
      const gameId = num(mustOpt(options, 'game-id'), 'game-id');
      const challengeId = num(mustOpt(options, 'challenge-id'), 'challenge-id');
      const folder = options.folder ? String(options.folder) : undefined;
      const includeAll = options.all === true;
      const raw = await client.request('GET', `/game/${gameId}/challenge/${challengeId}/file`, {
        params: { all: includeAll, folder },
      });
      toJSON({ raw, flattened: flattenFiles(raw), all: includeAll });
      return;
    }

    if (scope === 'files' && action === 'download') {
      await authIfNeeded();
      const gameId = num(mustOpt(options, 'game-id'), 'game-id');
      const challengeId = num(mustOpt(options, 'challenge-id'), 'challenge-id');
      const destRoot = path.resolve(String(options.dest || 'attachments'));

      const includeAll = options.all === true;
      const raw = await client.request('GET', `/game/${gameId}/challenge/${challengeId}/file`, {
        params: { all: includeAll, folder: options.folder ? String(options.folder) : undefined },
      });
      let files = flattenFiles(raw);

      if (options.file) {
        files = [{ folder: String(options.folder || '.'), file: String(options.file) }];
      } else if (!options['all-files']) {
        if (files.length !== 1) {
          throw new Error(`ambiguous files (${files.length}). use --all-files or --file/--folder`);
        }
      }

      const candidates = (gameId2, challengeId2, folder2, file2) => ([
        { p: `/game/${gameId2}/challenge/${challengeId2}/file/${folder2}/${file2}`, q: {} },
        { p: `/game/${gameId2}/challenge/${challengeId2}/file/${file2}`, q: { folder: folder2 } },
        { p: `/game/${gameId2}/challenge/${challengeId2}/file`, q: { folder: folder2, file: file2 } },
        { p: `/game/${gameId2}/challenge/${challengeId2}/file`, q: { folder: folder2, name: file2 } },
        { p: `/game/${gameId2}/challenge/${challengeId2}/file`, q: { path: `${folder2}/${file2}` } },
      ]);

      const downloaded = [];
      for (const f of files) {
        let ok = false;
        let lastErr = null;
        for (const c of candidates(gameId, challengeId, f.folder, f.file)) {
          try {
            const bin = await client.request('GET', c.p, { params: c.q, wantBinary: true });
            if (!bin.buffer || !bin.buffer.length) {
              lastErr = 'empty binary';
              continue;
            }
            const outDir = path.join(destRoot, String(gameId), String(challengeId), f.folder);
            fs.mkdirSync(outDir, { recursive: true });
            const outPath = path.join(outDir, f.file);
            fs.writeFileSync(outPath, bin.buffer);
            downloaded.push({ folder: f.folder, file: f.file, size: bin.buffer.length, saved_to: outPath, source_path: c.p });
            ok = true;
            break;
          } catch (err) {
            lastErr = String(err?.message || err);
          }
        }
        if (!ok) throw new Error(`download failed for ${f.folder}/${f.file}: ${lastErr}`);
      }
      toJSON({ downloaded });
      return;
    }

    if (scope === 'instance' && ['status', 'env', 'start', 'renew', 'extend', 'stop', 'shutdown', 'endpoint'].includes(action)) {
      await authIfNeeded();
      const gameId = num(mustOpt(options, 'game-id'), 'game-id');
      const challengeId = num(mustOpt(options, 'challenge-id'), 'challenge-id');
      const getStatus = async () => {
        try {
          return await client.request('GET', `/game/${gameId}/challenge/${challengeId}/instance`);
        } catch (err) {
          // Some training games deny challenge-level instance status to players.
          if (isHttpErrorFor(err, 403, 'GET', `/game/${gameId}/challenge/${challengeId}/instance`)) {
            const gameLevel = await client.request('GET', `/game/${gameId}/instance`);
            const instances = parseInstanceStatusPayload(gameLevel);
            return instances.filter((x) => Number(x?.challenge_id) === challengeId);
          }
          throw err;
        }
      };

      if (action === 'endpoint') {
        const statusPayload = await getStatus();
        const instances = parseInstanceStatusPayload(statusPayload);
        const running = instances.find((x) => String(x?.state || '').toLowerCase() === 'running') || instances[0] || null;
        if (!running) {
          toJSON({
            game_id: gameId,
            challenge_id: challengeId,
            found: false,
            message: 'instance not found; start it first',
          });
          return;
        }

        const traffic = running.traffic || null;
        const remotePort = Number(running?.ports?.[0]) || null;
        const logPath = String(options['wsrx-log'] || DEFAULT_WSRX_LOG);
        const parsed = parseWsrxCandidatesFromLog({ logPath, traffic, remotePort });
        const fallbackHits = pickEndpointFromTail(parsed.tail);
        const fromSig = parsed.candidates.filter((x) => x.endpoint);
        const strict = fromSig.length ? fromSig[fromSig.length - 1] : null;
        const listenText = shellOut("lsof -nP -iTCP -sTCP:LISTEN | rg -i 'wsrx|websocketreflector|reflectorx'");
        const listenerPorts = parseListenPorts(listenText).filter((p) => p !== 3307);
        const inferred = strict || (listenerPorts.length === 1 ? { endpoint: `127.0.0.1:${listenerPorts[0]}`, inferred: true } : null);
        const approx = fallbackHits.length ? fallbackHits[fallbackHits.length - 1] : null;

        const alivePort = fs.existsSync(path.join(path.dirname(parsed.log_path), '..', '.rx.is.alive'))
          ? fs.readFileSync(path.join(path.dirname(parsed.log_path), '..', '.rx.is.alive'), 'utf8').trim()
          : null;

        toJSON({
          game_id: gameId,
          challenge_id: challengeId,
          found: Boolean(inferred),
          traffic,
          remote_port: remotePort,
          local_endpoint: inferred?.endpoint || null,
          confidence: strict ? 'strict_token_match' : (inferred ? 'single_listener_inferred' : 'none'),
          evidence: {
            wsrx_log: parsed.log_path,
            matched_lines: fromSig.slice(-10),
            recent_instance_lines: fallbackHits.slice(-10),
            recent_instance_endpoint_hint: approx?.endpoint || null,
            wsrx_alive_port: alivePort || null,
            wsrx_listener_ports: listenerPorts,
            wsrx_listen_sockets: listenText,
          },
        });
        return;
      }

      const actionNormalized = action === 'extend' ? 'renew' : (action === 'shutdown' ? 'stop' : action);
      const map = {
        status: ['GET', `/game/${gameId}/challenge/${challengeId}/instance`],
        env: ['GET', `/game/${gameId}/challenge/${challengeId}/env`],
        start: ['POST', `/game/${gameId}/challenge/${challengeId}/instance`],
        renew: ['PATCH', `/game/${gameId}/challenge/${challengeId}/instance`],
        stop: ['DELETE', `/game/${gameId}/challenge/${challengeId}/instance`],
      };
      const [method, apiPath] = map[actionNormalized];
      let out;
      if (actionNormalized === 'status') {
        out = await getStatus();
      } else {
        out = await client.request(method, apiPath, { body: method === 'PATCH' ? {} : null });
      }
      toJSON({
        action,
        action_normalized: actionNormalized,
        result: out,
      });
      return;
    }

    if (scope === 'submit' && action === 'flag') {
      await authIfNeeded();
      const gameId = num(mustOpt(options, 'game-id'), 'game-id');
      const challengeId = num(mustOpt(options, 'challenge-id'), 'challenge-id');
      const flag = mustOpt(options, 'flag');
      const submit = await client.request('POST', `/game/${gameId}/challenge/${challengeId}/submit`, {
        body: { content: flag },
      });
      const result = { submit };
      if (options['check-after']) {
        const status = await client.request('GET', `/game/${gameId}/challenge/${challengeId}/submit`);
        result.solve_status = status;
      }
      toJSON(result);
      return;
    }

    throw new Error(`unknown command: ${scope} ${action}`);
  } finally {
    await client.close();
  }
}

main().catch((err) => {
  process.stderr.write(`ERROR: ${err?.message || err}\n`);
  process.exit(1);
});
