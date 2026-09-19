#!/usr/bin/env node
// Focused browser-interaction regression checks for the generated static site
// in dist/. No third-party dependency: this uses Node's built-in HTTP server,
// global fetch and global WebSocket to drive a headless Brave
// instance over the Chrome DevTools Protocol (CDP).
//
// Why a real browser: the defects under test are DOM geometry and live React
// state changes (dialog layout while a result list grows, explorer controls
// reacting to typing, 320px overflow, mobile document order). None of these can
// be established by scanning static HTML the way check-a11y.mjs does.
//
// Design constraints:
//   - only Node builtins (node:http, node:child_process, node:fs, node:os)
//   - the browser gets its own isolated temp profile and is the only process
//     this script kills; a dev server or the user's browser is never touched
//   - assertions use DOM state/geometry and bounded polling, never fixed sleeps
//     and never pixel screenshots
//
// Exit code is non-zero when any assertion fails. Skips are reported but do not
// fail the run (they mark coverage that does not exist yet).

import http from 'node:http';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { extname, join, normalize, resolve, sep } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const distDir = join(root, 'dist');

if (!existsSync(distDir)) {
	console.error('check-interactions: dist/ not found — run the build first.');
	process.exit(1);
}

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

function waitForExit(child, timeout = 5000) {
	return new Promise((done) => {
		if (child.exitCode !== null) return done(true);
		const timer = setTimeout(() => {
			child.removeListener('exit', onExit);
			done(false);
		}, timeout);
		const onExit = () => {
			clearTimeout(timer);
			done(true);
		};
		child.once('exit', onExit);
	});
}

async function waitForPortClosed(port, timeout = 5000) {
	const deadline = Date.now() + timeout;
	while (Date.now() < deadline) {
		const controller = new AbortController();
		const probeTimeout = setTimeout(() => controller.abort(), Math.min(500, deadline - Date.now()));
		try {
			const response = await fetch(`http://127.0.0.1:${port}/json/version`, {
				cache: 'no-store',
				signal: controller.signal,
			});
			await response.body?.cancel();
		} catch (error) {
			if (!controller.signal.aborted && error?.cause?.code === 'ECONNREFUSED') return true;
		} finally {
			clearTimeout(probeTimeout);
		}
		await sleep(50);
	}
	return false;
}

async function removeDir(dir) {
	for (let attempt = 0; attempt < 30; attempt += 1) {
		try {
			rmSync(dir, { recursive: true, force: true });
		} catch {
			// A just-killed browser can still be flushing its profile; retry.
		}
		if (!existsSync(dir)) return;
		await sleep(100);
	}
}

// ---------------------------------------------------------------------------
// Static file server for dist/
// ---------------------------------------------------------------------------

const CONTENT_TYPES = {
	'.html': 'text/html; charset=utf-8',
	'.json': 'application/json; charset=utf-8',
	'.js': 'text/javascript; charset=utf-8',
	'.mjs': 'text/javascript; charset=utf-8',
	'.css': 'text/css; charset=utf-8',
	'.svg': 'image/svg+xml',
	'.png': 'image/png',
	'.jpg': 'image/jpeg',
	'.jpeg': 'image/jpeg',
	'.webp': 'image/webp',
	'.ico': 'image/x-icon',
	'.woff2': 'font/woff2',
	'.woff': 'font/woff',
	'.xml': 'application/xml; charset=utf-8',
	'.txt': 'text/plain; charset=utf-8',
};

function safeFilePath(pathname) {
	const candidate = normalize(join(distDir, pathname));
	if (candidate !== distDir && !candidate.startsWith(distDir + sep)) return null;
	return candidate;
}

function resolveRequestFile(pathname) {
	let file = safeFilePath(pathname);
	if (!file) return null;
	if (existsSync(file) && statSync(file).isDirectory()) file = join(file, 'index.html');
	if (existsSync(file) && statSync(file).isFile()) return file;
	const index = safeFilePath(normalize(join(pathname, 'index.html')));
	if (index && existsSync(index) && statSync(index).isFile()) return index;
	return null;
}

async function startServer() {
	const server = http.createServer((req, res) => {
		try {
			const url = new URL(req.url, 'http://127.0.0.1');
			const pathname = decodeURIComponent(url.pathname);
			const file = resolveRequestFile(pathname);
			if (!file) {
				res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
				res.end('not found');
				return;
			}
			res.writeHead(200, {
				'content-type': CONTENT_TYPES[extname(file).toLowerCase()] ?? 'application/octet-stream',
				'cache-control': 'no-store',
			});
			res.end(readFileSync(file));
		} catch (error) {
			res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
			res.end(String(error && error.message));
		}
	});
	await new Promise((res, rej) => {
		server.once('error', rej);
		server.listen(0, '127.0.0.1', res);
	});
	const { port } = server.address();
	return { server, origin: `http://127.0.0.1:${port}` };
}

// ---------------------------------------------------------------------------
// Browser discovery and launch
// ---------------------------------------------------------------------------

function resolveBrowser() {
	const candidates = [
		process.env.BRAVE_BIN,
		'brave',
		'brave-browser',
	].filter(Boolean);

	const pathDirs = (process.env.PATH ?? '').split(sep === '/' ? ':' : ';').filter(Boolean);
	for (const candidate of candidates) {
		if (candidate.includes('/') || candidate.includes('\\')) {
			if (existsSync(candidate)) return candidate;
			continue;
		}
		for (const dir of pathDirs) {
			const full = join(dir, candidate);
			if (existsSync(full)) return full;
		}
	}
	return null;
}

async function launchBrowser(browserPath, profileDir) {
	const child = spawn(
		browserPath,
		[
			'--headless=new',
			'--remote-debugging-port=0',
			`--user-data-dir=${profileDir}`,
			'--no-first-run',
			'--no-default-browser-check',
			'--disable-gpu',
			'--disable-dev-shm-usage',
			'--disable-extensions',
			'--disable-background-networking',
			'--window-size=1280,900',
			'about:blank',
		],
		{ stdio: ['ignore', 'ignore', 'pipe'] },
	);

	let stderr = '';
	child.stderr?.on('data', (chunk) => {
		stderr += chunk.toString();
		if (stderr.length > 8000) stderr = stderr.slice(-8000);
	});

	const portFile = join(profileDir, 'DevToolsActivePort');
	const deadline = Date.now() + 20000;
	while (Date.now() < deadline) {
		if (existsSync(portFile)) {
			const [line] = readFileSync(portFile, 'utf-8').trim().split(/\r?\n/);
			if (line && Number.isFinite(Number(line))) {
				return { child, port: Number(line), getStderr: () => stderr };
			}
		}
		if (child.exitCode !== null) {
			throw new Error(`browser exited early with code ${child.exitCode}\n${stderr}`);
		}
		await sleep(100);
	}
	child.kill('SIGKILL');
	await waitForExit(child);
	throw new Error(`timed out waiting for DevToolsActivePort\n${stderr}`);
}

async function stopBrowser(instance, profileDir) {
	try {
		if (!instance?.child) return;
		if (instance.child.exitCode === null) instance.child.kill('SIGKILL');
		assert(await waitForExit(instance.child), 'browser process did not exit after SIGKILL');
		assert(await waitForPortClosed(instance.port), `browser DevTools port ${instance.port} remained open`);
	} finally {
		await removeDir(profileDir);
	}
}

// ---------------------------------------------------------------------------
// Minimal CDP client over the Node global WebSocket
// ---------------------------------------------------------------------------

class CDPClient {
	constructor(url) {
		this.ws = new WebSocket(url);
		this.nextId = 0;
		this.pending = new Map();
		this.listeners = new Map();
	}

	connect() {
		return new Promise((res, rej) => {
			this.ws.addEventListener('open', () => res());
			this.ws.addEventListener('error', () => rej(new Error('CDP WebSocket error')));
			this.ws.addEventListener('message', (event) => this.#onMessage(event.data));
		});
	}

	#onMessage(raw) {
		let message;
		try {
			message = JSON.parse(typeof raw === 'string' ? raw : String(raw));
		} catch {
			return;
		}
		if (message.id !== undefined) {
			const entry = this.pending.get(message.id);
			if (!entry) return;
			this.pending.delete(message.id);
			if (message.error) entry.reject(new Error(`${message.error.message} (${message.error.code})`));
			else entry.resolve(message.result);
			return;
		}
		for (const fn of this.listeners.get(message.method) ?? []) fn(message.params);
	}

	send(method, params = {}) {
		const id = ++this.nextId;
		return new Promise((res, rej) => {
			this.pending.set(id, { resolve: res, reject: rej });
			this.ws.send(JSON.stringify({ id, method, params }));
		});
	}

	on(method, fn) {
		if (!this.listeners.has(method)) this.listeners.set(method, []);
		this.listeners.get(method).push(fn);
	}

	close() {
		try {
			this.ws.close();
		} catch {
			// already closing
		}
	}
}

// ---------------------------------------------------------------------------
// Assertion bookkeeping
// ---------------------------------------------------------------------------

const passes = [];
const failures = [];
const skips = [];

async function check(name, fn) {
	try {
		await fn();
		passes.push(name);
		console.log(`  PASS ${name}`);
	} catch (error) {
		failures.push({ name, error });
		console.error(`  FAIL ${name}: ${error.message}`);
	}
}

function assert(condition, message) {
	if (!condition) throw new Error(message);
}

function skip(name, reason) {
	skips.push({ name, reason });
	console.log(`  SKIP ${name}: ${reason}`);
}

// ---------------------------------------------------------------------------
// Page driving helpers
// ---------------------------------------------------------------------------

let cdp;

async function evaluate(expression) {
	const result = await cdp.send('Runtime.evaluate', {
		expression,
		awaitPromise: true,
		returnByValue: true,
		userGesture: true,
	});
	if (result.exceptionDetails) {
		const detail = result.exceptionDetails.exception?.description ?? result.exceptionDetails.text;
		throw new Error(`page evaluate failed: ${detail}`);
	}
	return result.result.value;
}

async function waitFor(predicate, { timeout = 5000, interval = 50, label = 'condition' } = {}) {
	const deadline = Date.now() + timeout;
	let last;
	while (Date.now() < deadline) {
		try {
			last = await predicate();
			if (last) return last;
		} catch (error) {
			last = error.message;
		}
		await sleep(interval);
	}
	throw new Error(`timed out after ${timeout}ms waiting for ${label}${last !== undefined ? ` (last: ${JSON.stringify(last)})` : ''}`);
}

async function goto(path) {
	await cdp.send('Page.navigate', { url: `${origin}${path}` });
	await waitFor(
		async () => {
			const state = await evaluate('({ ready: document.readyState, path: location.pathname })');
			return state.ready === 'complete' && state.path === path;
		},
		{ timeout: 15000, label: `navigation to ${path}` },
	);
}

async function setViewport(width, height) {
	await cdp.send('Emulation.setDeviceMetricsOverride', {
		width,
		height,
		deviceScaleFactor: 1,
		mobile: width < 600,
	});
}

// Wait until every Astro island on the page reports hydrated. Astro removes the
// `ssr` attribute during hydration, which is a deterministic readiness signal
// (unlike a fixed timeout).
async function waitForHydration() {
	await waitFor(
		() => evaluate("document.querySelectorAll('astro-island[client][ssr]').length === 0"),
		{ timeout: 15000, label: 'Astro island hydration' },
	);
}

function setInputValue(selector, value) {
	return evaluate(`(() => {
		const el = document.querySelector(${JSON.stringify(selector)});
		if (!el) return false;
		el.focus();
		const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
		const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
		setter.call(el, ${JSON.stringify(value)});
		el.dispatchEvent(new Event('input', { bubbles: true }));
		return true;
	})()`);
}

function textContent(selector) {
	return evaluate(`(() => {
		const el = document.querySelector(${JSON.stringify(selector)});
		return el ? el.textContent.replace(/\\s+/g, ' ').trim() : null;
	})()`);
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

const SEARCH_DIALOG = 'dialog[aria-labelledby="search-dialog-title"]';
const SEARCH_INPUT = `${SEARCH_DIALOG} input[type="search"]`;
const SEARCH_STATUS = `${SEARCH_DIALOG} [role="status"]`;
const SEARCH_LIST = `${SEARCH_DIALOG} ul`;

async function testSearchDialogStability() {
	await setViewport(1024, 700);
	await goto('/');
	await waitForHydration();

	await evaluate(`document.querySelector('button[aria-label="Search"]')?.click() ?? false`);
	await waitFor(() => evaluate(`document.querySelector(${JSON.stringify(SEARCH_DIALOG)})?.open === true`), {
		label: 'search dialog to open',
	});

	const queries = await evaluate(`(async () => {
		const response = await fetch('/search-index.json');
		if (!response.ok) throw new Error('search index unavailable');
		const data = await response.json();
		const entries = Array.isArray(data) ? data : data?.entries;
		if (!Array.isArray(entries)) throw new Error('search index has no entries');
		const fields = (entry) => [
			entry.title,
			entry.description,
			entry.objective,
			entry.category,
			entry.label,
			...(entry.tags ?? []),
			...(entry.tools ?? []),
			entry.skill,
			entry.outcome,
		].filter((value) => typeof value === 'string');
		const matches = (term) => entries
			.filter((entry) => fields(entry).some((value) => value.toLowerCase().includes(term)))
			.map((entry) => entry.href);
		const candidates = new Set();
		const pairs = new Set();
		for (const entry of entries) {
			const terms = new Set();
			for (const value of fields(entry)) {
				for (const term of value.toLowerCase().match(/[a-z0-9][a-z0-9-]*/g) ?? []) {
					candidates.add(term);
					if (term.length > 1) terms.add(term);
				}
			}
			const entryTerms = [...terms];
			for (let first = 0; first < entryTerms.length; first += 1) {
				for (let second = first + 1; second < entryTerms.length; second += 1) {
					pairs.add(entryTerms[first] + ' ' + entryTerms[second]);
				}
			}
		}
		const ranked = [...candidates].map((term) => ({
			term,
			hrefs: matches(term),
		})).filter((candidate) => candidate.hrefs.length > 0)
			.sort((a, b) => b.hrefs.length - a.hrefs.length);
		const first = ranked[0];
		const second = ranked.find((candidate) =>
			candidate.term !== first?.term && candidate.hrefs.slice(0, 20).join('\\n') !== first?.hrefs.slice(0, 20).join('\\n'),
		);
		const and = [...pairs].map((query) => {
			const [firstTerm, secondTerm] = query.split(' ');
			const firstHrefs = matches(firstTerm);
			const secondHrefs = matches(secondTerm);
			const hrefs = entries
				.filter((entry) => fields(entry).some((value) => value.toLowerCase().includes(firstTerm)) && fields(entry).some((value) => value.toLowerCase().includes(secondTerm)))
				.map((entry) => entry.href);
			return { query, hrefs, broad: Math.max(firstHrefs.length, secondHrefs.length) };
		}).find((candidate) => candidate.hrefs.length > 0 && candidate.hrefs.length < candidate.broad);
		return {
			first: first ? { query: first.term, hrefs: first.hrefs } : null,
			second: second ? { query: second.term, hrefs: second.hrefs } : null,
			and: and ?? null,
		};
	})()`);
	assert(queries.first && queries.second && queries.and, 'search index has no measurable single-term and AND query result sets');
	const firstQuery = queries.first.query;
	const secondQuery = queries.second.query;

	await waitFor(
		async () => (await textContent(SEARCH_STATUS)) === 'Start typing to search.',
		{ label: 'search index to load' },
	);
	await setInputValue(SEARCH_INPUT, firstQuery);
	await waitFor(
		async () => {
			const text = await textContent(SEARCH_STATUS);
			return typeof text === 'string' && /^\d+ results?\b/.test(text);
		},
		{ label: `search status for query ${firstQuery}` },
	);

	const searchState = () =>
		evaluate(`(() => {
			const dialog = document.querySelector(${JSON.stringify(SEARCH_DIALOG)});
			const list = dialog.querySelector(${JSON.stringify(SEARCH_LIST)});
			const status = dialog.querySelector('[role="status"]')?.textContent.trim() ?? '';
			const hrefs = Array.from(list?.querySelectorAll(':scope > li a') ?? []).map((link) => link.getAttribute('href'));
			const total = status.match(/^(\\d+)\\s+results?\\b/)?.[1] ?? null;
			const shown = status.match(/Showing the first (\\d+)/)?.[1] ?? total;
			return { status, hrefs, total: total ? Number(total) : null, shown: shown ? Number(shown) : null };
		})()`);

	const firstSearch = await searchState();
	assert(firstSearch.total !== null, `search status has no total: "${firstSearch.status}"`);
	assert(firstSearch.shown !== null, `search status has no rendered limit: "${firstSearch.status}"`);
	assert(firstSearch.total > 0, `search status reports no measurable results: "${firstSearch.status}"`);
	assert(firstSearch.total >= firstSearch.shown, `search status total is below rendered limit: "${firstSearch.status}"`);
	assert(
		firstSearch.hrefs.length === firstSearch.shown,
		`search status says ${firstSearch.shown} rendered results, found ${firstSearch.hrefs.length}`,
	);
	assert(firstSearch.total === queries.first.hrefs.length, `search total ${firstSearch.total} differs from index matches ${queries.first.hrefs.length}`);
	assert(JSON.stringify(firstSearch.hrefs) === JSON.stringify(queries.first.hrefs.slice(0, firstSearch.shown)), 'search displayed hrefs differ from index matches or cap');
	if (queries.first.hrefs.length > firstSearch.shown) {
		assert(firstSearch.status.includes('Showing the first'), `search cap message missing: "${firstSearch.status}"`);
	}

	const geometry = () =>
		evaluate(`(() => {
			const dialog = document.querySelector(${JSON.stringify(SEARCH_DIALOG)});
			const list = dialog.querySelector(${JSON.stringify(SEARCH_LIST)});
			const heading = dialog.querySelector('h2');
			const input = dialog.querySelector('input[type="search"]');
			const status = dialog.querySelector('[role="status"]');
			const dialogRect = dialog.getBoundingClientRect();
			const inputRect = input.getBoundingClientRect();
			const listStyle = getComputedStyle(list);
			return {
				dialogTop: dialogRect.top,
				inputTop: inputRect.top,
				listOverflowY: listStyle.overflowY,
				listScrollHeight: list.scrollHeight,
				listClientHeight: list.clientHeight,
				dialogScrollHeight: dialog.scrollHeight,
				dialogClientHeight: dialog.clientHeight,
				dialogOverflowY: getComputedStyle(dialog).overflowY,
				headingInList: list.contains(heading),
				inputInList: list.contains(input),
				statusInList: list.contains(status),
			};
		})()`);

	const first = await geometry();

	// The result list must be its own scroll container while the dialog chrome
	// stays fixed.
	assert(
		first.listOverflowY === 'auto' || first.listOverflowY === 'scroll',
		`result list is not a scroll container (overflow-y: ${first.listOverflowY})`,
	);
	assert(
		first.listScrollHeight > first.listClientHeight + 1,
		`result list does not overflow as expected (scrollHeight ${first.listScrollHeight} <= clientHeight ${first.listClientHeight})`,
	);
	assert(
		first.dialogScrollHeight <= first.dialogClientHeight + 1,
		`dialog itself is scrolling (scrollHeight ${first.dialogScrollHeight} > clientHeight ${first.dialogClientHeight})`,
	);
	assert(
		first.dialogOverflowY !== 'auto' && first.dialogOverflowY !== 'scroll',
		`dialog is a scroll container (overflow-y: ${first.dialogOverflowY})`,
	);
	assert(!first.headingInList, 'heading is inside the result list scroll container');
	assert(!first.inputInList, 'search input is inside the result list scroll container');
	assert(!first.statusInList, 'status region is inside the result list scroll container');

	// Changing the rendered result set must not move the dialog or its top chrome.
	await setInputValue(SEARCH_INPUT, secondQuery);
	await waitFor(
		async () => {
			const next = await searchState();
			return next.hrefs.join('\n') !== firstSearch.hrefs.join('\n') ? next : false;
		},
		{ label: `search status for query ${secondQuery}` },
	);
	const secondSearch = await searchState();
	assert(secondSearch.total !== null, `search status has no total: "${secondSearch.status}"`);
	assert(secondSearch.shown !== null, `search status has no rendered limit: "${secondSearch.status}"`);
	assert(secondSearch.total > 0, `search status reports no measurable results: "${secondSearch.status}"`);
	assert(secondSearch.total >= secondSearch.shown, `search status total is below rendered limit: "${secondSearch.status}"`);
	assert(
		secondSearch.hrefs.length === secondSearch.shown,
		`search status says ${secondSearch.shown} rendered results, found ${secondSearch.hrefs.length}`,
	);
	assert(secondSearch.total === queries.second.hrefs.length, `search total ${secondSearch.total} differs from index matches ${queries.second.hrefs.length}`);
	assert(JSON.stringify(secondSearch.hrefs) === JSON.stringify(queries.second.hrefs.slice(0, secondSearch.shown)), 'search displayed hrefs differ from index matches or cap');
	if (queries.second.hrefs.length > secondSearch.shown) {
		assert(secondSearch.status.includes('Showing the first'), `search cap message missing: "${secondSearch.status}"`);
	}

	const second = await geometry();
	assert(
		Math.abs(second.dialogTop - first.dialogTop) <= 1,
		`dialog top moved as results changed (${first.dialogTop} -> ${second.dialogTop})`,
	);
	assert(
		Math.abs(second.inputTop - first.inputTop) <= 1,
		`dialog chrome moved as results changed (input top ${first.inputTop} -> ${second.inputTop})`,
	);

	await setInputValue(SEARCH_INPUT, queries.and.query);
	await waitFor(
		async () => {
			const next = await searchState();
			return next.total === queries.and.hrefs.length ? next : false;
		},
		{ label: `search status for multi-term query ${queries.and.query}` },
	);
	const andSearch = await searchState();
	assert(andSearch.total === queries.and.hrefs.length, `AND search total ${andSearch.total} differs from index matches ${queries.and.hrefs.length}`);
	assert(andSearch.shown !== null, `AND search status has no rendered limit: "${andSearch.status}"`);
	assert(
		JSON.stringify(andSearch.hrefs) === JSON.stringify(queries.and.hrefs.slice(0, andSearch.shown)),
		'multi-term search used OR matching instead of AND matching',
	);
}

async function testExplorerInteractivity() {
	const REACTION_TIMEOUT = 2000;
	await setViewport(1280, 900);
	await goto('/case-studies/');
	await waitForHydration();

	const inputExists = await evaluate(`!!document.querySelector('#explorer-search')`);
	assert(inputExists, 'explorer search input #explorer-search is missing');

	const initial = await evaluate(`(() => ({
		status: document.querySelector('.explorer-result-js')?.textContent ?? '',
		visibleHrefs: Array.from(document.querySelectorAll('#explorer-grid .explorer-card:not([hidden]) a'))
			.map((link) => link.getAttribute('href')),
	}))()`);
	const expected = await evaluate(`(() => {
		const cards = Array.from(document.querySelectorAll('#explorer-grid .explorer-card'));
		const initialHrefs = new Set(${JSON.stringify(initial.visibleHrefs)});
		const island = Array.from(document.querySelectorAll('astro-island')).find((candidate) =>
			candidate.getAttribute('component-url')?.includes('/Explorer'),
		);
		const props = island?.getAttribute('props');
		let studies;
		try {
			studies = props ? JSON.parse(props).studies : null;
		} catch {
			studies = null;
		}
		if (!Array.isArray(studies)) return null;
		const dataByHref = new Map(studies.map((study) => [study.href, study]));
		const ordered = cards
			.map((card) => dataByHref.get(card.querySelector('a')?.getAttribute('href')))
			.filter(Boolean);
		const candidates = new Set();
		for (const study of ordered) {
			for (const term of study.search.toLowerCase().match(/[a-z0-9][a-z0-9-]*/g) ?? []) candidates.add(term);
		}
		for (const term of candidates) {
			const matches = ordered
				.filter((study) => study.search.toLowerCase().includes(term))
				.map((study) => study.href);
			if (matches.length > 0 && (matches.length !== initialHrefs.size || matches.some((href) => !initialHrefs.has(href)))) {
				return { query: term, hrefs: matches };
			}
		}
		return null;
	})()`);
	assert(expected, 'explorer data has no query producing a measurable, different result set');
	const started = Date.now();
	const set = await setInputValue('#explorer-search', expected.query);
	assert(set, 'could not set the explorer search input');
	const status = await waitFor(
		async () => {
			const text = await textContent('.explorer-result-js');
			const visibleHrefs = await evaluate(
				`Array.from(document.querySelectorAll('#explorer-grid .explorer-card:not([hidden]) a')).map((link) => link.getAttribute('href'))`,
			);
			return typeof text === 'string' && text !== initial.status && visibleHrefs.join('\n') !== initial.visibleHrefs.join('\n')
				? { text, visibleHrefs }
				: false;
		},
		{ timeout: REACTION_TIMEOUT, label: 'explorer results to react to typing' },
	);
	const elapsed = Date.now() - started;
	assert(elapsed <= REACTION_TIMEOUT, `explorer response exceeded ${REACTION_TIMEOUT}ms (${elapsed}ms)`);
	const count = status.text.match(/^(?:Showing (\d+) of \d+|(\d+) results?)/);
	assert(count, `explorer result state is not truthful: "${status.text}"`);
	const renderedCount = Number(count[1] ?? count[2]);
	assert(
		renderedCount === status.visibleHrefs.length,
		`explorer result state says ${renderedCount} rendered results, found ${status.visibleHrefs.length}`,
	);
	assert(renderedCount === expected.hrefs.length, `explorer result state says ${renderedCount}, expected ${expected.hrefs.length}`);
	assert(JSON.stringify(status.visibleHrefs) === JSON.stringify(expected.hrefs), 'explorer visible hrefs differ from rendered-card matches');
	console.log(`       (explorer reacted in ~${elapsed}ms, status: "${status.text}")`);
}

async function testNarrowViewportOverflow() {
	await setViewport(320, 640);
	await goto('/');

	const metrics = await evaluate(`(() => {
		const doc = document.documentElement;
		const header = document.querySelector('.portfolio-header');
		const hasHeader = !!header;
		const headerInner = header ? header.firstElementChild : null;
		const hasHeaderInner = !!headerInner;
		return {
			hasHeader,
			hasHeaderInner,
			innerWidth: window.innerWidth,
			clientWidth: doc.clientWidth,
			scrollWidth: doc.scrollWidth,
			bodyScrollWidth: document.body.scrollWidth,
			headerScrollWidth: header ? header.scrollWidth : null,
			headerClientWidth: header ? header.clientWidth : null,
			headerInnerRight: headerInner ? headerInner.getBoundingClientRect().right : null,
		};
	})()`);
	assert(metrics.hasHeader, 'header .portfolio-header is missing at 320px');
	assert(metrics.hasHeaderInner, 'mobile header inner container is missing at 320px');

	assert(
		metrics.scrollWidth <= metrics.clientWidth + 1,
		`document overflows at 320px (scrollWidth ${metrics.scrollWidth} > clientWidth ${metrics.clientWidth})`,
	);
	assert(
		metrics.bodyScrollWidth <= metrics.clientWidth + 1,
		`body overflows at 320px (body scrollWidth ${metrics.bodyScrollWidth} > clientWidth ${metrics.clientWidth})`,
	);
	assert(
		metrics.headerScrollWidth <= metrics.headerClientWidth + 1,
		`header overflows at 320px (scrollWidth ${metrics.headerScrollWidth} > clientWidth ${metrics.headerClientWidth})`,
	);
}

async function testMobileCaseOrder() {
	await setViewport(390, 844);
	await goto('/case-studies/htb/machines/windows/monteverde/');

	const order = await evaluate(`(() => {
		const prefix = (a, b) =>
			!!(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
		const mobileDisclosures = Array.from(document.querySelectorAll('main[data-page="case"] div'))
			.filter((container) => container.classList.contains('xl:hidden'))
			.flatMap((container) => Array.from(container.querySelectorAll('details')));
		const disclosure = (label) =>
			mobileDisclosures.find((details) =>
				(details.querySelector('summary.portfolio-disclosure')?.textContent ?? '')
					.toLowerCase()
					.includes(label),
			);
		const article = document.querySelector('article[data-page="case"]');
		const h1 = document.querySelector('#_top');
		const articleContent = article
			? Array.from(article.children).find(
					(child) => child.classList.contains('portfolio-prose') && !child.querySelector('h1'),
				)
			: null;
		const facts = disclosure('case facts')?.querySelector('aside[aria-label="Case facts"]');
		const contents = disclosure('contents')?.querySelector('nav[aria-label="Case contents"]');
		const relatedDisclosure = disclosure('related cases and provenance');
		const related = relatedDisclosure?.querySelector('nav[aria-label="Related cases"]');
		const provenance = relatedDisclosure?.querySelector('nav[aria-label="Provenance"]');
		return {
			hasArticle: !!articleContent,
			hasH1: !!h1,
			hasFacts: !!facts,
			hasContents: !!contents,
			hasRelated: !!related,
			hasProvenance: !!provenance,
			h1BeforeFacts: !!(h1 && facts) && prefix(h1, facts),
			factsBeforeContents: !!(facts && contents) && prefix(facts, contents),
			contentsBeforeArticle: !!(contents && articleContent) && prefix(contents, articleContent),
			articleBeforeRelated: !!(articleContent && related) && prefix(articleContent, related),
			articleBeforeProvenance: !!(articleContent && provenance) && prefix(articleContent, provenance),
			relatedBeforeProvenance: !!(related && provenance) && prefix(related, provenance),
		};
	})()`);

	for (const key of ['hasArticle', 'hasH1', 'hasFacts', 'hasContents', 'hasRelated', 'hasProvenance']) {
		assert(order[key], `mobile case page is missing an expected element: ${key}`);
	}
	assert(order.h1BeforeFacts, 'H1 does not precede the Case facts disclosure in document order');
	assert(order.factsBeforeContents, 'Case facts does not precede Contents in document order');
	assert(order.contentsBeforeArticle, 'Contents does not precede article in document order');
	assert(order.articleBeforeRelated, 'Related cases appears before the end of the article in document order');
	assert(order.articleBeforeProvenance, 'Provenance appears before the end of the article in document order');
	if (order.hasRelated && order.hasProvenance) {
		assert(order.relatedBeforeProvenance, 'Related cases does not precede Provenance in document order');
	}
}

async function testMobileTocs() {
	const pages = ['/method/', '/prolabs/dante/'];
	for (const path of pages) {
		await check(`mobile TOC on ${path}`, async () => {
			const response = await fetch(`${origin}${path}`);
			assert(
				response.ok && response.headers.get('content-type')?.includes('text/html'),
				`required mobile TOC fixture unavailable: ${path}`,
			);
			await setViewport(390, 844);
			await goto(path);
			const ok = await evaluate(`(() => {
				const toc = Array.from(document.querySelectorAll('main .xl\\:hidden details'))
					.find((details) => details.querySelector('summary.portfolio-disclosure')?.textContent.trim() === 'Contents');
				const summary = toc?.querySelector('summary.portfolio-disclosure');
				const links = toc?.querySelectorAll('nav[aria-label="Page contents"] a[href^="#"]');
				return !!toc && !!summary && !!links?.length && toc.open === false;
			})()`);
			assert(ok, `mobile TOC on ${path} is missing Contents disclosure or links`);
		});
	}
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

let origin = '';
let server;
let browser;

try {
	const browserPath = resolveBrowser();
	if (!browserPath) {
		console.error(
			'check-interactions: no Brave executable found. Set BRAVE_BIN or install Brave.',
		);
		process.exit(1);
	}
	console.log(`check-interactions: using browser ${browserPath}`);

	const started = await startServer();
	server = started.server;
	origin = started.origin;

	const profileDir = mkdtempSync(join(tmpdir(), 'portfolio-interactions-'));
	try {
		browser = await launchBrowser(browserPath, profileDir);

		const targets = await (await fetch(`http://127.0.0.1:${browser.port}/json/list`)).json();
		const page = targets.find((target) => target.type === 'page');
		if (!page?.webSocketDebuggerUrl) {
			throw new Error('no page target available over CDP');
		}

		cdp = new CDPClient(page.webSocketDebuggerUrl);
		await cdp.connect();
		await cdp.send('Page.enable');
		await cdp.send('Runtime.enable');

		console.log('check-interactions: running assertions');
		await check('search dialog top stable and list scrolls independently', testSearchDialogStability);
		await check('explorer controls respond to typing promptly', testExplorerInteractivity);
		await check('320px homepage/header has no horizontal overflow', testNarrowViewportOverflow);
		await check('mobile case document order', testMobileCaseOrder);
		await testMobileTocs();
	} finally {
		cdp?.close();
		await stopBrowser(browser, profileDir);
	}
} catch (error) {
	console.error(`check-interactions: fatal error: ${error.message}`);
	failures.push({ name: 'runner', error });
} finally {
	await new Promise((done) => (server ? server.close(done) : done()));
}

console.log('');
console.log(
	`check-interactions: ${passes.length} passed, ${failures.length} failed, ${skips.length} skipped`,
);
for (const { name, error } of failures) console.error(`  - ${name}: ${error.message}`);
for (const { name, reason } of skips) console.log(`  - skipped ${name}: ${reason}`);

if (failures.length > 0) process.exit(1);
console.log('check-interactions: OK');
