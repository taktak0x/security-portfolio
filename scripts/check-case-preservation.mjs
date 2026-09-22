#!/usr/bin/env node
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { relative, resolve, sep } from 'node:path';

const LABEL = /^\s*(?:[*_]{0,2})(Observation|Action|Evidence|Significance|Result|Recommendation|Detection|Validation)(?:[*_]{0,2}):/i;

function usage() {
	return 'usage: node scripts/check-case-preservation.mjs --base <git-ref> --draft-root <dir> --public-root <dir> [--files <path,...>] [--strict] [--json]';
}

function parseArgs(argv) {
	const args = {};
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (arg === '--strict' || arg === '--json') args[arg.slice(2)] = true;
		else if (['--base', '--draft-root', '--public-root', '--files'].includes(arg)) {
			if (!argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error(`${arg} needs a value`);
			args[arg.slice(2)] = argv[++i];
		} else throw new Error(`unknown option: ${arg}`);
	}
	for (const name of ['base', 'draft-root', 'public-root']) if (!args[name]) throw new Error(`missing --${name}`);
	if (args.base.startsWith('-') || /[\0\r\n:]/.test(args.base)) throw new Error(`unsafe git ref: ${args.base}`);
	args.files = args.files ? args.files.split(',').map((file) => file.trim()).filter(Boolean) : null;
	return args;
}

function normalize(text) {
	return text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
}

function withoutStatus(text) {
	return text.replace(/^(---\n[\s\S]*?\n---\n?)/, (block) => block.replace(/^status:\s*.*\n?/m, ''));
}

function frontmatter(text) {
	const match = text.match(/^---\n[\s\S]*?\n---\n?/);
	return match ? match[0] : '';
}

function headings(text) {
	return [...text.matchAll(/^#{1,6}\s+(.+?)\s*$/gm)].map((match) => match[1].trim().replace(/\s*[–—]\s*/g, ': ').replace(/:\s*$/, ':'));
}

function fencedBlocks(text) {
	const blocks = [];
	const lines = [...text.matchAll(/^.*(?:\n|$)/gm)];
	for (let i = 0; i < lines.length; i += 1) {
		const opening = lines[i][0].match(/^ {0,3}(`{3,}|~{3,})[^\n]*\n?$/);
		if (!opening) continue;
		const marker = opening[1];
		const character = marker[0];
		let end = i + 1;
		for (; end < lines.length; end += 1) {
			const closing = lines[end][0].match(new RegExp(`^ {0,3}${character}{${marker.length},}\\s*\\n?$`));
			if (closing) break;
		}
		const endIndex = end < lines.length ? lines[end].index + lines[end][0].length : text.length;
		blocks.push({ start: lines[i].index, end: endIndex, value: text.slice(lines[i].index, endIndex) });
		if (end < lines.length) i = end;
	}
	return blocks;
}

function maskRanges(text, ranges) {
	const masked = [...text];
	for (const range of ranges) for (let i = range.start; i < range.end; i += 1) if (masked[i] !== '\n') masked[i] = ' ';
	return masked.join('');
}

function sameMultiset(left, right) {
	if (left.length !== right.length) return false;
	const counts = new Map();
	for (const value of left) counts.set(value, (counts.get(value) ?? 0) + 1);
	for (const value of right) {
		const count = counts.get(value) ?? 0;
		if (!count) return false;
		if (count === 1) counts.delete(value);
		else counts.set(value, count - 1);
	}
	return counts.size === 0;
}

function tableShape(text) {
	const tables = [];
	let current = null;
	for (const line of text.split('\n')) {
		if (!/^\s*\|/.test(line)) {
			if (current) tables.push(current);
			current = null;
			continue;
		}
		const cells = line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').length;
		current ??= { rows: 0, columns: [] };
		current.rows += 1;
		current.columns.push(cells);
	}
	if (current) tables.push(current);
	return tables;
}

function protectedParts(raw) {
	const text = normalize(raw);
	const fences = fencedBlocks(text);
	const masked = maskRanges(text, fences);
	const inlineCode = [...masked.matchAll(/`[^`\n]+`/g)].map((match) => ({ index: match.index, value: text.slice(match.index, match.index + match[0].length) }));
  const code = fences.map(({ value }) => value);
	const destinations = [
		...[...text.matchAll(/!?\[[^\]\n]*\]\(([^)\n]+)\)/g)].map((match) => match[1].trim()),
		...[...text.matchAll(/^\s{0,3}\[[^\]\n]+\]:\s*(?:<([^>\n]+)>|(\S+))/gm)].map((match) => (match[1] ?? match[2]).trim()),
		...[...text.matchAll(/<((?:https?:|mailto:)[^>\n]+)>/gi)].map((match) => match[1]),
		...[...text.matchAll(/\b(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/gi)].map((match) => match[1] ?? match[2] ?? match[3]),
	];
	const labels = [...text.matchAll(/^[^\n]*$/gm)].filter(([line]) => LABEL.test(line)).map(([line]) => {
		const match = line.match(LABEL);
		return match[1].toLowerCase();
	});
	const tables = tableShape(masked);
	const ordered = text.split('\n').map((line) => line.match(/^\s*(\d+)[.)]\s+/)?.[1]).filter(Boolean);
	const attackPath = text.split('\n').filter((line) => /^\*\*Attack path:\*\*/i.test(line));
	const technical = text.match(/\bCVE-\d{4}-\d+\b|\b\d+(?:\.\d+){1,3}\b|(?<![\w])--[a-z][\w-]*|\b\d{2,5}\b/g) ?? [];
	return {
		frontmatter: withoutStatus(frontmatter(text)),
		headings: headings(text),
		code,
		destinations,
		labels,
		tables,
		ordered,
		attackPath,
		technical,
	};
}

function diffLines(before, after) {
	const left = normalize(before).split('\n');
	const right = normalize(after).split('\n');
	const lines = [];
	const max = Math.max(left.length, right.length);
	for (let i = 0; i < max; i += 1) if (left[i] !== right[i]) {
		if (left[i] !== undefined) lines.push(`- ${i + 1}: ${left[i]}`);
		if (right[i] !== undefined) lines.push(`+ ${i + 1}: ${right[i]}`);
	}
	return lines;
}

function compare(before, after, label) {
	const a = protectedParts(before);
	const b = protectedParts(after);
	const failures = [];
	for (const key of Object.keys(a)) {
		if (['destinations', 'technical'].includes(key)) {
			if (!sameMultiset(a[key], b[key])) failures.push(`${label}: protected ${key} changed`);
		} else if (key === 'headings') {
			if (JSON.stringify(a[key]) !== JSON.stringify(b[key])) failures.push(`${label}: heading sequence/text changed`);
		} else if (JSON.stringify(a[key]) !== JSON.stringify(b[key])) failures.push(`${label}: protected ${key} changed`);
	}
	return { failures, proseDiff: failures.length ? diffLines(before, after) : diffLines(withoutProtected(before), withoutProtected(after)) };
}

function withoutProtected(text) {
	let result = normalize(text);
	const fences = fencedBlocks(result);
	for (const { start, end } of [...fences].reverse()) result = result.slice(0, start) + result.slice(end);
	return result
		.replace(/^---\n[\s\S]*?\n---\n?/, '')
		.replace(/^#{1,6}\s+.*$/gm, '')
		.replace(/`[^`\n]+`/g, '')
		.replace(/^\s*\|.*$/gm, '')
		.replace(/^\s*\d+[.)]\s+.*$/gm, '')
		.replace(/^\*\*Attack path:\*\*.*$/gim, '')
		.replace(/^\s*(?:[*_]{0,2})(?:Observation|Action|Evidence|Significance|Result|Recommendation|Detection|Validation)(?:[*_]{0,2}):\s*/gim, '');
}

function allMarkdown(dir) {
		const found = [];
		for (const entry of readdirSync(dir, { withFileTypes: true })) {
			const path = resolve(dir, entry.name);
			if (entry.isDirectory()) found.push(...allMarkdown(path));
			else if (entry.isFile() && entry.name.endsWith('.md')) found.push(path);
		}
	return found;
}

function relativeMarkdownFiles(root) {
	return allMarkdown(root).map((file) => relative(root, file).split(sep).join('/'));
}

function draftForPublic(publicName, draftNames) {
	const matches = draftNames.filter((name) => name.split('/').pop() === publicName.split('/').pop());
	if (matches.length === 0) throw new Error(`draft missing for public file ${publicName} (basename ${publicName.split('/').pop()})`);
	if (matches.length > 1) throw new Error(`ambiguous draft basename for public file ${publicName}: ${matches.join(', ')}`);
	return matches[0];
}

function publicForDraft(draftName, publicNames) {
	const basename = draftName.split('/').pop();
	const matches = publicNames.filter((name) => name.split('/').pop() === basename);
	if (matches.length === 0) throw new Error(`public file missing for draft ${draftName} (basename ${basename})`);
	if (matches.length > 1) throw new Error(`ambiguous public basename for draft ${draftName}: ${matches.join(', ')}`);
	return matches[0];
}

function selectPublicFiles(files, publicNames) {
	if (!files) return publicNames;
	return files.map((selector) => {
		if (publicNames.includes(selector)) return selector;
		const matches = publicNames.filter((name) => name.split('/').pop() === selector);
		if (matches.length === 0) throw new Error(`public file not found: ${selector}`);
		if (matches.length > 1) throw new Error(`ambiguous public basename ${selector}: ${matches.join(', ')}`);
		return matches[0];
	});
}

function gitRoot(cwd) {
	return execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd, encoding: 'utf8' }).trim();
}

function gitFile(base, file, root) {
	const path = relative(root, file).split(sep).join('/');
	if (!path || path.startsWith('../') || path === '..') throw new Error(`file outside git root: ${file}`);
	try {
		return execFileSync('git', ['show', `${base}:${path}`], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
	} catch {
		throw new Error(`base file missing: ${path}`);
	}
}

function run(options, cwd = process.cwd()) {
	const draftRoot = resolve(cwd, options['draft-root']);
	const publicRoot = resolve(cwd, options['public-root']);
	if (!existsSync(draftRoot) || !existsSync(publicRoot)) throw new Error('draft/public root not found');
	const root = gitRoot(publicRoot);
	const publicNames = relativeMarkdownFiles(publicRoot);
	const draftNames = relativeMarkdownFiles(draftRoot);
	const files = options.files ? selectPublicFiles(options.files, publicNames) : draftNames.map((name) => publicForDraft(name, publicNames));
	if (!files.length) throw new Error('no markdown files selected');
	const failures = [];
	const prose = [];
	for (const name of files) {
		if (name.startsWith('/') || name.split(/[\\/]/).includes('..')) throw new Error(`unsafe file path: ${name}`);
		const draftName = draftForPublic(name, draftNames);
		const draft = resolve(draftRoot, draftName);
		const current = resolve(publicRoot, name);
		if (!existsSync(current)) throw new Error(`public file missing: ${name}`);
		const draftText = readFileSync(draft, 'utf8');
		const currentText = readFileSync(current, 'utf8');
		for (const result of [compare(gitFile(options.base, current, root), currentText, `${name} base`), compare(draftText, currentText, `${name} draft`)]) {
			failures.push(...result.failures);
			if (result.proseDiff.length) prose.push({ file: name, lines: result.proseDiff });
		}
	}
	return { ok: failures.length === 0, failures, prose };
}

function main() {
	try {
		const options = parseArgs(process.argv.slice(2));
		const result = run(options);
		if (options.json) console.log(JSON.stringify(result, null, 2));
		else {
			for (const failure of result.failures) console.error(`FAIL ${failure}`);
			for (const item of result.prose) console.log(`PROSE ${item.file}\n${item.lines.join('\n')}`);
			if (!result.failures.length && !result.prose.length) console.log('pass: protected content preserved');
		}
		if (options.strict && !result.ok) process.exitCode = 1;
	} catch (error) {
		console.error(`check-case-preservation: ${error.message}\n${usage()}`);
		process.exitCode = 2;
	}
}

export { compare, parseArgs, protectedParts, run };
if (import.meta.url === `file://${process.argv[1]}`) main();
