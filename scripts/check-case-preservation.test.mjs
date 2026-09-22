import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { compare, run } from './check-case-preservation.mjs';

const page = (body, status = 'draft') => `---\ntitle: Test\nstatus: ${status}\ntags: [x]\n---\n\n## Summary\n\n${body}\n\n**Attack path:** **scan → shell**\n\n## References\n\n[guide](https://example.test/guide)\n`;

function fixture(baseBody, draftBody, baseStatus = 'published-ready') {
	const root = mkdtempSync(join(tmpdir(), 'case-preservation-'));
	const draftRoot = join(root, 'draft');
	const publicRoot = join(root, 'public');
	mkdirSync(draftRoot); mkdirSync(publicRoot);
	writeFileSync(join(draftRoot, 'case.md'), page(draftBody));
	writeFileSync(join(publicRoot, 'case.md'), page(baseBody, baseStatus));
	return { root, draftRoot, publicRoot };
}

function gitFixture(f) {
	execFileSync('git', ['init', '-q'], { cwd: f.root });
	execFileSync('git', ['config', 'user.email', 'test@example.test'], { cwd: f.root });
	execFileSync('git', ['config', 'user.name', 'Test'], { cwd: f.root });
	execFileSync('git', ['add', '.'], { cwd: f.root });
	execFileSync('git', ['commit', '-qm', 'fixture'], { cwd: f.root });
	return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: f.root, encoding: 'utf8' }).trim();
}

function result(base, draft, current) {
	return compare(page(base, 'published-ready'), page(current, 'published-ready'), 'case base').failures
		.concat(compare(page(draft), page(current, 'published-ready'), 'case draft').failures);
}

test('status-only change passes', () => assert.deepEqual(result('same', 'same', 'same'), []));
test('prose-only change passes and reports prose', () => {
	const check = compare(page('old'), page('new', 'published-ready'), 'case');
	assert.deepEqual(check.failures, []);
	assert.ok(check.proseDiff.length);
});
test('stage label change fails preservation', () => {
	const check = compare(page('Observation: old'), page('Observation: new', 'published-ready'), 'case');
	assert.deepEqual(check.failures, []);
});

test('stage label loss fails preservation', () => {
	const check = compare(page('Observation: old'), page('old', 'published-ready'), 'case');
	assert.match(check.failures.join('\n'), /protected labels/);
});

for (const [name, body] of [
	['heading', 'same\n\n### Changed'],
  ['code', 'same\n\n```text\nchanged\n```'],
	['link', 'same\n\n[guide](https://other.test)'],
	['reference link', 'same\n\n[guide][docs]\n\n[docs]: https://other.test/docs'],
	['autolink', 'same\n\n<https://other.test>'],
	['numeric token', 'same on 9090'],
]) test(`protected ${name} fails`, () => {
	const failures = result('same', 'same', body);
	assert.ok(failures.length, failures);
});

test('four-backtick fences protect content through matching close', () => {
	const before = '````md\nold\n```\nnew\n````\n';
	const after = '````md\nold\n```\nchanged\n````\n';
	assert.match(compare(before, after, 'case').failures.join('\n'), /protected code/);
});

test('inline-code prose edits do not create protected-code residuals', () => {
  assert.deepEqual(compare('Result: `old`\n', 'Result: `new`\n', 'case').failures, []);
});

test('unterminated fences protect content through EOF', () => {
	const before = '```md\nold\n';
	const after = '```md\nchanged\n';
	assert.match(compare(before, after, 'case').failures.join('\n'), /protected code/);
});

test('reference and autolink target mutations fail', () => {
	const before = '[guide][docs]\n\n[docs]: https://example.test/old\n\n<https://example.test/old>\n';
	const after = '[guide][docs]\n\n[docs]: https://example.test/new\n\n<https://example.test/new>\n';
	assert.match(compare(before, after, 'case').failures.join('\n'), /protected destinations/);
});

test('raw HTML href and src target mutations fail', () => {
	const before = '<a href="/old">guide</a>\n<img src=\'/old.png\'>\n';
	const after = '<a href="/new">guide</a>\n<img src=\'/new.png\'>\n';
	assert.match(compare(before, after, 'case').failures.join('\n'), /protected destinations/);
});

test('destinations and technical tokens may reorder but not disappear', () => {
	const before = '[one](https://example.test/one) 9090\n\n[two](https://example.test/two) 443\n';
	const reordered = '[two](https://example.test/two) 443\n\n[one](https://example.test/one) 9090\n';
	assert.deepEqual(compare(before, reordered, 'case').failures, []);
	assert.match(compare(before, '[one](https://example.test/one) 9090\n', 'case').failures.join('\n'), /protected destinations/);
	assert.match(compare(before, '[one](https://example.test/one) 9090\n\n[two](https://example.test/two) 80\n', 'case').failures.join('\n'), /protected technical/);
});

test('table and ordered-list prose may reorder but structure cannot change', () => {
	const before = '| A | B |\n|---|---|\n| one | two |\n\n1. first\n2. second\n';
	const reordered = '| B | A |\n|---|---|\n| two | one |\n\n1. second\n2. first\n';
	assert.deepEqual(compare(before, reordered, 'case').failures, []);
	assert.match(compare(before, '| A | B |\n|---|---|\n| one |\n', 'case').failures.join('\n'), /protected tables/);
	assert.match(compare(before, '| A | B |\n|---|---|\n| one |\n\n1. first\n', 'case').failures.join('\n'), /protected tables|protected ordered/);
});

test('frontmatter change fails while status-only change passes', () => {
	const check = compare(page('same', 'draft'), page('same', 'published-ready').replace('tags: [x]', 'tags: [y]'), 'case');
	assert.match(check.failures[0], /frontmatter/);
});

test('heading dash normalization is permitted', () => {
	assert.deepEqual(compare('## One — Two\n', '## One: Two\n', 'case').failures, []);
});

test('base loss is detected through git base', () => {
  const f = fixture('same\n\n```text\nkeep\n```', 'same\n\n```text\nkeep\n```');
  writeFileSync(join(f.publicRoot, 'case.md'), page('same', 'published-ready'));
	execFileSync('git', ['init', '-q'], { cwd: f.root });
	execFileSync('git', ['config', 'user.email', 'test@example.test'], { cwd: f.root });
	execFileSync('git', ['config', 'user.name', 'Test'], { cwd: f.root });
	execFileSync('git', ['add', '.'], { cwd: f.root });
	execFileSync('git', ['commit', '-qm', 'fixture'], { cwd: f.root });
	const base = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: f.root, encoding: 'utf8' }).trim();
	writeFileSync(join(f.publicRoot, 'case.md'), page('same'));
	const check = run({ base, 'draft-root': f.draftRoot, 'public-root': f.publicRoot, files: ['case.md'] }, f.root);
	assert.match(check.failures.join('\n'), /protected code/);
	rmSync(f.root, { recursive: true, force: true });
});

test('nested public path maps to flat draft basename', () => {
	const f = fixture('same', 'same');
	mkdirSync(join(f.publicRoot, 'htb', 'machines'), { recursive: true });
	writeFileSync(join(f.publicRoot, 'htb', 'machines', 'case.md'), page('same', 'published-ready'));
	rmSync(join(f.publicRoot, 'case.md'));
	const base = gitFixture(f);
	assert.deepEqual(run({ base, 'draft-root': f.draftRoot, 'public-root': f.publicRoot }, f.root).failures, []);
	assert.deepEqual(run({ base, 'draft-root': f.draftRoot, 'public-root': f.publicRoot, files: ['htb/machines/case.md'] }, f.root).failures, []);
	assert.deepEqual(run({ base, 'draft-root': f.draftRoot, 'public-root': f.publicRoot, files: ['case.md'] }, f.root).failures, []);
	rmSync(f.root, { recursive: true, force: true });
});

test('missing draft basename fails with actionable error', () => {
	const f = fixture('same', 'same');
	rmSync(join(f.draftRoot, 'case.md'));
	const base = gitFixture(f);
	assert.throws(() => run({ base, 'draft-root': f.draftRoot, 'public-root': f.publicRoot, files: ['case.md'] }, f.root), /draft missing for public file case\.md.*basename case\.md/);
	rmSync(f.root, { recursive: true, force: true });
});

test('ambiguous draft basename fails with actionable error', () => {
	const f = fixture('same', 'same');
	mkdirSync(join(f.draftRoot, 'nested'));
	writeFileSync(join(f.draftRoot, 'nested', 'case.md'), page('same'));
	const base = gitFixture(f);
	assert.throws(() => run({ base, 'draft-root': f.draftRoot, 'public-root': f.publicRoot, files: ['case.md'] }, f.root), /ambiguous draft basename for public file case\.md:.*case\.md.*nested\/case\.md/);
	rmSync(f.root, { recursive: true, force: true });
});
