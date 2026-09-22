import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import test from 'node:test';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { buildRecord, strictFailures } from './check-content.mjs';

const checker = join(import.meta.dirname, 'check-content.mjs');

const markdown = `---
title: "Ignored metadata"
---

## At a glance

| Field | Value |
|---|---|
| Objective | Repeated metadata |

## Summary

**Observation:** observed evidence survived.

\`\`\`text
code evidence and -- dash stay excluded
\`\`\`

Action: I checked the service. The result was expected.

## References

Repeated technical reference phrase.
`;

test('analysis corpus excludes frontmatter, code, at-a-glance, tables, references, and labels', () => {
	const record = buildRecord('fixture.md', markdown);
	assert.match(record.prose, /observed evidence survived/);
	assert.doesNotMatch(record.prose, /Ignored metadata|Repeated metadata|code evidence|Repeated technical/);
	assert.doesNotMatch(record.prose, /Observation:|Action:/);
});

test('section stripping excludes nested headings until next same-level heading', () => {
	const record = buildRecord('fixture.md', `${markdown}
## Outcome

Outcome survived.`.replace('## References\n\nRepeated technical reference phrase.', '## References\n\nReference removed.\n\n### Nested reference\n\nNested reference removed.'));
	assert.doesNotMatch(record.prose, /Reference removed|Nested reference removed/);
	assert.match(record.prose, /Outcome survived/);
});

test('frontmatter must be terminated', () => {
	assert.throws(() => buildRecord('fixture.md', '---\ntitle: broken\n\n## Summary\nBody'), /frontmatter/);
});

test('code stripping matches long fences, not shorter inner fences', () => {
	const record = buildRecord('fixture.md', markdown.replace('## References', `\`\`\`\`text
strict analysis must exclude this
\`\`\`
still excluded
\`\`\`\`

Visible prose.

## References`));
	assert.doesNotMatch(record.prose, /strict analysis|still excluded/);
	assert.match(record.prose, /Visible prose/);
});

test('code stripping matches long fences with CRLF line endings', () => {
	const source = markdown.replace('## References', `\`\`\`\`text
strict analysis must exclude this
\`\`\`
still excluded
\`\`\`\`

Visible prose.

## References`).replaceAll('\n', '\r\n');
	const record = buildRecord('fixture.md', source);
	assert.doesNotMatch(record.prose, /strict analysis|still excluded/);
	assert.match(record.prose, /Visible prose/);
});

test('dash policy excludes code but catches body prose', () => {
	const record = buildRecord('fixture.md', markdown.replace('Action: I checked', 'Action: I checked —'));
	assert.equal(buildRecord('fixture.md', markdown).dashCount, 0);
	assert.equal(record.dashCount, 1);
});

test('strict policy keeps generic repeated phrases report-only', () => {
	const failures = strictFailures({
		maxSimilarity: 0.1,
		pairs: [],
		zeroUncertainty: [],
		zeroDecisions: [],
		dashViolations: [],
	});
	assert.deepEqual(failures, []);
});

test('strict policy rejects high similarity, missing markers, and dashes', () => {
	const failures = strictFailures({
		maxSimilarity: 0.35,
		pairs: [{ a: 'one.md', b: 'two.md' }],
		zeroUncertainty: ['one.md'],
		zeroDecisions: ['two.md'],
		dashViolations: ['three.md'],
	});
	assert.equal(failures.length, 4);
	assert.match(failures[0], /maximum similarity/);
	assert.match(failures[1], /uncertainty/);
});

test('low similarity passes strict similarity gate', () => {
	const failures = strictFailures({
		maxSimilarity: 0.349,
		pairs: [{ a: 'one.md', b: 'two.md' }],
		zeroUncertainty: [],
		zeroDecisions: [],
		dashViolations: [],
	});
	assert.deepEqual(failures, []);
});

async function runChecker(files) {
	const root = await mkdtemp(join(tmpdir(), 'check-content-'));
	const directory = join(root, 'src/content/docs/case-studies');
	await mkdir(directory, { recursive: true });
	for (const [name, content] of Object.entries(files)) await writeFile(join(directory, name), content);
	const result = spawnSync(process.execPath, [checker, '--strict'], {
		env: { ...process.env, CHECK_CONTENT_ROOT: root },
		encoding: 'utf8',
	});
	await rm(root, { recursive: true, force: true });
	return result;
}

test('strict CLI rejects empty or index-only corpus with corpus error', async () => {
	const result = await runChecker({ 'index.md': '# Index only' });
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /corpus error.*empty case-study corpus/);
});

test('strict CLI rejects malformed frontmatter', async () => {
	const result = await runChecker({ 'broken.md': '---\ntitle: broken\n' });
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /corpus or parsing error: malformed or unterminated frontmatter/);
});

test('strict CLI rejects unterminated code fences', async () => {
	const result = await runChecker({ 'broken.md': '## Summary\n\n````text\nbody leaked into analysis' });
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /corpus or parsing error: unterminated backtick fence/);
});
