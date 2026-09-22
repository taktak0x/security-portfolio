#!/usr/bin/env node
// Content-regularity report for the portfolio.
//
// The defect this looks for is *excessive regularity*, not bad writing: the
// question is whether a page would still make sense after swapping out its
// technical nouns. It reads the source markdown directly (no build required)
// and uses only Node built-ins. The report is informational: exit code is 0
// by default. `--strict` applies structural policy gates to the same corpus.
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const corpusRoot = process.env.CHECK_CONTENT_ROOT ? resolve(process.env.CHECK_CONTENT_ROOT) : root;
const CORPUS_DIRS = [
	join(corpusRoot, 'src/content/docs/case-studies'),
	// The corpus is the case-study tree only. The `prolabs` and `profiles`
	// sections are deliberately excluded because their pages are short,
	// uniform or owner-authored narrative rather than case studies, so this
	// regularity report does not cover them.
];

// Thresholds that only matter under `--strict`.
const SIMILARITY_LIMIT = 0.35; // max nearest-neighbour 3-gram Jaccard
const STAGE_LABELS = /^[*_]{0,2}(?:Observation|Action|Evidence|Significance|Result|Recommendation|Detection|Validation|Truncated scan output)[*_]{0,2}:\s*/gim;

const ABSTRACT_VOCAB = [
	'structured', 'broader', 'strengthened', 'developed', 'disciplined', 'repeatable',
	'robust', 'approach', 'context', 'understanding', 'judgment', 'methodology',
	'value', 'leverage', 'utilize', 'demonstrate',
];
// Habitual abstractions from the editorial voice pass. This is a warn list, not a ban.
const HABITUAL_ABSTRACTIONS = [
	'structured', 'broader', 'strengthened', 'disciplined', 'repeatable',
	'methodology', 'comprehensive', 'robust', 'leverage', 'utilise', 'holistic',
	'seamless', 'landscape', 'realm', 'testament', 'pivotal', 'crucial', 'delve',
	'myriad', 'nuanced', 'multifaceted', 'underscore', 'showcase', 'foster',
	'streamline',
];
const UNCERTAINTY_MARKERS = [
	'expected', 'inferred', 'could not verify', 'not reproduced', 'reconstructed',
	'hypothesis', 'dead end', 'wrong', 'mistake', 'assumed',
];
const DECISION_VERBS = ['expected', 'tried', 'rejected', 'dropped', 'kept', 'assumed', 'checked'];

// --- Input helpers -----------------------------------------------------------

/** Recursively collect files under `dir` whose name matches `filter`. */
function walk(dir, filter) {
	const out = [];
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const full = join(dir, entry.name);
		if (entry.isDirectory()) out.push(...walk(full, filter));
		else if (entry.isFile() && filter(entry.name)) out.push(full);
	}
	return out;
}

function stripFrontmatter(text) {
	const opening = text.match(/^\uFEFF?---\r?\n/);
	if (!opening) return text;
	const closing = text.slice(opening[0].length).match(/^---[ \t]*\r?\n?/m);
	if (!closing) throw new Error('malformed or unterminated frontmatter');
	return text.slice(opening[0].length + closing.index + closing[0].length);
}

function stripCode(text) {
	const lines = text.replace(/\r\n?/g, '\n').split('\n');
	const output = [];
	let fence = null;

	for (const line of lines) {
		const match = line.match(/^ {0,3}(`{3,}|~{3,})(?:[^`~].*)?$/);
		if (!fence && match) {
			fence = { marker: match[1][0], length: match[1].length };
			output.push('');
			continue;
		}
		if (fence) {
			const close = line.match(new RegExp(`^ {0,3}(${fence.marker === '`' ? '`' : '~'}{${fence.length},})[ \\t]*$`));
			if (close) fence = null;
			continue;
		}
		output.push(line);
	}

	if (fence) throw new Error(`unterminated ${fence.marker === '`' ? 'backtick' : 'tilde'} fence`);
	return output.join('\n');
}

function stripTables(text) {
	return text.split('\n').filter((line) => !/^\s*\|/.test(line)).join('\n');
}

function stripReferencesSection(text) {
	return stripSection(text, /^##\s+References\s*$/i, 2);
}

function stripSection(text, heading, level) {
	const lines = text.split('\n');
	const start = lines.findIndex((line) => heading.test(line));
	if (start < 0) return text;
	const end = lines.findIndex((line, index) => index > start && new RegExp(`^#{1,${level}}\\s+`).test(line));
	return lines.slice(0, start).concat(end < 0 ? [] : lines.slice(end)).join('\n');
}

/** Turn markdown prose into plain prose: no headings, lists, links or tags. */
function stripMarkdown(text) {
	return text
		.replace(/^#{1,6}\s+.*$/gm, '')
		.replace(/<[^>]+>/g, ' ')
		.replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
		.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
		.replace(/`([^`]*)`/g, ' $1 ')
		.replace(/^\s*(?:[-*+]|\d+[.)])\s+/gm, '')
		.replace(/[*_>]/g, ' ');
}

function stripStartingPositionMetadata(text) {
	return text.replace(/^\s*Starting position:[ \t]+unauthenticated network access\b(?:,\s*(?:with\s+)?no provided credentials\b)?[.;]?/gim, '');
}

function stripLabEnvironmentMetadata(text) {
	return text.replace(/^\s*(?:Constraints?|Environment|Context):[^\n]*?\bHack The Box lab environment\b[.;,]?\s*/gim, '');
}

function stripAtAGlanceSection(text) {
	return stripSection(text, /^##\s+At a glance\s*$/i, 2);
}

function stripStageLabels(text) {
	return text.replace(STAGE_LABELS, '');
}

function analysisMarkdown(text) {
	return stripStageLabels(stripTables(stripAtAGlanceSection(stripReferencesSection(stripCode(stripFrontmatter(text))))));
}

function buildRecord(path, raw) {
	const body = stripFrontmatter(raw);
	const prose = stripLabEnvironmentMetadata(stripStartingPositionMetadata(stripMarkdown(analysisMarkdown(raw))));
	const tokens = words(prose);
	const headings = headingList(body);
	return {
		path,
		prose,
		tokens,
		shingles: shingles(tokens, 3),
		sentences: sentences(prose),
		paragraphs: paragraphs(prose),
		headings,
		headingKey: [...new Set(headings.map((h) => h.toLowerCase()))].sort().join('\n'),
		topHeadingKey: [...new Set(topHeadingList(body).map((h) => h.toLowerCase()))].sort().join('\n'),
		dashCount: (stripCode(stripReferencesSection(body)).match(/[–—]/g) ?? []).length,
	};
}

export { analysisMarkdown, buildRecord, stripAtAGlanceSection, stripCode, stripFrontmatter, stripReferencesSection, stripStageLabels, stripTables };

export function strictFailures({ maxSimilarity, pairs, zeroUncertainty, zeroDecisions, dashViolations, corpusErrors = [] }) {
	const failures = [];
	for (const error of corpusErrors) failures.push(`corpus error: ${error}`);
	if (maxSimilarity >= SIMILARITY_LIMIT) {
		failures.push(`maximum similarity ${maxSimilarity.toFixed(3)} >= ${SIMILARITY_LIMIT} (${pairs[0].a} <-> ${pairs[0].b})`);
	}
	if (zeroUncertainty.length > 0) failures.push(`zero uncertainty markers in ${zeroUncertainty.length} file(s)`);
	if (zeroDecisions.length > 0) failures.push(`zero first-person decision sentences in ${zeroDecisions.length} file(s)`);
	if (dashViolations.length > 0) failures.push(`em/en dash found in ${dashViolations.length} file(s)`);
	return failures;
}

function words(text) {
	return text.toLowerCase().match(/[a-z0-9]+(?:['-][a-z0-9]+)*/g) ?? [];
}

function shingles(tokens, size) {
	const set = new Set();
	for (let i = 0; i + size <= tokens.length; i += 1) set.add(tokens.slice(i, i + size).join(' '));
	return set;
}

function sentences(text) {
	return text
		.split(/(?<=[.!?])\s+/)
		.map((s) => s.trim())
		.filter((s) => s.length > 0);
}

function paragraphs(text) {
	return text
		.split(/\n\s*\n/)
		.map((p) => p.replace(/\s+/g, ' ').trim())
		.filter((p) => p.length > 0);
}

function headingList(text) {
	return [...text.matchAll(/^(#{2,3})\s+(.+?)\s*$/gm)].map((m) =>
		m[2].replace(/[*_`]/g, '').replace(/^\d+[.)]\s*/, '').trim(),
	);
}

/** Top-level `##` headings only, ignoring any `###` subheadings. */
function topHeadingList(text) {
	return [...text.matchAll(/^##\s+(.+?)\s*$/gm)].map((m) =>
		m[1].replace(/[*_`]/g, '').replace(/^\d+[.)]\s*/, '').trim(),
	);
}

function openingPattern(paragraph) {
	const label = paragraph.match(/^([A-Za-z][A-Za-z -]{2,24}):/);
	if (label) return `${label[1].trim().toLowerCase()}:`;
	const first = paragraph.match(/^[A-Za-z']+/);
	return first ? first[0].toLowerCase() : '';
}

// --- Build the corpus --------------------------------------------------------

function main() {
	const strict = process.argv.includes('--strict');
	for (const dir of CORPUS_DIRS) {
		if (!existsSync(dir)) {
			console.error(`check-content: corpus directory not found: ${relative(root, dir)}`);
			process.exit(1);
		}
	}

// Index pages are excluded for the same reason as the `prolabs` and `profiles`
// sections: they are short, uniform navigation pages rather than case studies, so
// including them distorts every corpus-level statistic (similarity, boilerplate
// frequency, uncertainty markers) against a corpus of 70 leaf case studies.
const files = [...new Set(CORPUS_DIRS.flatMap((dir) => walk(dir, (name) => name.endsWith('.md') && name !== 'index.md')))].sort();

const records = files.map((file) => {
	return buildRecord(relative(root, file), readFileSync(file, 'utf-8'));
});

const lines = [];
const corpusErrors = strict && files.length === 0 ? ['empty case-study corpus'] : [];
const log = (line = '') => lines.push(line);
const pct = (n, d) => (d === 0 ? '0.0' : ((100 * n) / d).toFixed(1));
const title = (text) => log(`\n== ${text} ==`);

log(`check-content: ${records.length} file(s) analysed (case-studies/**)`);
log(`mode: ${strict ? 'strict' : 'report'} (informational${strict ? '' : '; exit 0 always'})`);

// --- 1. Cross-file similarity ------------------------------------------------

const pairs = [];
for (let i = 0; i < records.length; i += 1) {
	for (let j = i + 1; j < records.length; j += 1) {
		const a = records[i];
		const b = records[j];
		const union = a.shingles.size + b.shingles.size;
		if (union === 0) continue;
		let intersection = 0;
		for (const shingle of a.shingles) if (b.shingles.has(shingle)) intersection += 1;
		const score = intersection / (union - intersection);
		if (score > 0) pairs.push({ a: a.path, b: b.path, score });
	}
}
pairs.sort((x, y) => y.score - x.score || x.a.localeCompare(y.a) || x.b.localeCompare(y.b));

const nearest = new Map(records.map((r) => [r.path, 0]));
for (const pair of pairs) {
	nearest.set(pair.a, Math.max(nearest.get(pair.a), pair.score));
	nearest.set(pair.b, Math.max(nearest.get(pair.b), pair.score));
}
const maxSimilarity = pairs.length > 0 ? pairs[0].score : 0;
const meanNearest = records.length === 0 ? 0 : [...nearest.values()].reduce((s, v) => s + v, 0) / records.length;

title('1. Cross-file similarity (3-gram Jaccard)');
log(`maximum pairwise similarity: ${maxSimilarity.toFixed(3)}`);
log(`mean nearest-neighbour similarity: ${meanNearest.toFixed(3)}`);
log('most similar pairs:');
for (const pair of pairs.slice(0, 15)) {
	log(`  ${pair.score.toFixed(3)}  ${pair.a}  <->  ${pair.b}`);
}

// --- 2. Repeated phrases (boilerplate detector) ------------------------------

const phraseMap = new Map();
for (const record of records) {
	for (let size = 3; size <= 6; size += 1) {
		for (let i = 0; i + size <= record.tokens.length; i += 1) {
			const phrase = record.tokens.slice(i, i + size).join(' ');
			if (!phraseMap.has(phrase)) phraseMap.set(phrase, { count: 0, files: new Set() });
			const entry = phraseMap.get(phrase);
			entry.count += 1;
			entry.files.add(record.path);
		}
	}
}
const phrases = [...phraseMap.entries()]
	.filter(([, entry]) => entry.files.size >= 3)
	.map(([phrase, entry]) => ({ phrase, count: entry.count, files: [...entry.files].sort() }))
	.sort((x, y) => y.files.length - x.files.length || y.count - x.count || x.phrase.localeCompare(y.phrase));

title('2. Boilerplate phrases (3-6 words, in >= 3 files)');
log(`distinct repeated phrases: ${phrases.length}`);
for (const phrase of phrases.slice(0, 25)) {
	const filesShown = phrase.files.length > 6 ? `${phrase.files.slice(0, 5).join(', ')}, +${phrase.files.length - 5} more` : phrase.files.join(', ');
	log(`  x${phrase.count} in ${phrase.files.length} file(s): "${phrase.phrase}"`);
	log(`      ${filesShown}`);
}

// --- 3. Sentence-length distribution -----------------------------------------

const lengths = records.flatMap((r) => r.sentences.map((s) => words(s).length));
const corpusMean = lengths.length === 0 ? 0 : lengths.reduce((s, n) => s + n, 0) / lengths.length;
const distributions = records.map((record) => {
	const lens = record.sentences.map((s) => words(s).length);
	const mean = lens.length === 0 ? 0 : lens.reduce((s, n) => s + n, 0) / lens.length;
	const inBand = lens.filter((n) => Math.abs(n - corpusMean) <= 5).length;
	return {
		path: record.path,
		count: lens.length,
		mean,
		min: lens.length === 0 ? 0 : Math.min(...lens),
		max: lens.length === 0 ? 0 : Math.max(...lens),
		inBandShare: lens.length === 0 ? 0 : inBand / lens.length,
	};
}).sort((x, y) => y.inBandShare - x.inBandShare || x.path.localeCompare(y.path));

title('3. Sentence-length distribution (flattest first)');
log(`corpus mean sentence length: ${corpusMean.toFixed(1)} words; share within +/-5 words of the mean shown per file`);
for (const d of distributions) {
	log(`  ${pct(d.inBandShare * d.count, d.count).padStart(5)}% in-band  mean ${d.mean.toFixed(1)}  min ${d.min}  max ${d.max}  (${d.count} sents)  ${d.path}`);
}

// --- 4. Paragraph-opening patterns -------------------------------------------

const patternCounts = new Map();
let totalParagraphs = 0;
const perFilePatterns = records.map((record) => {
	const counts = new Map();
	for (const paragraph of record.paragraphs) {
		const pattern = openingPattern(paragraph);
		if (!pattern) continue;
		totalParagraphs += 1;
		patternCounts.set(pattern, (patternCounts.get(pattern) ?? 0) + 1);
		counts.set(pattern, (counts.get(pattern) ?? 0) + 1);
	}
	const total = [...counts.values()].reduce((s, n) => s + n, 0);
	const [top] = [...counts.entries()].sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]));
	return { path: record.path, total, pattern: top ? top[0] : '', share: top && total > 0 ? top[1] / total : 0 };
}).sort((x, y) => y.share - x.share || x.path.localeCompare(y.path));

title('4. Paragraph-opening patterns');
log(`corpus: ${totalParagraphs} paragraph(s) across ${records.length} file(s)`);
for (const [pattern, count] of [...patternCounts.entries()].sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0])).slice(0, 15)) {
	log(`  ${pct(count, totalParagraphs).padStart(5)}%  ${count}x  "${pattern}"`);
}
log('files whose paragraphs open with a single pattern most often:');
for (const f of perFilePatterns.slice(0, 15)) {
	log(`  ${pct(f.share * f.total, f.total).padStart(5)}%  "${f.pattern}"  (${f.total} paras)  ${f.path}`);
}

// --- 5. Heading duplication ---------------------------------------------------

const headingGroups = new Map();
for (const record of records) {
	if (!record.headingKey) continue;
	if (!headingGroups.has(record.headingKey)) headingGroups.set(record.headingKey, []);
	headingGroups.get(record.headingKey).push(record.path);
}
const sharedHeadings = [...headingGroups.entries()]
	.filter(([, filesInGroup]) => filesInGroup.length >= 2)
	.map(([key, filesInGroup]) => ({ headings: key.split('\n'), files: filesInGroup.sort() }))
	.sort((x, y) => y.files.length - x.files.length || x.headings.join().localeCompare(y.headings.join()));

title('5. Heading duplication (identical ##/### sets)');
log(`groups of files sharing an identical heading set: ${sharedHeadings.length}`);
for (const group of sharedHeadings.slice(0, 15)) {
	log(`  ${group.files.length} file(s): [${group.headings.join(' | ')}]`);
	log(`      ${group.files.join(', ')}`);
}

// --- 5b. Top-level heading duplication (## only) ------------------------------
//
// Section 5 combines `##` and `###`, so unique numbered subheadings mask the
// shared top-level template. This block groups by `##` headings alone to make
// that universal structure visible.

const topHeadingGroups = new Map();
for (const record of records) {
	if (!record.topHeadingKey) continue;
	if (!topHeadingGroups.has(record.topHeadingKey)) topHeadingGroups.set(record.topHeadingKey, []);
	topHeadingGroups.get(record.topHeadingKey).push(record.path);
}
const topHeadingSets = [...topHeadingGroups.entries()]
	.map(([key, filesInGroup]) => ({ headings: key.split('\n'), files: filesInGroup.sort() }))
	.sort((x, y) => y.files.length - x.files.length || x.headings.join().localeCompare(y.headings.join()));

title('5b. Heading duplication (top-level ## only, ### ignored)');
log(`distinct top-level ## heading groups: ${topHeadingSets.length}`);
for (const group of topHeadingSets) {
	log(`  ${group.files.length} file(s): [${group.headings.join(' | ')}]`);
	log(`      ${group.files.join(', ')}`);
}
const withTopHeadings = records.filter((record) => record.topHeadingKey).length;
const [largestTopGroup] = topHeadingSets;
if (largestTopGroup && largestTopGroup.files.length === withTopHeadings && withTopHeadings > 0) {
	log(`** all ${withTopHeadings} analysed file(s) that declare top-level ## headings share ONE identical set — the top-level template is universal, not absent. **`);
	if (withTopHeadings < records.length) {
		log(`   (${records.length - withTopHeadings} analysed file(s) declare no ## headings and are excluded above.)`);
	}
}

// --- 6. Abstract vocabulary ---------------------------------------------------

const abstractTotals = new Map(ABSTRACT_VOCAB.map((term) => [term, 0]));
const abstractPerFile = records.map((record) => {
	const lowered = record.prose.toLowerCase();
	const counts = new Map();
	let total = 0;
	for (const term of ABSTRACT_VOCAB) {
		const re = new RegExp(`\\b${term}\\b`, 'g');
		const n = (lowered.match(re) ?? []).length;
		if (n > 0) counts.set(term, n);
		abstractTotals.set(term, abstractTotals.get(term) + n);
		total += n;
	}
	return { path: record.path, total, counts };
}).sort((x, y) => y.total - x.total || x.path.localeCompare(y.path));

title('6. Abstract-vocabulary frequency');
log(`corpus totals: ${[...abstractTotals.entries()].filter(([, n]) => n > 0).sort((x, y) => y[1] - x[1]).map(([t, n]) => `${t} ${n}`).join(', ') || 'none'}`);
for (const f of abstractPerFile.filter((f) => f.total > 0).slice(0, 15)) {
	log(`  ${String(f.total).padStart(3)}  ${f.path}  (${[...f.counts.entries()].map(([t, n]) => `${t} x${n}`).join(', ')})`);
}

// --- 7. Uncertainty and failure markers --------------------------------------

const uncertaintyPerFile = records.map((record) => {
	const lowered = record.prose.toLowerCase();
	let count = 0;
	const hits = new Map();
	for (const marker of UNCERTAINTY_MARKERS) {
		const n = (lowered.match(new RegExp(`\\b${marker}\\b`, 'g')) ?? []).length;
		if (n > 0) hits.set(marker, n);
		count += n;
	}
	return { path: record.path, count, hits };
}).sort((x, y) => x.count - y.count || x.path.localeCompare(y.path));

const zeroUncertainty = uncertaintyPerFile.filter((f) => f.count === 0).map((f) => f.path);

title('7. Uncertainty and failure markers');
log(`files with zero markers (immaculate retrospection): ${zeroUncertainty.length} of ${records.length}`);
for (const path of zeroUncertainty) log(`  - ${path}`);
log('lowest non-zero counts:');
for (const f of uncertaintyPerFile.filter((f) => f.count > 0).slice(0, 10)) {
	log(`  ${String(f.count).padStart(3)}  ${f.path}  (${[...f.hits.entries()].map(([m, n]) => `${m} x${n}`).join(', ')})`);
}

// --- 8. First-person decision sentences --------------------------------------

const decisionPerFile = records.map((record) => {
	const hits = record.sentences.filter((sentence) => {
		if (!/(^|\s)I\s/.test(sentence)) return false;
		return DECISION_VERBS.some((verb) => new RegExp(`\\b${verb}\\b`, 'i').test(sentence));
	});
	return { path: record.path, count: hits.length, examples: hits.slice(0, 1) };
}).sort((x, y) => x.count - y.count || x.path.localeCompare(y.path));

const zeroDecisions = decisionPerFile.filter((f) => f.count === 0).map((f) => f.path);

title('8. First-person decision sentences');
log(`files with no first-person decision sentence: ${zeroDecisions.length} of ${records.length}`);
for (const path of zeroDecisions) log(`  - ${path}`);
log('highest counts:');
for (const f of [...decisionPerFile].sort((x, y) => y.count - x.count || x.path.localeCompare(y.path)).slice(0, 10)) {
	log(`  ${String(f.count).padStart(3)}  ${f.path}${f.examples[0] ? `  e.g. "${f.examples[0]}"` : ''}`);
}

const dashViolations = records.filter((record) => record.dashCount > 0).map((record) => record.path);
title('8b. Forbidden em/en dashes');
log(`files containing em/en dashes in body prose, headings or tables: ${dashViolations.length}`);
for (const path of dashViolations) log(`  - ${path}`);

// --- 9. Habitual abstract vocabulary (warn list, not a ban) ------------------

const habitualTotals = new Map(HABITUAL_ABSTRACTIONS.map((term) => [term, 0]));
const habitualPerFile = records.map((record) => {
	const lowered = record.prose.toLowerCase();
	const counts = new Map();
	let total = 0;
	for (const term of HABITUAL_ABSTRACTIONS) {
		const n = (lowered.match(new RegExp(`\\b${term}\\b`, 'g')) ?? []).length;
		if (n > 0) counts.set(term, n);
		habitualTotals.set(term, habitualTotals.get(term) + n);
		total += n;
	}
	return { path: record.path, total, counts };
}).sort((x, y) => y.total - x.total || x.path.localeCompare(y.path));

title('9. Habitual abstract vocabulary (warn list, not a ban)');
log(`corpus totals: ${[...habitualTotals.entries()].filter(([, n]) => n > 0).sort((x, y) => y[1] - x[1]).map(([t, n]) => `${t} ${n}`).join(', ') || 'none'}`);
for (const f of habitualPerFile.filter((f) => f.total > 0)) {
	log(`  ${String(f.total).padStart(3)}  ${f.path}  (${[...f.counts.entries()].map(([t, n]) => `${t} x${n}`).join(', ')})`);
}

// --- Strict gate --------------------------------------------------------------

console.log(lines.join('\n'));

if (strict) {
	const failures = strictFailures({ maxSimilarity, pairs, zeroUncertainty, zeroDecisions, dashViolations, corpusErrors });
	if (failures.length > 0) {
		console.error(`check-content: strict failures (${failures.length}):`);
		for (const failure of failures) console.error(`  - ${failure}`);
		process.exit(1);
	}
	console.error('check-content: strict OK — policy gates not exceeded.');
}
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
	try {
		main();
	} catch (error) {
		console.error(`check-content: corpus or parsing error: ${error.message}`);
		process.exitCode = 1;
	}
}
