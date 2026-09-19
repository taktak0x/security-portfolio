#!/usr/bin/env node
// Build-time metadata checks for the generated static site in dist/.
// No dependencies: parses the Astro-generated HTML with targeted regexes.
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const distDir = join(root, 'dist');
const LANGS = /^[a-z]{2,3}(-[A-Za-z0-9]{1,8})*$/i;

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

/** All captured matches of a global regex in a string. */
function matches(source, regex) {
	return [...source.matchAll(regex)].map((match) => match[1] ?? '');
}

/** Extract an attribute value from an open-tag string. */
function attr(tag, name) {
	const match = tag.match(new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
	if (!match) return undefined;
	return match[2] ?? match[3] ?? match[4];
}

/** Classify rendered page markers used by Astro page archetypes. */
function pageKind(html) {
	const marker = html.match(/<(?:main|article)\b[^>]*\bdata-page\s*=\s*["']([^"']+)["']/i)?.[1];
	if (marker === 'case') return 'case';
	if (marker === 'collection-index') return 'collection-index';
	return 'other';
}

/** Infer required page markers from generated route shape and metadata. */
function expectedPageKind(rel, html) {
	const path = rel.split('\\').join('/');
	if (
		/^dist\/(?:case-studies\/htb\/(?:machines\/(?:linux|windows)|sherlocks\/(?:dfir|soc))|prolabs)\/index\.html$/i.test(path)
	) {
		return 'collection-index';
	}
	if (
		/^dist\/case-studies\/htb\/(?:machines\/(?:linux|windows)|sherlocks\/(?:dfir|soc))\/[^/]+\/index\.html$/i.test(path) ||
		/<meta\b[^>]*property\s*=\s*["']og:type["'][^>]*content\s*=\s*["']article["']/i.test(html) ||
		/<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>[\s\S]*?"@type"\s*:\s*"Article"/i.test(html)
	) {
		return 'case';
	}
	return undefined;
}

/** Resolve a URL pathname to a generated file under dist/, if any. */
function resolveDistFile(pathname) {
	const trimmed = pathname.replace(/\/+$/, '');
	const candidates = [
		join(distDir, pathname, 'index.html'),
		join(distDir, trimmed, 'index.html'),
		join(distDir, pathname),
		join(distDir, trimmed),
	];
	return [...new Set(candidates)].find((candidate) => existsSync(candidate) && statSync(candidate).isFile());
}

if (!existsSync(distDir)) {
	console.error('check-metadata: dist/ not found — run the build first.');
	process.exit(1);
}

const htmlFiles = walk(distDir, (name) => name.endsWith('.html')).sort();
const problems = [];
const warnings = [];
const titles = new Map();
const canonicals = new Map();
const descriptionsByContent = new Map();

for (const file of htmlFiles) {
	const rel = relative(root, file);
	const html = readFileSync(file, 'utf-8');
	const head = html.match(/<head\b[^>]*>([\s\S]*?)<\/head>/i)?.[1] ?? '';
	const isRedirect = /<meta\b[^>]*http-equiv\s*=\s*["']?refresh/i.test(html);
	const expectedKind = expectedPageKind(rel, html);
	const actualKind = pageKind(html);

	const titleMatches = matches(head, /<title\b[^>]*>([\s\S]*?)<\/title>/gi);
	const linkTags = [...head.matchAll(/<link\b[^>]*>/gi)].map((m) => m[0]);
	const canonicalTags = linkTags.filter((tag) => (attr(tag, 'rel') ?? '').toLowerCase() === 'canonical');

	// Astro redirect stubs are not content pages: they only need a title and a
	// canonical, and their redirect target must exist.
	if (isRedirect) {
		const stubTitles = matches(html, /<title\b[^>]*>([\s\S]*?)<\/title>/gi);
		const stubCanonicals = [...html.matchAll(/<link\b[^>]*>/gi)]
			.map((m) => m[0])
			.filter((tag) => (attr(tag, 'rel') ?? '').toLowerCase() === 'canonical');
		if (stubTitles.length !== 1) problems.push(`${rel}: redirect stub expected exactly one <title>, found ${stubTitles.length}`);
		if (stubCanonicals.length !== 1) problems.push(`${rel}: redirect stub expected exactly one <link rel="canonical">, found ${stubCanonicals.length}`);
		const refresh = [...html.matchAll(/<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>/gi)].map((m) => m[0])[0];
		const target = refresh ? (attr(refresh, 'content') ?? '').match(/url=(.+)$/i)?.[1] : undefined;
		if (!target) {
			problems.push(`${rel}: redirect stub has no parseable refresh target`);
		} else {
			let targetPath;
			try {
				targetPath = decodeURIComponent(new URL(target, 'https://example.invalid').pathname);
			} catch {
				targetPath = undefined;
			}
			if (!targetPath || !resolveDistFile(targetPath)) {
				problems.push(`${rel}: redirect target has no generated file in dist/: ${target}`);
			}
		}
		continue;
	}

	if (expectedKind && actualKind !== expectedKind) {
		problems.push(`${rel}: expected data-page="${expectedKind}", found ${actualKind === 'other' ? 'missing or unknown marker' : `"${actualKind}"`}`);
	}

	if (titleMatches.length !== 1) {
		problems.push(`${rel}: expected exactly one <title>, found ${titleMatches.length}`);
	} else {
		const title = titleMatches[0].trim();
		if (!title) problems.push(`${rel}: <title> is empty`);
		if (!titles.has(title)) titles.set(title, []);
		titles.get(title).push(rel);
	}

	if (canonicalTags.length !== 1) {
		problems.push(`${rel}: expected exactly one <link rel="canonical">, found ${canonicalTags.length}`);
	} else {
		const href = (attr(canonicalTags[0], 'href') ?? '').trim();
		if (!href) problems.push(`${rel}: canonical link is missing an href`);
		if (!canonicals.has(href)) canonicals.set(href, []);
		canonicals.get(href).push(rel);
	}

	const metaTags = [...head.matchAll(/<meta\b[^>]*>/gi)].map((m) => m[0]);
	const descriptions = metaTags.filter((tag) => (attr(tag, 'name') ?? '').toLowerCase() === 'description');
	const nonEmptyDescriptions = descriptions.filter((tag) => (attr(tag, 'content') ?? '').trim());
	// The 404 page does carry a description, but it is exempt from the normal
	// exactly-one requirement and from duplicate-description reporting below: it is
	// not indexable content and is not compared against real pages, and it is also
	// skipped by the sitemap coverage check. It is still checked for title,
	// canonical and lang. `rel` is project-root relative (e.g. "dist/404.html"),
	// so match on suffix.
	const is404 = rel.endsWith('404.html');
	if (!is404 && nonEmptyDescriptions.length !== 1) {
		problems.push(`${rel}: expected exactly one non-empty <meta name="description">, found ${nonEmptyDescriptions.length} (${descriptions.length} tag(s) total)`);
	}

	if (!is404 && nonEmptyDescriptions.length === 1) {
		const content = (attr(nonEmptyDescriptions[0], 'content') ?? '').trim();
		if (!descriptionsByContent.has(content)) descriptionsByContent.set(content, []);
		descriptionsByContent.get(content).push({ rel, pageKind: expectedKind ?? actualKind });
	}

	const h1s = matches(html, /<h1\b[^>]*>([\s\S]*?)<\/h1>/gi);
	if (h1s.length !== 1) {
		problems.push(`${rel}: expected exactly one <h1>, found ${h1s.length}`);
	}

	const htmlTag = html.match(/<html\b[^>]*>/i);
	const lang = htmlTag ? attr(htmlTag[0], 'lang') : undefined;
	if (!lang || !LANGS.test(lang.trim())) {
		problems.push(`${rel}: missing or invalid <html lang="..."> (${lang === undefined ? 'absent' : `"${lang}"`})`);
	}
}

for (const [title, files] of titles) {
	if (files.length > 1) problems.push(`duplicate <title> across pages: "${title}" in ${files.join(', ')}`);
}
for (const [href, files] of canonicals) {
	if (files.length > 1) problems.push(`duplicate canonical URL across pages: ${href} in ${files.join(', ')}`);
}

// Duplicate meta descriptions: identical summaries are a defect on case-study
// pages, where each investigation should describe itself. Index, prolabs and
// other pages may legitimately repeat a short description, so they only warn.
for (const [content, entries] of descriptionsByContent) {
	if (entries.length < 2) continue;
	const files = entries.map((entry) => entry.rel);
	const allCaseStudies = entries.every((entry) => entry.pageKind === 'case');
	const detail = `duplicate <meta name="description"> across pages: "${content}" in ${files.join(', ')}`;
	if (allCaseStudies) problems.push(`[case-study failure] ${detail}`);
	else warnings.push(`[warning] ${detail}`);
}

// --- Sitemap cross-check -----------------------------------------------------
const sitemapPath = join(distDir, 'sitemap-0.xml');
if (!existsSync(sitemapPath)) {
	problems.push('dist/sitemap-0.xml is missing');
} else {
	const locs = matches(readFileSync(sitemapPath, 'utf-8'), /<loc>\s*([^<]+?)\s*<\/loc>/gi);
	const sitemapPaths = new Set();
	for (const loc of locs) {
		let pathname;
		try {
			pathname = decodeURIComponent(new URL(loc).pathname);
		} catch {
			problems.push(`sitemap: invalid <loc> URL: ${loc}`);
			continue;
		}
		sitemapPaths.add(pathname.replace(/\/+$/, '') || '/');
		if (!resolveDistFile(pathname)) {
			problems.push(`sitemap: orphan <loc> has no generated file in dist/: ${loc}`);
		}
	}

	// Content pages absent from the sitemap. 404 and redirect stubs are exempt.
	for (const file of htmlFiles) {
		const rel = relative(distDir, file);
		if (rel === '404.html') continue;
		if (/<meta\b[^>]*http-equiv\s*=\s*["']?refresh/i.test(readFileSync(file, 'utf-8'))) continue;
		const dir = relative(distDir, join(file, '..')).split('\\').join('/');
		const pathname = dir === '.' ? '/' : `/${dir.replace(/\/+$/, '')}`;
		if (!sitemapPaths.has(pathname)) {
			problems.push(`sitemap: ${relative(root, file)} is generated but missing from the sitemap`);
		}
	}
}

if (warnings.length > 0) {
	console.warn(`check-metadata: ${warnings.length} non-fatal description warning(s):`);
	for (const warning of warnings) console.warn(`  - ${warning}`);
}

if (problems.length > 0) {
	console.error(`check-metadata: ${problems.length} problem(s) found in ${htmlFiles.length} HTML file(s):`);
	for (const problem of problems) console.error(`  - ${problem}`);
	process.exit(1);
}

const warningNote = warnings.length > 0 ? ` (${warnings.length} non-fatal description warning(s))` : '';
console.log(`check-metadata: OK — ${htmlFiles.length} HTML file(s) and the sitemap passed${warningNote}.`);
