import { getCollection } from 'astro:content';
import { resolveCategory } from '../lib/category';

// Lightweight client-side search index for the site search dialog. Plain JSON,
// no dependency on any framework component. `category` uses shared case-page
// resolution; non-case entries are empty. `kind`/`label` are derived
// from the real route segment and frontmatter only, so the dialog can show what
// each result is without inventing metadata.
export async function GET() {
	const docs = await getCollection('docs');
	const items = docs.map((entry) => {
		const resolvedCategory = resolveCategory(entry.id);
		const category = resolvedCategory?.key ?? '';

		// The loader strips a trailing `/index` from `entry.id`, so index entries
		// are detected by filename, the same way `[...slug].astro` does.
		const isIndex =
			(entry.filePath ?? '')
				.replace(/\\/g, '/')
				.split('/')
				.pop()
				?.replace(/\.(md|mdx)$/, '') === 'index';

		const top = entry.id.split('/')[0];
		let kind = 'page';
		let label = '';
		if (top === 'case-studies') {
			if (isIndex) {
				kind = 'collection';
				label = 'Collection';
			} else if (entry.data.content_type === 'sherlock') {
				kind = 'case-study';
				label = `${resolvedCategory?.label} investigation`;
			} else {
				kind = 'case-study';
				label = `${resolvedCategory?.label} machine`;
			}
		} else if (top === 'prolabs') {
			if (isIndex) {
				kind = 'collection';
				label = 'Pro Labs';
			} else {
				kind = 'credential';
				label = 'Credential';
			}
		} else if (top === 'profiles') {
			kind = 'profile';
			label = 'Profile';
		} else if (top === 'method') {
			kind = 'method';
			label = 'Method';
		}

		return {
			id: entry.id,
			href: '/' + entry.id.replace(/\/index$/, '') + '/',
			title: entry.data.title,
			description: entry.data.description,
			objective: entry.data.objective,
			tags: entry.data.tags ?? [],
			tools: entry.data.tools ?? [],
			skill: entry.data.skill,
			outcome: entry.data.outcome,
			category,
			kind,
			label,
		};
	});
	return new Response(JSON.stringify(items), {
		headers: { 'content-type': 'application/json' },
	});
}
