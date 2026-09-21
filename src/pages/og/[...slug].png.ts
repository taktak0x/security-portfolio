import { getCollection, type CollectionEntry } from 'astro:content';
import type { APIRoute } from 'astro';
import sharp from 'sharp';

const escapeXml = (value: string) =>
	value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const wrap = (value: string, limit: number) => {
	const words = value.split(/\s+/);
	const lines: string[] = [];
	let line = '';
	for (const word of words) {
		if ((line + ' ' + word).trim().length > limit && line) {
			lines.push(line);
			line = word;
		} else {
			line = `${line} ${word}`.trim();
		}
	}
	if (line) lines.push(line);
	return lines.slice(0, 3);
};

const category = (entry: CollectionEntry<'docs'>) => {
	const tags = (entry.data.tags ?? [])
		.filter((tag) => /^[a-z0-9][a-z0-9-]{0,23}$/i.test(tag))
		.slice(0, 3)
		.join(' · ');
	return [entry.data.platform, entry.data.content_type, tags].filter(Boolean).join(' · ');
};

export async function getStaticPaths() {
	const entries = await getCollection('docs', ({ data }) => data.type === 'case-study');
	return entries.map((entry) => ({
		params: { slug: entry.id },
		props: { entry },
	}));
}

export const GET: APIRoute = async ({ props }) => {
	const entry = props.entry as CollectionEntry<'docs'>;
	const titleLines = wrap(entry.data.title, 34);
	const label = category(entry);
	const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
<rect width="1200" height="630" fill="#fbf8f1"/>
<rect x="32" y="32" width="1136" height="566" rx="20" fill="#fff" stroke="#e2dace" stroke-width="3"/>
<path d="M32 508h1136" stroke="#e2dace" stroke-width="3"/>
<circle cx="1032" cy="126" r="72" fill="#f0e4dc"/>
<circle cx="1032" cy="126" r="40" fill="none" stroke="#7a3e2a" stroke-width="4"/>
<rect x="1008" y="102" width="48" height="48" rx="6" fill="none" stroke="#7a3e2a" stroke-width="4"/>
<text x="82" y="112" fill="#7a3e2a" font-family="monospace" font-size="24" font-weight="700" letter-spacing="3">TAKTAK.HU</text>
<text x="82" y="176" fill="#6b655c" font-family="monospace" font-size="22">SECURITY CASE STUDY</text>
${titleLines.map((line, index) => `<text x="82" y="${260 + index * 58}" fill="#1a1a17" font-family="Georgia, serif" font-size="48" font-weight="600">${escapeXml(line)}</text>`).join('')}
<text x="82" y="558" fill="#7a3e2a" font-family="monospace" font-size="22">${escapeXml(label)}</text>
</svg>`;

	const image = await sharp(Buffer.from(svg)).png().toBuffer();
	return new Response(image, { headers: { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=31536000, immutable' } });
};
