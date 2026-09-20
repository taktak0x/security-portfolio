import { defineCollection } from 'astro:content';
import type { LoaderContext } from 'astro/loaders';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
import { z } from 'astro/zod';

const baseDocsLoader = docsLoader();

// Shared ISO date validation for frontmatter dates. All fields are optional:
// existing content carries none of them and must keep building unchanged.
const isoDate = (field: string) =>
	z
		.string()
		.regex(/^\d{4}-\d{2}-\d{2}$/, `${field} must be ISO YYYY-MM-DD`)
		.refine((value) => {
			const [year, month, day] = value.split('-').map(Number);
			const date = new Date(Date.UTC(year, month - 1, day));
			return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
		}, `${field} must be a valid calendar date`)
		.refine((value) => value <= new Date().toISOString().slice(0, 10), `${field} cannot be in the future`)
		.optional();

// Starlight validates frontmatter only, so its schema never sees the source
// path. Surface the entry path (attached before validation) to the schema below
// so it can check that a machine's OS directory agrees with its `tags`.
const docsLoaderWithPath = {
	...baseDocsLoader,
	load: (context: LoaderContext) =>
		baseDocsLoader.load({
			...context,
			parseData: ({ id, data, filePath }) =>
				context.parseData({ id, data: { ...data, _filePath: filePath }, filePath }),
		}),
};

export const collections = {
	docs: defineCollection({
		loader: docsLoaderWithPath,
		schema: docsSchema({
			extend: z.object({
				type: z.string().optional(),
				platform: z.string().optional(),
				status: z.string().optional(),
				content_type: z.string().optional(),
				blog_type: z.enum(['analysis', 'note', 'briefing']).optional(),
				category: z.string().optional(),
				published: isoDate('published'),
				updated: isoDate('updated'),
				telemetry: z.array(z.string()).optional(),
				defensive_analysis: z.boolean().optional(),
				references_verified: z.boolean().optional(),
				research_status: z.string().optional(),
				// Optional concise browser/search title; falls back to `title` when absent.
				seoTitle: z.string().optional(),
				tags: z.array(z.string()).optional(),
				objective: z.string().optional(),
				tools: z.array(z.string()).optional(),
				skill: z.string().optional(),
				outcome: z.string().optional(),
				// Injected by `docsLoaderWithPath`; not authored in frontmatter.
				_filePath: z.string().optional(),
				// Immutable portfolio-addition date (not completion or last-edit).
				addedAt: isoDate('addedAt'),
				// Optional provenance metadata. All fields are opt-in; no content file
				// sets them yet, so the schema stays backward compatible.
				author: z.string().optional(),
				publishedAt: isoDate('publishedAt'),
				updatedAt: isoDate('updatedAt'),
				evidenceQuality: z
					.enum(['original-artifacts', 'partial-artifacts', 'reconstructed-from-notes'])
					.optional(),
				aiAssistance: z.enum(['none', 'copy-editing', 'research-assist', 'other']).optional(),
				featured: z.boolean().default(false),
				featuredOrder: z.number().optional(),
				featuredReason: z.string().optional(),
				// Hero image asset; every subfield is optional.
				heroEvidence: z
					.object({
						path: z.string().optional(),
						alt: z.string().optional(),
						caption: z.string().optional(),
					})
					.optional(),
				// External sources; every subfield is optional.
				references: z
					.array(
						z.object({
							title: z.string().optional(),
							url: z.url({ protocol: /^https?$/ }).optional(),
							publisher: z.string().optional(),
						}),
					)
					.optional(),
			}).superRefine((data, ctx) => {
				const filePath = (data._filePath ?? '').split('\\').join('/');
				const docsPath = filePath.split('/src/content/docs/')[1] ?? '';
				const section = docsPath.split('/')[0];
				if ((section === 'blog' || section === 'lab') && data.type !== section) {
					ctx.addIssue({
						code: 'custom',
						path: ['type'],
						message: `Entries under ${section}/ must declare type: ${section}`,
					});
				}
				if (data.blog_type !== undefined && data.type !== 'blog') {
					ctx.addIssue({ code: 'custom', path: ['blog_type'], message: 'Only valid for blog entries' });
				}
				if (data.research_status !== undefined && data.type !== 'lab') {
					ctx.addIssue({ code: 'custom', path: ['research_status'], message: 'Only valid for lab entries' });
				}
				if (data.type === undefined && data.content_type === undefined) return;

				if (data.type === 'blog' || data.type === 'lab') {
					if (data.content_type !== undefined) {
						ctx.addIssue({ code: 'custom', path: ['content_type'], message: 'Not valid for blog or lab entries' });
					}
					const section = data.type === 'blog' ? 'blog' : 'lab';
					if (docsPath !== section && !docsPath.startsWith(`${section}/`)) {
						ctx.addIssue({ code: 'custom', path: ['type'], message: `${data.type} entries must live under ${section}/` });
					}
					return;
				}

				if (data.type !== 'case-study') {
					ctx.addIssue({ code: 'custom', path: ['type'], message: 'Must be case-study' });
				}
				if (!data.platform?.trim()) {
					ctx.addIssue({ code: 'custom', path: ['platform'], message: 'Required' });
				}
				if (data.content_type !== 'machine' && data.content_type !== 'sherlock') {
					ctx.addIssue({ code: 'custom', path: ['content_type'], message: 'Invalid case-study content type' });
				}
				if (data.status !== 'published-ready') {
					ctx.addIssue({ code: 'custom', path: ['status'], message: 'Must be published-ready' });
				}
				if (!data.tags?.length || data.tags.some((tag) => !tag.trim())) {
					ctx.addIssue({ code: 'custom', path: ['tags'], message: 'Must contain nonempty tags' });
				}
				if (!data.description?.trim()) {
					ctx.addIssue({ code: 'custom', path: ['description'], message: 'Required' });
				}

				const windowsDir = filePath.includes('/machines/windows/');
				const linuxDir = filePath.includes('/machines/linux/');
				const machinePath = /\/case-studies\/htb\/machines\/(windows|linux)\//.test(filePath);
				const sherlockPath = /\/case-studies\/htb\/sherlocks\/(dfir|soc)\//.test(filePath);
				if (data.content_type === 'machine' && !machinePath) {
					ctx.addIssue({ code: 'custom', path: ['content_type'], message: 'Machine entries must live under case-studies/htb/machines/{windows|linux}/' });
				}
				if (data.content_type === 'sherlock' && !sherlockPath) {
					ctx.addIssue({ code: 'custom', path: ['content_type'], message: 'Sherlock entries must live under case-studies/htb/sherlocks/{dfir|soc}/' });
				}
				const relativePath = filePath.includes('/src/') ? filePath.slice(filePath.indexOf('/src/') + 1) : filePath || 'unknown file';
				if (windowsDir && data.tags?.includes('linux')) {
					ctx.addIssue({
						code: 'custom',
						path: ['tags'],
						message: `Machine under machines/windows/ cannot be tagged linux: move ${relativePath} to machines/linux/ or fix its tags`,
					});
				}
				if (linuxDir && data.tags?.includes('windows')) {
					ctx.addIssue({
						code: 'custom',
						path: ['tags'],
						message: `Machine under machines/linux/ cannot be tagged windows: move ${relativePath} to machines/windows/ or fix its tags`,
					});
				}
			}),
		}),
	}),
};
