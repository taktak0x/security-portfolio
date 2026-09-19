// On-this-page table of contents. Server component: a plain, working list of
// the page's own H2/H3 headings. No ids here — the anchors target ids the
// rendered article owns.

type Heading = { depth: number; slug: string; text: string }

export function Toc({ headings }: { headings: Heading[] }) {
	const items = headings.filter((heading) => (heading.depth === 2 || heading.depth === 3) && heading.slug)
	if (items.length === 0) return null
	return (
		<nav aria-label="On this page" className="flex flex-col gap-3">
			<h2 className="m-0 font-mono text-[0.68rem] font-medium tracking-[0.08em] text-muted-foreground uppercase">
				On this page
			</h2>
			<ol className="m-0 flex list-none flex-col gap-1.5 p-0 text-sm">
				{items.map((heading) => (
					<li key={heading.slug} className={heading.depth === 3 ? "ms-4" : undefined}>
						<a
							href={`#${heading.slug}`}
							className="block rounded-[var(--portfolio-radius-sm)] px-2 py-1 text-muted-foreground no-underline hover:text-primary hover:underline focus-visible:text-primary focus-visible:underline"
						>
							{heading.text}
						</a>
					</li>
				))}
			</ol>
		</nav>
	)
}
