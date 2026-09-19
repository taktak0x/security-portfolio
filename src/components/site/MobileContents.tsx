type Heading = { depth: number; slug: string; text: string }

type Props = {
	headings: Heading[]
	depths?: readonly number[]
	ariaLabel?: string
}

export function MobileContents({
	headings,
	depths = [2, 3],
	ariaLabel = 'Page contents',
}: Props) {
	const items = headings.filter(
		(heading) => depths.includes(heading.depth) && heading.slug,
	)
	if (items.length === 0) return null

	return (
		<div className="pb-6 xl:hidden">
			<details className="rounded-[var(--portfolio-radius)] border border-border bg-card">
				<summary className="cursor-pointer list-none px-4 py-3 font-mono text-sm font-medium text-foreground portfolio-disclosure">
					Contents
				</summary>
				<div className="px-4 pb-4">
					<nav aria-label={ariaLabel}>
						<ul>
							{items.map((heading) => (
								<li key={heading.slug}>
									<a href={`#${heading.slug}`}>{heading.text}</a>
								</li>
							))}
						</ul>
					</nav>
				</div>
			</details>
		</div>
	)
}
