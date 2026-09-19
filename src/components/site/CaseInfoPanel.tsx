// Case information rail. Server component. Rendered three times per case page:
// the complete panel in the desktop rail, and two halves inside the mobile
// disclosures (facts before the article, related cases and provenance after).
// It therefore carries no id attributes at all — duplicate ids would fail the
// accessibility gate — and each variant gets a distinct landmark label.

import { Fragment } from "react"

type RelatedLink = { href: string; title: string }

type Variant = "full" | "facts" | "related"

type Props = {
	categoryLabel: string
	tools: string[]
	skill?: string
	tags: string[]
	published?: string
	publishedLabel?: string
	updated?: string
	updatedLabel?: string
	evidenceQuality?: string
	related: RelatedLink[]
	reportUrl: string
	variant?: Variant
}

export function CaseInfoPanel({
	categoryLabel,
	tools,
	skill,
	tags,
	published,
	publishedLabel,
	updated,
	updatedLabel,
	evidenceQuality,
	related,
	reportUrl,
	variant = "full",
}: Props) {
	const rows: [string, string][] = [["Category", categoryLabel]]
	if (tools.length > 0) rows.push(["Tools", tools.join(", ")])
	if (skill) rows.push(["Skill", skill])
	if (tags.length > 0) rows.push(["Tags", tags.join(", ")])
	if (published) rows.push([publishedLabel ?? "Published", published])
	if (updated) rows.push([updatedLabel ?? "Updated", updated])
	if (evidenceQuality) rows.push(["Evidence", evidenceQuality])

	const showFacts = variant !== "related"
	const showRelated = variant !== "facts"
	const panelLabel =
		variant === "facts"
			? "Case facts"
			: variant === "related"
				? "Related cases and provenance"
				: "Case information"

	return (
		<aside
			aria-label={panelLabel}
			className="flex flex-col gap-5 rounded-[var(--portfolio-radius)] border border-border bg-background p-5 text-left font-mono"
		>
			{showFacts && (
				<dl className="m-0 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-xs">
					{rows.map(([rowLabel, value]) => (
						<Fragment key={rowLabel}>
							<dt className="text-[0.68rem] font-medium tracking-[0.06em] text-primary uppercase">{rowLabel}</dt>
							<dd className="m-0 text-muted-foreground [overflow-wrap:anywhere]">{value}</dd>
						</Fragment>
					))}
				</dl>
			)}

			{showRelated && related.length > 0 && (
				<nav
					aria-label="Related cases"
					className={showFacts ? "border-t border-border pt-3.5" : undefined}
				>
					<h2 className="m-0 mb-2 font-mono text-[0.68rem] font-medium tracking-[0.08em] text-muted-foreground uppercase">
						Related cases
					</h2>
					<ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-[0.78rem]">
						{related.map((item) => (
							<li key={item.href}>
								<a
									href={item.href}
									className="inline-flex min-h-6 items-center text-muted-foreground no-underline hover:text-primary hover:underline focus-visible:text-primary focus-visible:underline"
								>
									{item.title}
								</a>
							</li>
						))}
					</ul>
				</nav>
			)}

			{showRelated && (
				<nav
					aria-label="Provenance"
					className={showFacts || related.length > 0 ? "border-t border-border pt-3.5" : undefined}
				>
					<h2 className="m-0 mb-2 font-mono text-[0.68rem] font-medium tracking-[0.08em] text-muted-foreground uppercase">
						Provenance
					</h2>
					<ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-[0.78rem]">
						<li>
							<a
								href={reportUrl}
								target="_blank"
								rel="noopener noreferrer"
								className="inline-flex min-h-6 items-center text-foreground no-underline hover:text-primary hover:underline focus-visible:text-primary focus-visible:underline"
							>
								Report an error
							</a>
						</li>
					</ul>
				</nav>
			)}
		</aside>
	)
}
