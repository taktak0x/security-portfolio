// Case navigation rail. Hydrated client component. Without JavaScript it is a
// plain, working list of H2 jump links; the effect only adds a scrollspy mark
// (aria-current="location") to the section currently under the sticky header.
//
// Ported from the previous Sidebar.astro inline script: an IntersectionObserver
// watches the referenced headings — no scroll listener reads layout per frame.

import { useEffect, useRef } from "react"

type Heading = { depth: number; slug: string; text: string }

type Props = {
	categoryHref: string
	categoryLabel: string
	headings: Heading[]
}

export function CaseRail({ categoryHref, categoryLabel, headings }: Props) {
	const navRef = useRef<HTMLElement>(null)
	const sections = headings.filter((heading) => heading.depth === 2 && heading.slug)

	useEffect(() => {
		const nav = navRef.current
		if (!nav) return
		const links = Array.from(nav.querySelectorAll<HTMLAnchorElement>('a[href^="#"]'))
		if (links.length === 0) return

		const targets: { link: HTMLAnchorElement; heading: HTMLElement }[] = []
		for (const link of links) {
			// The href is already an encoded slug; decode defensively so a
			// malformed percent sequence cannot throw and abort the spy.
			let id = link.hash.slice(1)
			try {
				id = decodeURIComponent(id)
			} catch {
				// Keep the raw fragment.
			}
			const heading = document.getElementById(id)
			if (heading) targets.push({ link, heading })
		}
		if (targets.length === 0) return

		// Latest viewport-relative top seen for each heading. The observer only
		// fires as a heading crosses the header line, so this stays in sync
		// without a scroll listener reading layout every frame.
		const tops = new Map<Element, number>()
		let current: HTMLAnchorElement | null = null
		let atEnd = false
		let spy: IntersectionObserver | null = null
		let endSpy: IntersectionObserver | null = null

		const setCurrent = (link: HTMLAnchorElement | null) => {
			if (link === current) return
			if (current) current.removeAttribute("aria-current")
			current = link
			if (link) link.setAttribute("aria-current", "location")
		}

		// "Current" = the last heading whose top has passed beneath the sticky
		// header (its scroll-padding-top line); below that, the first. At the
		// document end the last entry wins, because a short final section
		// cannot always be scrolled up to that line.
		const recompute = () => {
			const offset = parseFloat(getComputedStyle(document.documentElement).scrollPaddingTop) || 0
			let active = targets[0].link
			if (atEnd) {
				active = targets[targets.length - 1].link
			} else {
				for (const { link, heading } of targets) {
					const top = tops.get(heading)
					if (top !== undefined && top <= offset + 1) active = link
				}
			}
			setCurrent(active)
		}

		const observe = () => {
			if (spy) spy.disconnect()
			const offset = parseFloat(getComputedStyle(document.documentElement).scrollPaddingTop) || 0
			// A thin band either side of the header line, so a heading that
			// snaps to exactly the line still registers.
			const band = 2
			const bandBottom = Math.max(0, window.innerHeight - offset - band)
			spy = new IntersectionObserver(
				(entries) => {
					for (const entry of entries) tops.set(entry.target, entry.boundingClientRect.top)
					recompute()
				},
				{ rootMargin: `${-Math.max(0, offset - band)}px 0px ${-bandBottom}px 0px`, threshold: 0 },
			)
			for (const { heading } of targets) spy.observe(heading)
		}

		// Inert sentinel at the document end. A real 1px box: a zero-area target
		// is not guaranteed to report `isIntersecting`, which would leave the
		// final section unmarked. Created and removed by this effect, so a
		// repeated mount cannot stack sentinels or observers.
		const sentinel = document.createElement("div")
		sentinel.setAttribute("aria-hidden", "true")
		sentinel.style.cssText =
			"position: absolute; height: 1px; width: 1px; margin-top: -1px; pointer-events: none;"
		document.body.append(sentinel)
		endSpy = new IntersectionObserver(
			(entries) => {
				const reachedEnd =
					entries.some((entry) => entry.isIntersecting) &&
					document.documentElement.scrollHeight > window.innerHeight
				if (reachedEnd === atEnd) return
				atEnd = reachedEnd
				recompute()
			},
			{ rootMargin: "0px 0px 8px 0px", threshold: 0 },
		)
		endSpy.observe(sentinel)

		observe()
		let frame = 0
		const onResize = () => {
			cancelAnimationFrame(frame)
			frame = requestAnimationFrame(observe)
		}
		window.addEventListener("resize", onResize)

		return () => {
			window.removeEventListener("resize", onResize)
			cancelAnimationFrame(frame)
			spy?.disconnect()
			endSpy?.disconnect()
			sentinel.remove()
			if (current) current.removeAttribute("aria-current")
		}
	}, [headings])

	return (
		<nav
			ref={navRef}
			aria-label="Case navigation"
			className="flex flex-col gap-5 border-t border-border pt-4 text-left"
		>
			<a
				href={categoryHref}
				className="inline-flex min-h-6 items-center gap-1 font-mono text-[0.78rem] tracking-[0.02em] text-primary no-underline hover:underline focus-visible:underline"
			>
				<span aria-hidden="true">←</span> {categoryLabel}
			</a>
			{sections.length > 0 && (
				<div className="border-t border-border pt-4">
					<h2 className="m-0 mb-2 font-mono text-[0.68rem] font-medium tracking-[0.08em] text-muted-foreground uppercase">
						Contents
					</h2>
					<ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-[0.82rem]">
						{sections.map((heading) => (
							<li key={heading.slug}>
								<a
									href={`#${heading.slug}`}
									className="block rounded-[var(--portfolio-radius-sm)] px-1 py-1 text-muted-foreground no-underline hover:text-primary hover:underline focus-visible:text-primary focus-visible:underline aria-[current=location]:font-semibold aria-[current=location]:text-primary"
								>
									{heading.text}
								</a>
							</li>
						))}
					</ul>
				</div>
			)}
		</nav>
	)
}
