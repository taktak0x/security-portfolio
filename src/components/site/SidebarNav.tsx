// Site section navigation. Server component: replaces Starlight's sidebar with
// a short, fixed list of the portfolio's own sections. Rendered by the case
// page shell; active state comes from the server-provided pathname.

type NavLink = { label: string; href: string }

const PRIMARY_LINKS: NavLink[] = [
	{ label: "Case Studies", href: "/case-studies/" },
	{ label: "Pro Labs", href: "/prolabs/" },
	{ label: "Profiles", href: "/profiles/" },
]

const GROUPS: { label: string; links: NavLink[] }[] = [
	{
		label: "Offensive Security",
		links: [
			{ label: "Windows", href: "/case-studies/htb/machines/windows/" },
			{ label: "Linux", href: "/case-studies/htb/machines/linux/" },
		],
	},
	{
		label: "Investigations",
		links: [{ label: "DFIR", href: "/case-studies/htb/sherlocks/dfir/" }],
	},
]

// Compare path parts only: drop query/hash and the trailing slash, so
// "/prolabs/" and "/prolabs" match and "/case-studies/" matches "/case-studies".
function normalize(path: string): string {
	const clean = path.split("#")[0].split("?")[0]
	const trimmed = clean.replace(/\/+$/, "")
	return trimmed === "" ? "/" : trimmed
}

function LinkList({ links, current }: { links: NavLink[]; current: string }) {
	return (
		<ul className="m-0 flex list-none flex-col gap-1 p-0">
			{links.map((item) => {
				const active = normalize(item.href) === current
				return (
					<li key={item.href}>
						<a
							href={item.href}
							aria-current={active ? "page" : undefined}
							className="block rounded-[var(--portfolio-radius-sm)] px-2 py-1.5 text-sm text-muted-foreground no-underline hover:bg-muted hover:text-foreground focus-visible:bg-muted focus-visible:text-foreground aria-[current=page]:bg-muted aria-[current=page]:font-semibold aria-[current=page]:text-foreground"
						>
							{item.label}
						</a>
					</li>
				)
			})}
		</ul>
	)
}

export function SidebarNav({ currentPath }: { currentPath: string }) {
	const current = normalize(currentPath)
	return (
		<nav aria-label="Section navigation" className="flex flex-col gap-5">
			<LinkList links={PRIMARY_LINKS} current={current} />
			{GROUPS.map((group) => (
				<div key={group.label} className="border-t border-border pt-4">
					<h2 className="m-0 mb-2 font-mono text-[0.68rem] font-medium tracking-[0.08em] text-muted-foreground uppercase">
						{group.label}
					</h2>
					<LinkList links={group.links} current={current} />
				</div>
			))}
		</nav>
	)
}
