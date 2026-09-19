interface Card {
	kind: "linux" | "windows" | "dfir";
	href: string;
	label: string;
	description: string;
}

const CARDS: Card[] = [
	{
		kind: "linux",
		href: "/case-studies/htb/machines/linux/",
		label: "Linux machine",
		description:
			"Web and service exploitation, credential recovery, and local privilege escalation.",
	},
	{
		kind: "windows",
		href: "/case-studies/htb/machines/windows/",
		label: "Windows machine",
		description:
			"Active Directory attack paths, including delegation and domain escalation.",
	},
	{
		kind: "dfir",
		href: "/case-studies/htb/sherlocks/dfir/",
		label: "DFIR / Sherlock",
		description:
			"Reconstructing timelines from logs and tracing persistence.",
	},
];

export default function FocusCards() {
	return (
		<section className="pt-16 pb-4" aria-labelledby="focus-title">
			<div className="max-w-[68ch]">
				<h2
					id="focus-title"
					className="text-3xl tracking-[-0.04em] sm:text-4xl"
				>
					Browse by focus
				</h2>
				<p className="mt-1 text-muted-foreground">
					Windows and Linux machines, or DFIR case work.
				</p>
			</div>
			<ul
				className="mt-6 list-none border-t border-[var(--portfolio-line)] pl-0"
			>
				{CARDS.map((card) => (
					<li
						key={card.kind}
						className="border-b border-[var(--portfolio-line)]"
					>
						<a
							href={card.href}
							className="grid gap-1 py-4 no-underline transition-colors hover:bg-muted/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring md:grid-cols-[12rem_1fr] md:gap-6"
						>
							<span className="font-medium">{card.label}</span>
							<span className="text-sm text-muted-foreground">
								{card.description}
							</span>
						</a>
					</li>
				))}
			</ul>
		</section>
	);
}
