const LINKS = [
	{ href: "/case-studies/", label: "Case Studies" },
	{ href: "/prolabs/", label: "Pro Labs" },
	{ href: "/profiles/", label: "Profiles" },
	{ href: "/method/", label: "Method" },
	{ href: "https://github.com/taktak0x/security-portfolio", label: "GitHub" },
];

export default function SiteFooter() {
	return (
		<footer className="portfolio-footer">
			<div className="mx-auto flex w-full max-w-[var(--portfolio-max-width)] flex-wrap items-baseline justify-between gap-2 px-4 py-4 lg:px-8">
				<p>&copy; {new Date().getFullYear()} taktak.hu</p>
				<nav aria-label="Footer" className="portfolio-footer-links">
					{LINKS.map(({ href, label }) => (
						<a key={href} href={href} className="inline-flex min-h-6 items-center">
							{label}
						</a>
					))}
				</nav>
			</div>
		</footer>
	);
}
