import * as React from "react";
import { Menu, Search, X } from "lucide-react";

import { Button } from "../ui/button";
import { cn } from "../../lib/utils";
import SearchDialog from "./SearchDialog";
import ThemeControl from "./ThemeControl";

const LINKS = [
	{ href: "/case-studies/", label: "Case Studies" },
	{ href: "/prolabs/", label: "Pro Labs" },
	{ href: "/method/", label: "Method" },
];

function isCurrent(currentPath: string, href: string): boolean {
	if (currentPath === href) return true;
	return currentPath.startsWith(href) && currentPath.length > href.length;
}

export default function SiteHeader({ currentPath }: { currentPath: string }) {
	const [menuOpen, setMenuOpen] = React.useState(false);
	const [searchOpen, setSearchOpen] = React.useState(false);
	const closeSearch = React.useCallback(() => setSearchOpen(false), []);

	return (
		<header className="portfolio-header sticky top-0 z-10 border-b border-border bg-background">
			<div className="mx-auto flex min-h-14 w-full max-w-[var(--portfolio-max-width)] flex-wrap items-center gap-x-2 gap-y-2 px-4 py-2 sm:gap-x-4 md:grid md:grid-cols-[1fr_auto_1fr] md:gap-x-0 lg:px-8">
				<a
					href="/"
					aria-current={currentPath === "/" ? "page" : undefined}
					className="brand-lockup portfolio-brand shrink-0 md:justify-self-start"
				>
					<span className="brand-wordmark" translate="no">
						taktak.hu
					</span>
				</a>
				<nav
					id="site-nav"
					aria-label="Primary navigation"
					className={cn(
						"order-last w-full flex-col gap-2 text-sm md:order-none md:w-auto md:flex-row md:items-center md:justify-self-center md:gap-6",
						menuOpen ? "flex" : "hidden md:flex",
					)}>
					{LINKS.map(({ href, label }) => (
						<a
							key={href}
							href={href}
							aria-current={isCurrent(currentPath, href) ? "page" : undefined}
							className="inline-flex min-h-6 items-center text-muted-foreground no-underline hover:text-foreground aria-[current=page]:text-foreground">
							{label}
						</a>
					))}
					<div className="flex items-center justify-between border-t border-border pt-2 md:hidden">
						<span className="text-sm text-muted-foreground">Theme</span>
						<ThemeControl />
					</div>
				</nav>
				<div className="ml-auto flex min-w-0 items-center justify-end gap-1 sm:gap-2.5 md:justify-self-end">
					<Button
						variant="outline"
						size="sm"
						aria-label="Search"
						className="h-8 w-8 px-0 shadow-none sm:w-auto sm:px-3 sm:has-[>svg]:px-2.5"
						onClick={() => setSearchOpen(true)}>
						<Search aria-hidden="true" />
						<span className="sr-only sm:not-sr-only">Search</span>
					</Button>
					<div className="hidden md:block ml-1 border-l border-border pl-2 sm:ml-2 sm:pl-3">
						<ThemeControl />
					</div>
					<Button
						variant="ghost"
						size="icon-sm"
						className="rounded-md border border-input shadow-none md:hidden"
						aria-expanded={menuOpen}
						aria-controls="site-nav"
						aria-label={menuOpen ? "Close menu" : "Open menu"}
						onClick={() => setMenuOpen((value) => !value)}>
						{menuOpen ? (
							<X aria-hidden="true" />
						) : (
							<Menu aria-hidden="true" />
						)}
					</Button>
				</div>
				<SearchDialog open={searchOpen} onClose={closeSearch} />
			</div>
		</header>
	);
}
