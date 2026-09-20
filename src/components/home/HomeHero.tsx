import type { Study } from "./types";

export default function HomeHero({ studies }: { studies: Study[] }) {
	return (
		<section
			className="grid grid-cols-1 gap-8 py-10 lg:grid-cols-12 lg:gap-6 lg:py-24"
			aria-labelledby="portfolio-title"
		>
			<div className="lg:col-span-7">
				<p className="font-mono text-xs font-medium uppercase tracking-[0.12em] text-primary">
					SECURITY / WRITEUPS
				</p>
				<h1
					id="portfolio-title"
					className="mt-4 max-w-[14ch] text-[clamp(3rem,1.75rem+6.5vw,7.5rem)] leading-[0.92] tracking-[-0.02em]"
				>
					TakTak
				</h1>
				<p className="mt-5 max-w-[68ch] text-pretty text-base text-muted-foreground">
					I focus on cybersecurity, with an emphasis on Active Directory, penetration testing, and incident investigation. I'm currently expanding my skills in SOC operations, DFIR, and detection engineering. I learn them through hands-on labs, HTB content, and practical security projects.
				</p>
				<div className="mt-7 flex flex-wrap items-center gap-x-5 gap-y-3">
					<a
						href="/archive/"
						className="inline-flex items-center rounded-md border border-primary bg-primary px-4 py-2 font-bold text-primary-foreground no-underline hover:brightness-110 focus-visible:brightness-110"
					>
						Explore my work
					</a>
				</div>
			</div>
			<aside
				className="col-span-1 lg:col-start-8 lg:col-span-5"
				aria-labelledby="recent-work-title"
			>
				<div className="border-t border-input pt-5">
					<h2
						id="recent-work-title"
						className="font-mono text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground"
					>
						RECENT WRITEUPS
					</h2>
					<ul className="mt-2 divide-y divide-input">
						{studies.map((study) => (
							<li key={study.id}>
								<a
									href={study.href}
									className="flex flex-col gap-0.5 py-3 no-underline hover:text-primary focus-visible:text-primary"
								>
									<span className="font-medium">{study.title}</span>
									<span className="font-mono text-xs text-muted-foreground">
										{study.label}
									</span>
								</a>
							</li>
						))}
					</ul>
					<a
						href="/archive/"
						className="mt-2 inline-block py-1 font-mono text-xs text-muted-foreground no-underline hover:text-primary"
					>
						View all writeups
					</a>
				</div>
			</aside>
		</section>
	);
}
