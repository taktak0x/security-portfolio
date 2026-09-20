import * as React from "react";

import { Button } from "../ui/button";
import { Input } from "../ui/input";

type Entry = {
	href: string;
	title?: string;
	description?: string;
	objective?: string;
	tags?: string[];
	tools?: string[];
	skill?: string;
	outcome?: string;
	category?: string;
	kind?: string;
	label?: string;
};

type Status = "idle" | "loading" | "ready" | "error";

// One source of truth for the result cap and its truncation message.
const MAX_RESULTS = 20;

function fieldValues(entry: Entry): string[] {
	return [
		entry.title,
		entry.description,
		entry.objective,
		entry.category,
		entry.label,
		...(entry.tags ?? []),
		...(entry.tools ?? []),
		entry.skill,
		entry.outcome,
	].filter((value): value is string => typeof value === "string");
}

export default function SearchDialog({
	open,
	onClose,
	redirectOnClose,
	titleId: providedTitleId,
}: {
	open: boolean;
	onClose?: () => void;
	redirectOnClose?: string;
	titleId?: string;
}) {
	const dialogRef = React.useRef<HTMLDialogElement>(null);
	const inputRef = React.useRef<HTMLInputElement>(null);
	const generatedTitleId = React.useId();
	const titleId = providedTitleId ?? generatedTitleId;
	const loadedRef = React.useRef(false);
	const resultSelectionRef = React.useRef(false);
	const [entries, setEntries] = React.useState<Entry[]>([]);
	const [status, setStatus] = React.useState<Status>("idle");
	const [query, setQuery] = React.useState("");

	// Drive the native dialog from the `open` prop.
	React.useEffect(() => {
		const dialog = dialogRef.current;
		if (!dialog) return;
		if (open && !dialog.open) {
			dialog.showModal();
			inputRef.current?.focus();
		} else if (!open && dialog.open) {
			dialog.close();
		}
	}, [open]);

	// Native close (Escape, close(), form method=dialog) bubbles to the caller.
	React.useEffect(() => {
		const dialog = dialogRef.current;
		if (!dialog) return;
		const handleClose = () => {
			if (resultSelectionRef.current) {
				resultSelectionRef.current = false;
				return;
			}
			if (onClose) onClose();
			else if (redirectOnClose) window.location.assign(redirectOnClose);
		};
		dialog.addEventListener("close", handleClose);
		return () => dialog.removeEventListener("close", handleClose);
	}, [onClose, redirectOnClose]);

	// Fetch the index once, on the first open.
	React.useEffect(() => {
		if (!open || loadedRef.current) return;
		loadedRef.current = true;
		setStatus("loading");
		fetch("/search-index.json")
			.then((response) => {
				if (!response.ok) throw new Error(`HTTP ${response.status}`);
				return response.json();
			})
			.then((data: unknown) => {
				const list = Array.isArray(data)
					? data
					: ((data as { entries?: Entry[] } | null)?.entries ?? []);
				setEntries(Array.isArray(list) ? (list as Entry[]) : []);
				setStatus("ready");
			})
			.catch(() => {
				loadedRef.current = false;
				setStatus("error");
			});
	}, [open]);

	const trimmed = query.trim().toLowerCase();
	const matches = React.useMemo(() => {
		if (!trimmed) return [];
		const terms = trimmed.split(/\s+/);
		return entries.filter((entry) =>
			terms.every((term) =>
				fieldValues(entry).some((value) => value.toLowerCase().includes(term)),
			),
		);
	}, [entries, trimmed]);
	const results = matches.slice(0, MAX_RESULTS);

	let message = "Start typing to search.";
	if (status === "loading") {
		message = "Loading search index…";
	} else if (status === "error") {
		message = "Search is unavailable right now.";
	} else if (trimmed) {
		const total = matches.length;
		if (total === 0) {
			message = `No results for “${query.trim()}”.`;
		} else if (total > results.length) {
			message = `${total} results. Showing the first ${MAX_RESULTS}.`;
		} else {
			message = `${total} result${total === 1 ? "" : "s"}.`;
		}
	}

	// Single close path: update controlled state synchronously (so a fast
	// reopen is not coalesced away by the async native `close` event) and close
	// the native dialog. The `close` listener remains for external closes.
	const closeDialog = React.useCallback(() => {
		if (onClose) onClose();
		dialogRef.current?.close();
	}, [onClose]);

	const handleBackdropClick = (event: React.MouseEvent<HTMLDialogElement>) => {
		if (event.target === dialogRef.current) closeDialog();
	};

	const handleKeyDown = (event: React.KeyboardEvent<HTMLDialogElement>) => {
		if (event.key === "Escape") {
			event.preventDefault();
			closeDialog();
		}
	};

	return (
		<dialog
			ref={dialogRef}
			aria-labelledby={titleId}
			onClick={handleBackdropClick}
			onKeyDown={handleKeyDown}
			className="fixed inset-x-0 top-[10vh] bottom-auto mx-auto my-0 hidden h-fit max-h-[85dvh] w-[min(40rem,90vw)] flex-col overflow-hidden rounded-lg border border-border bg-background p-0 text-foreground shadow-none open:flex backdrop:bg-black/60">
			<div className="flex min-h-0 flex-col gap-3 p-4">
				<div className="flex shrink-0 items-center justify-between gap-3">
					<h2 id={titleId} className="text-sm font-semibold">Search the site</h2>
					<Button
						type="button"
						variant="ghost"
						size="sm"
						className="shadow-none"
						onClick={closeDialog}>
						Close
					</Button>
				</div>
				<Input
					ref={inputRef}
					type="search"
					aria-label="Search query"
					className="shrink-0 shadow-none"
					value={query}
					onChange={(event) => setQuery(event.target.value)}
					placeholder="Search case studies, credentials, and more…"
				/>
				<p role="status" aria-live="polite" className="shrink-0 text-xs text-muted-foreground">
					{message}
				</p>
				{status === "ready" && results.length > 0 && (
					<ul className="flex min-h-0 flex-col gap-1 overflow-y-auto overscroll-contain">
						{results.map((entry) => (
							<li key={entry.href}>
								<a
									href={entry.href}
									onClick={() => { resultSelectionRef.current = true; closeDialog(); }}
									className="block rounded-sm px-2 py-1.5 hover:bg-accent hover:text-accent-foreground">
									<span className="flex items-baseline justify-between gap-3">
										<span className="truncate text-sm">{entry.title ?? entry.href}</span>
										{entry.label && (
											<span className="shrink-0 font-mono text-[0.7rem] uppercase tracking-wide text-muted-foreground">
												{entry.label}
											</span>
										)}
									</span>
									{entry.description && (
										<span className="mt-0.5 block text-xs text-muted-foreground">
											{entry.description}
										</span>
									)}
								</a>
							</li>
						))}
					</ul>
				)}
			</div>
		</dialog>
	);
}
