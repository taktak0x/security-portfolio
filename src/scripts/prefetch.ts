type NetworkInformation = {
	effectiveType?: string;
	saveData?: boolean;
};

const connection = () => (navigator as Navigator & { connection?: NetworkInformation }).connection;

const supportsPrefetch = (() => {
	try {
		return document.createElement("link").relList.supports("prefetch");
	} catch {
		return false;
	}
})();

const state = window as Window & {
	__portfolioPrefetchInitialized?: boolean;
	__portfolioPrefetchCleanup?: () => void;
};

if (supportsPrefetch && !state.__portfolioPrefetchInitialized) {
	state.__portfolioPrefetchInitialized = true;
	const prefetched = new Set<string>();
	const pending = new Map<HTMLAnchorElement, number>();
	const controller = new AbortController();
	const intentDelay = 120;

	const getAnchor = (event: Event) => {
		const target = event.target;
		return target instanceof Element ? target.closest<HTMLAnchorElement>("a[href]") : null;
	};

	const prefetch = (anchor: HTMLAnchorElement) => {
		pending.delete(anchor);
		const network = connection();
		if (network?.saveData || ["slow-2g", "2g"].includes(network?.effectiveType ?? "")) return;
		if (!anchor || anchor.target && anchor.target !== "_self" || anchor.hasAttribute("download")) return;

		const url = new URL(anchor.href, location.href);
		if (url.origin !== location.origin || url.protocol !== location.protocol || anchor.getAttribute("href")?.startsWith("#")) return;
		const path = url.pathname.toLowerCase().replace(/\/+$/, "");
		if (/\.[^/]+$/.test(path) && !/\.html?$/.test(path)) return;

		url.hash = "";
		if (url.href === `${location.origin}${location.pathname}${location.search}` || prefetched.has(url.href)) return;

		prefetched.add(url.href);
		const link = document.createElement("link");
		link.rel = "prefetch";
		link.href = url.href;
		document.head.append(link);
	};

	const schedule = (event: Event) => {
		if (event.type === "pointerenter" && (event as PointerEvent).pointerType === "touch") return;
		const anchor = getAnchor(event);
		if (!anchor || pending.has(anchor)) return;
		pending.set(anchor, window.setTimeout(() => prefetch(anchor), intentDelay));
	};

	const cancel = (event: Event) => {
		const anchor = getAnchor(event);
		const relatedTarget = (event as PointerEvent | FocusEvent).relatedTarget;
		if (!anchor || relatedTarget instanceof Node && anchor.contains(relatedTarget)) return;
		const timer = pending.get(anchor);
		if (timer !== undefined) {
			window.clearTimeout(timer);
			pending.delete(anchor);
		}
	};

	document.addEventListener("pointerenter", schedule, { capture: true, signal: controller.signal });
	document.addEventListener("pointerleave", cancel, { capture: true, signal: controller.signal });
	document.addEventListener("focusin", schedule, { signal: controller.signal });
	document.addEventListener("focusout", cancel, { signal: controller.signal });
	state.__portfolioPrefetchCleanup = () => {
		controller.abort();
		for (const timer of pending.values()) window.clearTimeout(timer);
		pending.clear();
		state.__portfolioPrefetchInitialized = false;
		delete state.__portfolioPrefetchCleanup;
	};
}
