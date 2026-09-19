export const CASE_CATEGORIES = {
	"machines/linux": "Linux",
	"machines/windows": "Windows",
	"sherlocks/dfir": "DFIR",
	"sherlocks/soc": "SOC",
} as const;

export type CategoryKey = keyof typeof CASE_CATEGORIES;
export type CategoryLabel = (typeof CASE_CATEGORIES)[CategoryKey];

export type Category = {
	key: CategoryKey;
	label: CategoryLabel;
};

export function resolveCategory(path: string): Category | null {
	const normalized = path.replace(/^\/+|\/+$/g, "");
	const prefix = "case-studies/htb/";

	if (!normalized.startsWith(prefix)) return null;

	const key = (Object.keys(CASE_CATEGORIES) as CategoryKey[]).find(
		(candidate) =>
			normalized === prefix + candidate || normalized.startsWith(prefix + candidate + "/"),
	);

	if (!key) throw new Error(`Unknown case-study category: ${path}`);

	return { key, label: CASE_CATEGORIES[key] };
}
