export type Category = "linux" | "windows" | "dfir" | "soc";
export type Kind = "all" | Category;
export type SortKey = "newest" | "az" | "category";

export const KINDS: Kind[] = ["all", "linux", "windows", "dfir"];
export const SORT_KEYS: SortKey[] = ["newest", "az", "category"];

export interface Study {
	id: string;
	href: string;
	title: string;
	description: string;
	category: Category;
	label: string;
	tools: string[];
	tags: string[];
	addedAt: string;
	search: string;
}

export interface Counts {
	all: number;
	linux: number;
	windows: number;
	dfir: number;
}
