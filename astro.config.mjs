// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import react from '@astrojs/react';
import tailwindcss from '@tailwindcss/vite';

// https://astro.build/config
export default defineConfig({
	site: 'https://taktak.hu',
	security: {
		csp: {
			algorithm: "SHA-256",
			directives: [
				"default-src 'self'",
				"base-uri 'self'",
				"object-src 'none'",
				"form-action 'self'",
				"img-src 'self' data:",
				"font-src 'self'",
				"connect-src 'self'",
				"frame-src 'self'",
			],
			scriptDirective: {
				resources: ["'self'"],
				hashes: [
					"sha256-OT6rncc3q/HAZxFhU8Z7usSuSFUYlKM4kgPHZV03rBg=",
					"sha256-Zq2C3D7tul51zk4otXeF3betszC3IgHnvOlehVJyxOE=",
					"sha256-DHuK3BTFJHv6tO/o0w6Q9CBLZXOE7meJeHLXV2EmBUw=",
					"sha256-eul7RODnaOvI+OTE6Yc3WDU7UHyKbLyWAExV32Cq22c=",
				],
			},
			styleDirective: {
				resources: ["'self'", "'unsafe-inline'"],
			},
		},
	},
	redirects: {
		'/about/': '/profiles/',
		'/case-studies/htb/machines/windows/monitorsfour/':
			'/case-studies/htb/machines/linux/monitorsfour/',
		'/training/': '/profiles/',
		'/training/dante/': '/prolabs/dante/',
		'/training/zephyr/': '/prolabs/zephyr/',
		'/training/offshore/': '/prolabs/offshore/',
		'/training/mythical/': '/prolabs/mythical/',
		'/training/puppet/': '/prolabs/puppet/',
	},
	markdown: {
		shikiConfig: {
			themes: { light: 'github-light', dark: 'github-dark' },
			defaultColor: false,
		},
	},
	integrations: [react(), sitemap({ filter: (page) => new URL(page).pathname !== '/search/' })],
	vite: {
		plugins: [tailwindcss()],
	},
});
