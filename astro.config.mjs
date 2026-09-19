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
					// Legacy homepage-explorer forwarder (index.astro).
					"sha256-i2hw14cM0hF+uWtbt0I/lSFAp9pYOmzhpC+PR05L82o=",
				],
			},
			styleDirective: {
				resources: ["'self'", "'unsafe-inline'"],
			},
		},
	},
	redirects: {
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
	integrations: [react(), sitemap()],
	vite: {
		plugins: [tailwindcss()],
	},
});
