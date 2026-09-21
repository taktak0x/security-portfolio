# security-portfolio

Static security portfolio of case studies, digital forensics, and credential records, built with Astro, React, and shadcn/ui.

## Stack

- [Astro](https://astro.build) 7
- [React](https://react.dev) + [shadcn/ui](https://ui.shadcn.com) for the site shell, rendered by Astro
- Astro content collections for Markdown content under `src/content/docs/`
- [@astrojs/sitemap](https://docs.astro.build/en/guides/integrations-guide/sitemap/) for the sitemap
- pnpm

## Development

```bash
pnpm install
pnpm dev       # local dev server
pnpm build     # static output in dist/
pnpm preview   # serve the build locally
```

## Content

Case studies live under `src/content/docs/case-studies/`, grouped by platform and target type:

```
case-studies/htb/machines/windows/<slug>.md
case-studies/htb/machines/linux/<slug>.md
case-studies/htb/sherlocks/dfir/<slug>.md
```

Profile links live under `src/content/docs/profiles/`, and completed Pro Lab credential records live under `src/content/docs/prolabs/`. Every page's frontmatter is validated against the schema in `src/content.config.ts`; the homepage explorer and the sidebar pick up new entries automatically.

## Production

The canonical site URL is configured as `site` in `astro.config.mjs`. The build emits a static site to `dist/`, including `sitemap-index.xml`.

## Branches and deployment

Two long-lived branches:

| Branch | Purpose | Deployment |
|---|---|---|
| `dev` | All work, experiments, and local verification. | None — pushing `dev` publishes nothing. |
| `main` | Permanent, confirmed changes only. | `.github/workflows/deploy.yml` builds and deploys to GitHub Pages at https://taktak.hu/. |

Work and test on `dev` (`pnpm dev` for the local server, `pnpm build` to verify the static output). `main` is protected; `dev` is unprotected. Move a change to `main` only once it is final and confirmed, since pushing `main` publishes the live site. Do not force-push or rewrite published history on `main`; undo a published change with a new corrective commit on `dev`.

Production changes use a pull request with base `main` and head `dev` or an exact trusted publisher branch pattern. Required checks are `quality` and `Analyze`; `portfolio-security-gate` is the security gate. PR #30 passed all checks and merged; PR #31 later auto-merged. No human-only approval or merge requirement is documented. Exact branch protection settings are unavailable.

The `pull_request_target` review workflow verifies the trusted base SHA and must never check out or run PR-head code while App credentials are available. GitHub App values come from `vars.PORTFOLIO_BOT_APP_ID`, `vars.PORTFOLIO_BOT_INSTALLATION_ID`, and secret `PORTFOLIO_BOT_APP_PRIVATE_KEY`.

GitHub Actions allowlist includes GitHub actions and the exact pinned `pnpm/action-setup` SHA. Complete future policy actions before November 2, 2026.
