---
"@pnpm/node.fetcher": patch
"pnpm": patch
---

Fix path traversal vulnerability in Node.js binary fetcher ZIP extraction (CVE-2026-23888)

- Validate ZIP entry paths before extraction to prevent writing files outside target directory
- Validate package name (basename) to prevent directory escape via crafted prefix
- Both attack vectors now throw `ERR_PNPM_PATH_TRAVERSAL` error
