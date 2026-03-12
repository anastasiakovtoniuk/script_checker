# script_checker

## Що змінилося

- `resolved.py` читає `Package.resolved` як джерело exact pinned versions / revisions.
- `osv_client.py` виконує batched OSV lookup.
- `graph.py` будує dependency paths через `swift package show-dependencies --format json`.
- `analyzer.py` зшиває advisory findings із конкретними пакетами та шляхами.
- `reporting.py` віддає або text, або JSON.
- `spm_dep_audit.py` лишається як сумісний entrypoint.

## Запуск

### 1. Згенерувати або оновити lockfile


swift package resolve


### 2. Перевірка з живим графом


python3 spm_dep_audit.py --project-dir . --fail-on-any-vuln


### 3. JSON-режим для CI


python3 spm_dep_audit.py --project-dir . --format json --fail-on-any-vuln


### 4. Лише querybatch ids без детального добору


python3 spm_dep_audit.py --project-dir . --no-details

