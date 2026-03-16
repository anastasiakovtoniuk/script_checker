# script_checker

## Запуск

### 1. Зарезолвити залежності

swift package resolve

### 2. Побудувати граф залежностей

swift package show-dependencies --format json > deps.json

### 3. JSON-режим для CI

python3 spm_dep_audit.py --project-dir . --format json --fail-on-any-vuln

### 4. Запустити звичайний аналіз

python3 -B spm_dep_audit.py --project-dir . --graph-json deps.json --lookup version

### 5. Згенерувати звіт та переглянути

python3 -B spm_dep_audit.py --project-dir . --graph-json deps.json --lookup version --format json > report.json

cat report.json

### 6. Аналіз з автофіксом та автоверифікацією 

python3 -B spm_dep_audit.py --project-dir . --graph-json deps.json --lookup version --auto-fix --format json > report.json

### 7. Переглянути help

python3 spm_dep_audit.py --help
