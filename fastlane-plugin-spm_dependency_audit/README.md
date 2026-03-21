# fastlane-plugin-spm_dependency_audit

Fastlane plugin that wraps the vendored `script_checker` Python audit tool and exposes it as the `spm_dependency_audit` action.

## What the plugin does

The action runs the SwiftPM vulnerability audit against `Package.resolved`, optionally uses a pre-generated dependency graph, supports JSON or text output, can fail the lane according to vulnerability policy, and can enable the existing auto-fix / auto-verify flow.

## Installation in another project

Add the plugin from a local path while developing it:

```ruby
# fastlane/Pluginfile
gem 'fastlane-plugin-spm_dependency_audit', path: '../fastlane-plugin-spm_dependency_audit'
```

Then run:

```bash
bundle exec fastlane install_plugins
```

## Example Fastfile usage

```ruby
lane :audit_dependencies do
  result = spm_dependency_audit(
    project_dir: '.',
    format: 'json',
    output_path: 'fastlane/reports/spm_audit_report.json',
    fail_on_any_vuln: true,
    verbose: true
  )

  UI.message("Findings count: #{Array(result['findings']).size}")
end
```

## Main parameters

- `project_dir` — path to the SwiftPM project root.
- `resolved` — relative path to `Package.resolved`.
- `graph_json` — optional path to a saved `swift package show-dependencies --format json` file.
- `lookup` — `auto`, `version`, or `commit`.
- `format` — `json` or `text`.
- `fail_on_any_vuln` — fails the lane if any vulnerability is found.
- `fail_on_severity` — fails the lane on a chosen severity threshold.
- `ignore_advisory` — array of advisory IDs to skip.
- `auto_fix` — enables the existing auto-fix mode.
- `keep_temp_copy` — keeps the temp project created by auto verification.
- `python_bin` — override the Python interpreter, default `python3`.
- `output_path` — file path for saving stdout from the audit command.

## Notes

- The plugin vendors the Python sources from the current repository, so it does not require a separate Python package installation.
- The audit still needs network access to query OSV and a working Swift toolchain when the dependency graph is generated on the fly.
