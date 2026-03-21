$LOAD_PATH.unshift(File.expand_path('lib', __dir__))
require 'fastlane/plugin/spm_dependency_audit/version'

Gem::Specification.new do |spec|
  spec.name          = 'fastlane-plugin-spm_dependency_audit'
  spec.version       = Fastlane::SpmDependencyAudit::VERSION
  spec.author        = ['anastasia']
  spec.email         = ['noreply@example.com']
  spec.summary       = 'Runs a SwiftPM dependency vulnerability audit from fastlane.'
  spec.homepage      = 'https://github.com/anastasiakovtoniuk/script_checker'
  spec.license       = 'MIT'

  spec.files = Dir[
    'lib/**/*.rb',
    'vendor/script_checker/**/*.py',
    'README.md',
    'LICENSE',
    'Gemfile',
    'Rakefile'
  ]

  spec.require_paths = ['lib']

  spec.add_dependency('fastlane', '>= 2.0.0')
end
