require 'fastlane/action'
require_relative 'spm_dependency_audit/version'

module Fastlane
  module SpmDependencyAudit
    def self.all_classes
      @all_classes ||= Dir[File.expand_path('spm_dependency_audit/{actions,helper}/*.rb', __dir__)].sort
    end
  end
end

Fastlane::SpmDependencyAudit.all_classes.each do |current_file|
  require current_file
end
