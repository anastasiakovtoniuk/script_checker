require 'open3'

module Fastlane
  module Helper
    class SpmDependencyAuditHelper
      def self.show_message
        UI.message('Using the spm_dependency_audit fastlane plugin')
      end

      def self.ensure_python!(python_bin)
        _stdout, stderr, status = Open3.capture3(python_bin, '--version')
        return if status.success?

        UI.user_error!("Could not execute #{python_bin}. stderr: #{stderr}")
      rescue Errno::ENOENT
        UI.user_error!("#{python_bin} was not found in PATH. Install Python 3 or pass a custom :python_bin.")
      end
    end
  end
end
