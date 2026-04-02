require 'json'
require 'fileutils'
require 'open3'
require 'shellwords'
require_relative '../helper/spm_dependency_audit_helper'

module Fastlane
  module Actions
    module SharedValues
      SPM_DEPENDENCY_AUDIT_RESULT = :SPM_DEPENDENCY_AUDIT_RESULT
      SPM_DEPENDENCY_AUDIT_OUTPUT_PATH = :SPM_DEPENDENCY_AUDIT_OUTPUT_PATH
    end

    class SpmDependencyAuditAction < Action
      def self.run(params)
        Fastlane::Helper::SpmDependencyAuditHelper.ensure_python!(params[:python_bin])

        plugin_root = File.expand_path('../../../../..', __dir__)
        script_path = File.join(plugin_root, 'vendor', 'script_checker', 'spm_dep_audit.py')
        UI.user_error!("Vendored script not found: #{script_path}") unless File.exist?(script_path)

        command = [
          params[:python_bin],
          script_path,
          '--project-dir', params[:project_dir],
          '--resolved', params[:resolved],
          '--lookup', params[:lookup],
          '--api-base', params[:api_base],
          '--format', params[:format]
        ]

        command += ['--graph-json', params[:graph_json]] if params[:graph_json].to_s.strip != ''
        command += ['--fail-on-severity', params[:fail_on_severity]] if params[:fail_on_severity].to_s.strip != ''
        Array(params[:ignore_advisory]).each do |advisory_id|
          next if advisory_id.to_s.strip.empty?
          command += ['--ignore-advisory', advisory_id]
        end

        command << '--fail-on-any-vuln' if params[:fail_on_any_vuln]
        command << '--no-details' if params[:no_details]
        command << '--auto-fix' if params[:auto_fix]
        command << '--keep-temp-copy' if params[:keep_temp_copy]

        UI.message("Running command: #{command.shelljoin}") if params[:verbose]

        stdout, stderr, status = Open3.capture3(*command)

        unless stderr.to_s.strip.empty?
          UI.important(stderr)
        end

        output_path = params[:output_path]
        if output_path.to_s.strip != ''
          absolute_output_path = File.expand_path(output_path)
          FileUtils.mkdir_p(File.dirname(absolute_output_path))
          File.write(absolute_output_path, stdout)
          Actions.lane_context[SharedValues::SPM_DEPENDENCY_AUDIT_OUTPUT_PATH] = absolute_output_path
          UI.success("Audit report saved to #{absolute_output_path}")
        end

        result = stdout
        if params[:format] == 'json' && !stdout.to_s.strip.empty?
          begin
            result = JSON.parse(stdout)
          rescue JSON::ParserError
            UI.important('The audit finished, but JSON parsing failed. Returning raw output.')
            result = stdout
          end
        end

        Actions.lane_context[SharedValues::SPM_DEPENDENCY_AUDIT_RESULT] = result

        if status.success?
          findings_count = result.is_a?(Hash) ? Array(result['findings']).size : nil
          if findings_count
            UI.success("SPM audit finished. Findings: #{findings_count}")
          else
            UI.success('SPM audit finished successfully.')
          end
          return result
        end

        UI.user_error!(<<~ERROR)
          spm_dependency_audit failed with exit code #{status.exitstatus}.
          #{stderr}
          #{stdout}
        ERROR
      end

      def self.description
        'Runs the vendored SwiftPM dependency vulnerability audit from fastlane.'
      end

      def self.details
        'Wraps the script_checker Python CLI inside a reusable fastlane plugin action, supports JSON/text output, policy-based failures, advisory ignore lists, and auto-fix verification mode.'
      end

      def self.authors
        ['OpenAI']
      end

      def self.return_value
        'Returns parsed JSON as a Ruby Hash when format=json, otherwise returns raw command output as a String.'
      end

      def self.output
        [
          ['SPM_DEPENDENCY_AUDIT_RESULT', 'Parsed audit result Hash or raw output String.'],
          ['SPM_DEPENDENCY_AUDIT_OUTPUT_PATH', 'Absolute path to the saved report file when output_path is provided.']
        ]
      end

      def self.available_options
        [
          FastlaneCore::ConfigItem.new(key: :project_dir,
                                       env_name: 'SPM_AUDIT_PROJECT_DIR',
                                       description: 'Path to the root of the SwiftPM project to audit',
                                       default_value: '.'),
          FastlaneCore::ConfigItem.new(key: :resolved,
                                       env_name: 'SPM_AUDIT_RESOLVED',
                                       description: 'Path to Package.resolved relative to project_dir',
                                       default_value: 'Package.resolved'),
          FastlaneCore::ConfigItem.new(key: :graph_json,
                                       env_name: 'SPM_AUDIT_GRAPH_JSON',
                                       description: 'Optional path to a pre-generated swift package show-dependencies JSON file',
                                       optional: true,
                                       type: String),
          FastlaneCore::ConfigItem.new(key: :lookup,
                                       env_name: 'SPM_AUDIT_LOOKUP',
                                       description: 'Lookup mode for OSV queries',
                                       default_value: 'auto',
                                       verify_block: proc do |value|
                                         UI.user_error!('lookup must be auto, version, or commit') unless %w[auto version commit].include?(value)
                                       end),
          FastlaneCore::ConfigItem.new(key: :api_base,
                                       env_name: 'SPM_AUDIT_API_BASE',
                                       description: 'Base URL of the OSV API',
                                       default_value: 'https://api.osv.dev/v1'),
          FastlaneCore::ConfigItem.new(key: :format,
                                       env_name: 'SPM_AUDIT_FORMAT',
                                       description: 'Output format of the audit result',
                                       default_value: 'json',
                                       verify_block: proc do |value|
                                         UI.user_error!('format must be json or text') unless %w[json text].include?(value)
                                       end),
          FastlaneCore::ConfigItem.new(key: :fail_on_any_vuln,
                                       env_name: 'SPM_AUDIT_FAIL_ON_ANY_VULN',
                                       description: 'Fail the lane when at least one vulnerability is found',
                                       type: Boolean,
                                       default_value: false),
          FastlaneCore::ConfigItem.new(key: :fail_on_severity,
                                       env_name: 'SPM_AUDIT_FAIL_ON_SEVERITY',
                                       description: 'Fail when the maximum severity meets the threshold',
                                       optional: true,
                                       type: String),
          FastlaneCore::ConfigItem.new(key: :ignore_advisory,
                                       env_name: 'SPM_AUDIT_IGNORE_ADVISORY',
                                       description: 'List of advisory IDs to ignore',
                                       type: Array,
                                       default_value: []),
          FastlaneCore::ConfigItem.new(key: :no_details,
                                       env_name: 'SPM_AUDIT_NO_DETAILS',
                                       description: 'Skip per-advisory detail fetches',
                                       type: Boolean,
                                       default_value: false),
          FastlaneCore::ConfigItem.new(key: :auto_fix,
                                       env_name: 'SPM_AUDIT_AUTO_FIX',
                                       description: 'Try automatic remediation suggestions for direct dependencies',
                                       type: Boolean,
                                       default_value: false),
          FastlaneCore::ConfigItem.new(key: :keep_temp_copy,
                                       env_name: 'SPM_AUDIT_KEEP_TEMP_COPY',
                                       description: 'Keep the temporary project copy created during auto verification',
                                       type: Boolean,
                                       default_value: false),
          FastlaneCore::ConfigItem.new(key: :python_bin,
                                       env_name: 'SPM_AUDIT_PYTHON_BIN',
                                       description: 'Python interpreter used to execute the vendored audit script',
                                       default_value: 'python3'),
          FastlaneCore::ConfigItem.new(key: :output_path,
                                       env_name: 'SPM_AUDIT_OUTPUT_PATH',
                                       description: 'Optional file path where the command output will be saved',
                                       optional: true,
                                       type: String),
          FastlaneCore::ConfigItem.new(key: :verbose,
                                       env_name: 'SPM_AUDIT_VERBOSE',
                                       description: 'Print the fully expanded command before execution',
                                       type: Boolean,
                                       default_value: false)
        ]
      end

      def self.is_supported?(_platform)
        true
      end
    end
  end
end
