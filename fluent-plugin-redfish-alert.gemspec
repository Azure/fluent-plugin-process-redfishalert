
Gem::Specification.new do |spec|
  spec.name          = "fluent-plugin-process-redfishalert"
  spec.version       = "0.1.0"
  spec.authors       = ["gadelamo"]
  spec.email         = ["gadelamo@microsoft.com"]
  spec.summary       = "a fluentd plugin to retrieve infro from an RMC using redfish"
  spec.description   = spec.summary
  spec.homepage      = "https://github.com/Azure/fluent-plugin-process-redfishalert"
  spec.license       = "MIT"
  
  spec.required_ruby_version = Gem::Requirement.new(">= 2.3.0")
  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = `git ls-files`.split("\n")
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
end
