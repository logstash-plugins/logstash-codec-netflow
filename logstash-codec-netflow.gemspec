Gem::Specification.new do |s|

  s.name            = 'logstash-codec-netflow'
  s.version         = '0.1.0'
  s.licenses        = ['Apache License (2.0)']
  s.summary         = "$summary"
  s.description     = "$description"
  s.authors         = ["Elasticsearch"]
  s.email           = 'richard.pijnenburg@elasticsearch.com'
  s.homepage        = "http://logstash.net/"
  s.require_paths = ["lib"]

  # Files
  s.files = `git ls-files`.split($\)

  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "group" => "codec" }

  # Jar dependencies
  s.requirements << "jar 'jarnamepath', 'version'"

  # Gem dependencies
  s.add_runtime_dependency 'logstash', '>= 1.4.0', '< 2.0.0'
  s.add_runtime_dependency 'jar-dependencies', ['~> 0.0.6']

  s.add_runtime_dependency 'gemname', ['version']

end

