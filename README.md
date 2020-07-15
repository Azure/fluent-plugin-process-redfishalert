# Fluent::Plugin::Redfish::Alert

## Installation

build with gem build
    $ gem build fluent-plugin-redfish-alert.gemspec
install with gem install
    $ gem install fluent-plugin-redfish-alert.gem

## Usage
TODO: ADD MOre info

<filter redfish.alert>
 @type process_redfishalert
  coloregion "#{ENV['COLO_REGION']}"
  username "#{ENV['REDFISH_USERNAME']}"
  passwordFile /path/to/file
</filter>

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/fluent-plugin-redfish-alert.

