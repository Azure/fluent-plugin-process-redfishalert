# Fluent::Plugin::Redfish::Alert

## Installation

build with gem build
    $ gem build fluent-plugin-redfish-alert.gemspec
install with gem install
    $ gem install fluent-plugin-redfish-alert.gem

## Configuration

```
<filter redfish.alert>
 @type process_redfishalert
  coloregion "#{ENV['COLO_REGION']}"
  username "#{ENV['REDFISH_USERNAME']}"
  passwordFile /path/to/file
</filter>
```

Will add a field to the record named "machineID" 
Will add a field to the record named "BaseChassisSerialNumber" ( unique ID of machine used for raising support requests)


## Contributing
Please Read Contributing.md

