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
  # Optional: comma-separated IPs/CIDRs this plugin is allowed to call out to.
  # Defaults to RFC1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
  # which cover standard BMC/RMC management networks. Override only if your fleet's
  # BMCs live outside those ranges.
  allowed_host_ranges 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
</filter>
```

Will add a field to the record named "machineID" 
Will add a field to the record named "BaseChassisSerialNumber" ( unique ID of machine used for raising support requests)

## Security

- `passwordFile` must point to a secret file readable only by its owner (mode `0600` or stricter). The plugin
  validates this on every read and will refuse to start/process records against a group- or world-readable file.
- The Redfish host (`REMOTE_ADDR` on the inbound record) is validated against `allowed_host_ranges` before any
  outbound HTTPS request is made, to prevent SSRF against arbitrary hosts.



## Contributing
Please Read Contributing.md

