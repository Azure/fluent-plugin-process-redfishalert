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
  # BMC/RMC credential is fetched live from Azure Key Vault using the pod's
  # user-assigned managed identity -- no password file is read from disk.
  keyVaultName "#{ENV['KEYVAULT_NAME']}"
  msiClientId "#{ENV['MSI_CLIENT_ID']}"
  secretName "#{ENV['SECRET_NAME']}"
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

- The BMC/RMC credential is never stored on disk. `getPassword` fetches an access token from IMDS
  (`msiClientId`), then reads the secret directly from Azure Key Vault (`keyVaultName`/`secretName`) over
  HTTPS. It's cached in memory for 10 minutes to avoid a Key Vault round-trip per alert, and retried once
  more (short backoff) on transient failures; if both attempts fail, the plugin raises rather than serving
  a stale or fallback credential. `keyVaultName`/`msiClientId`/`secretName` are required at configure time.
- Prerequisite: the identity behind `msiClientId` must already have "get secret" access on `secretName` in
  `keyVaultName` -- this plugin does not grant or manage that access.
- The Redfish host (`REMOTE_ADDR` on the inbound record) is validated against `allowed_host_ranges` before any
  outbound HTTPS request is made, to prevent SSRF against arbitrary hosts.



## Contributing
Please Read Contributing.md

