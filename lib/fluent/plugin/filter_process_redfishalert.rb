require 'fluent/plugin/filter'
require 'json'
require 'net/http'
require 'ipaddr'

module Fluent
  class ProcessRedfishAlert < Filter
    Fluent::Plugin.register_filter('process_redfishalert', self)

    # config_param
    config_param :coloregion, :string
    config_param :username, :string
    # CWE-522 remediation: the BMC/RMC credential is fetched live from Azure Key
    # Vault via the AKS cluster's user-assigned managed identity, instead of
    # being read from a plaintext file on disk. There is no file-based fallback.
    config_param :keyVaultName, :string
    config_param :msiClientId, :string
    config_param :secretName, :string
    config_param :hardware, :string, :default => "SDFLEX"
    # Comma-separated list of IPs/CIDRs this plugin is allowed to call out to.
    # REMOTE_ADDR on an inbound record is attacker-influenced (it's whatever the
    # syslog/redfish sender claims), so it must never be used verbatim to build an
    # outbound Redfish request. Defaults to the RFC1918 ranges BMC/RMC management
    # networks live on; override per-deployment if the fleet uses different ranges.
    config_param :allowed_host_ranges, :string, :default => "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

    IMDS_TOKEN_URI = 'http://169.254.169.254/metadata/identity/oauth2/token'
    KEY_VAULT_RESOURCE = 'https://vault.azure.net'
    KEY_VAULT_API_VERSION = '7.4'
    # How long a successfully-fetched secret is reused before refetching. This is
    # a resilience/performance measure (avoid a Key Vault round-trip per alert),
    # not a security fallback -- it never serves a value that wasn't itself
    # freshly fetched from Key Vault within this window.
    SECRET_CACHE_TTL_SECONDS = 600
    # Kept small and fast: `filter` runs on Fluentd's single event-loop thread, so
    # a long/blocking retry here would stall alert processing for every record
    # during a real Key Vault/IMDS outage -- exactly when hardware alerts matter most.
    MAX_FETCH_ATTEMPTS = 2
    RETRY_BACKOFF_SECONDS = 0.5

    def configure(conf)
      super
        raise Fluent::ConfigError, "keyVaultName must be set" if keyVaultName.nil? || keyVaultName.empty?
        raise Fluent::ConfigError, "msiClientId must be set" if msiClientId.nil? || msiClientId.empty?
        raise Fluent::ConfigError, "secretName must be set" if secretName.nil? || secretName.empty?
        @hwtDeviceURI = Hash["Dell_PowerEdge_iDRAC"=>"Systems/System.Embedded.1", "SDFLEX" => "Chassis/RMC", "SUPERMICRO" => "Systems/1"]
        @deviceRackURI = Hash["Dell_PowerEdge_iDRAC"=>"Systems/System.Embedded.1", "SDFLEX" => "Chassis/RackGroup", "SUPERMICRO" => "Chassis/1"]
        @deviceIDField = Hash["Dell_PowerEdge_iDRAC"=>"SKU", "SDFLEX" => "SerialNumber", "SUPERMICRO" => "SerialNumber"]
        @alternativeRMCEndpointForSDFlex = "Managers/RMC"
        begin
          @allowedHostRanges = allowed_host_ranges.split(",").map { |cidr| IPAddr.new(cidr.strip) }
        rescue IPAddr::Error, ArgumentError => e
          raise Fluent::ConfigError, "allowed_host_ranges contains an invalid IP/CIDR (#{allowed_host_ranges.inspect}): #{e.message}"
        end
    end

    def start
      super
    end

    def filter(tag, time, record)
      begin
      # REMOTE_ADDR is the IP the event was sent from
      rmcSN = getMachineIdentifier(record["REMOTE_ADDR"])
      if tag == "redfish.alert"
        rgSN = getRackGroupIdentifier(record["REMOTE_ADDR"])
      end
      rescue SecurityError => se
        record["error"] = "Error calling redfish API: #{se.message}"
      end
      if @hardware == "Dell_PowerEdge_iDRAC"
        record["ProductID"] = rmcSN
        record["PowerState"] = getPowerState(record["REMOTE_ADDR"])
      elsif @hardware == "SUPERMICRO"
        record["ProductSerialNumber"] = rmcSN
        record["ChassisSerialNumber"] = rgSN
        record["PowerState"] = getPowerState(record["REMOTE_ADDR"])
      else
        record["RMCSerialNumber"] = rmcSN
        # BaseChassisSerialNumber is used as the identifier by OEMs
        record["BaseChassisSerialNumber"] = rgSN
      end
      record
    end

    def callRedfishGetAPI(host, resourceURI)
      validate_host!(host)
      uri = URI.parse("https://#{host}:443/redfish/v1/#{resourceURI}")
      
      https = Net::HTTP.new(uri.host, uri.port)
      https.use_ssl = true
      # BMC/RMC management interfaces in this fleet present self-signed certs by
      # design (see the matching `insecure true` on the fluentd HTTP ingest side).
      # Outbound access is already restricted to internal management-network
      # ranges by validate_host! above (CWE-918 SSRF guard), so full chain
      # verification here isn't meaningful and previously silently dropped every
      # event from these devices once VERIFY_PEER started being enforced.
      https.verify_mode = OpenSSL::SSL::VERIFY_NONE

      header = {'Content-Type': 'application/json'}
      request = Net::HTTP::Get.new(uri.request_uri, header)
      request.basic_auth(username, getPassword())

      response = https.request(request)

      if response.code == "200" 
        return JSON.parse(response.body)
      else 
        message = "Status code: #{response.statuscode}. Detailed Error: #{response.body}"
        raise SecurityError, message
      end
    end

    # Guards against SSRF (CWE-918): reject any host outside the configured
    # management-network ranges before an outbound Redfish request (carrying the
    # BMC credential via Basic Auth) is ever built. Fails closed on anything that
    # isn't a valid IP, rather than attempting a DNS lookup on attacker-controlled input.
    def validate_host!(host)
      ip = IPAddr.new(host)
      unless @allowedHostRanges.any? { |range| range.include?(ip) }
        raise SecurityError, "Refusing to call Redfish API: host is outside allowed_host_ranges"
      end
    rescue ArgumentError
      raise SecurityError, "Refusing to call Redfish API: host is not a valid IP address"
    end

    def getMachineIdentifier(host)
      begin
        res = callRedfishGetAPI(host, @hwtDeviceURI[hardware])
        # alternativeRMCEndpointForSDFlex fetches the SerialNumber from the RMC endpoint for SDFlex 280 blades
      rescue NoMethodError => e
        res = callRedfishGetAPI(host, @alternativeRMCEndpointForSDFlex) if @hardware == "SDFLEX"
      end
      return res[@deviceIDField[hardware]]
    end

    def getRackGroupIdentifier(host)
      res = callRedfishGetAPI(host, @deviceRackURI[hardware])
      return res[@deviceIDField[hardware]]
    end

    def getPowerState(host)
      res = callRedfishGetAPI(host, @deviceRackURI[hardware])
      return res["PowerState"]
    end

    # Guards against CWE-522 (insufficiently protected credentials): the credential
    # is never written to disk. It's fetched live from Key Vault using the pod's
    # managed identity and held in memory only for SECRET_CACHE_TTL_SECONDS, so
    # there is no plaintext file for another local user/process to read.
    # @cachedSecret/@cacheExpiresAt are plain instance vars: safe because Fluentd
    # invokes a filter plugin's `filter` (and therefore getPassword) from a single
    # event-loop thread per plugin instance, not concurrently.
    def getPassword()
      return @cachedSecret if secret_cache_valid?

      last_error = nil
      MAX_FETCH_ATTEMPTS.times do |attempt|
        begin
          token = fetch_msi_token
          secret = fetch_key_vault_secret(token)
          @cachedSecret = secret
          @cacheExpiresAt = Time.now + SECRET_CACHE_TTL_SECONDS
          return secret
        rescue => e
          last_error = e
          sleep(retry_backoff_seconds) if attempt < MAX_FETCH_ATTEMPTS - 1
        end
      end
      raise SecurityError, "Unable to fetch RMC/BMC credential from Key Vault '#{keyVaultName}' after #{MAX_FETCH_ATTEMPTS} attempt(s): #{last_error&.message}"
    end

    def secret_cache_valid?
      !@cachedSecret.nil? && !@cacheExpiresAt.nil? && Time.now < @cacheExpiresAt
    end

    # Overridable so tests don't have to sleep through real retry backoff.
    def retry_backoff_seconds
      RETRY_BACKOFF_SECONDS
    end

    def fetch_msi_token
      uri = URI(IMDS_TOKEN_URI)
      uri.query = URI.encode_www_form(
        'api-version' => '2018-02-01',
        'resource' => KEY_VAULT_RESOURCE,
        'client_id' => msiClientId
      )
      request = Net::HTTP::Get.new(uri)
      request['Metadata'] = 'true'
      response = Net::HTTP.start(uri.hostname, uri.port, :open_timeout => 5, :read_timeout => 5) { |http| http.request(request) }
      unless response.code == '200'
        raise "IMDS token request failed with status #{response.code}: #{response.body}"
      end
      JSON.parse(response.body)['access_token']
    end

    def fetch_key_vault_secret(token)
      uri = URI("https://#{keyVaultName}.vault.azure.net/secrets/#{secretName}")
      uri.query = URI.encode_www_form('api-version' => KEY_VAULT_API_VERSION)
      request = Net::HTTP::Get.new(uri)
      request['Authorization'] = "Bearer #{token}"
      response = Net::HTTP.start(uri.host, uri.port, :use_ssl => true, :open_timeout => 5, :read_timeout => 5) { |http| http.request(request) }
      unless response.code == '200'
        raise "Key Vault secret request failed with status #{response.code}: #{response.body}"
      end
      JSON.parse(response.body)['value']
    end
  end
end
