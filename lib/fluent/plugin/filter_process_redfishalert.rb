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
    config_param :passwordFile, :string
    config_param :hardware, :string, :default => "SDFLEX"
    # Comma-separated list of IPs/CIDRs this plugin is allowed to call out to.
    # REMOTE_ADDR on an inbound record is attacker-influenced (it's whatever the
    # syslog/redfish sender claims), so it must never be used verbatim to build an
    # outbound Redfish request. Defaults to the RFC1918 ranges BMC/RMC management
    # networks live on; override per-deployment if the fleet uses different ranges.
    config_param :allowed_host_ranges, :string, :default => "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

    def configure(conf)
      super
        @hwtDeviceURI = Hash["Dell_PowerEdge_iDRAC"=>"Systems/System.Embedded.1", "SDFLEX" => "Chassis/RMC", "SUPERMICRO" => "Systems/1"]
        @deviceRackURI = Hash["Dell_PowerEdge_iDRAC"=>"Systems/System.Embedded.1", "SDFLEX" => "Chassis/RackGroup", "SUPERMICRO" => "Chassis/1"]
        @deviceIDField = Hash["Dell_PowerEdge_iDRAC"=>"SKU", "SDFLEX" => "SerialNumber", "SUPERMICRO" => "SerialNumber"]
        @alternativeRMCEndpointForSDFlex = "Managers/RMC"
        @allowedHostRanges = allowed_host_ranges.split(",").map { |cidr| IPAddr.new(cidr.strip) }
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
      https.verify_mode = OpenSSL::SSL::VERIFY_PEER

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

    def getPassword()
      validate_password_file_permissions!
      File.read(passwordFile).strip
    end

    # Guards against CWE-522 (insufficiently protected credentials): if the mounted
    # secret file is readable/writable by group or other, the BMC credential is
    # exposed to any other local user/process on the host. Fail closed instead of
    # silently reading a loosely-permissioned secret.
    def validate_password_file_permissions!
      mode = File.stat(passwordFile).mode & 0777
      if (mode & 0077) != 0
        raise SecurityError, "passwordFile #{passwordFile} must not be readable/writable by group or other (mode #{format('%o', mode)})"
      end
    rescue Errno::ENOENT
      raise SecurityError, "passwordFile #{passwordFile} does not exist"
    end
  end
end
