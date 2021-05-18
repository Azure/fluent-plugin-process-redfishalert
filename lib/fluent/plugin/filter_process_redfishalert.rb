
require 'fluent/plugin/filter'
require 'json'
require 'net/http'

module Fluent
  class ProcessRedfishAlert < Filter
    Fluent::Plugin.register_filter('process_redfishalert', self)

    # config_param
    config_param :coloregion, :string
    config_param :username, :string
    config_param :passwordFile, :string
    config_param :hardware, :string, :default => "SDFLEX"

    def configure(conf)
      super
        @hwtDeviceURI = Hash["Dell_PowerEdge_iDRAC"=>"Systems/System.Embedded.1", "SDFLEX" => "Chassis/RMC"]
        @deviceRackURI = Hash["Dell_PowerEdge_iDRAC"=>"Systems/System.Embedded.1", "SDFLEX" => "Chassis/RackGroup"]
    end

    def start
      super
    end

    def filter(tag, time, record)
     begin
      # REMOTE_ADDR is the IP the event was sent from
      rmcSN = getMachineIdentifier(record["REMOTE_ADDR"])
      if tag.include? "alert"
        rgSN = getRackGroupIdentifier(record["REMOTE_ADDR"])
      end
     rescue SecurityError => se
      record["error"] = "Error calling redfish API: #{se.message}"
     end
     record["RMCSerialNumber"] = rmcSN
     # BaseChassisSerialNumber is used as the identifier by OEMs
     record["BaseChassisSerialNumber"] = rgSN
     record
    end

    def callRedfishGetAPI(host, resourceURI)
      uri = URI.parse("https://#{host}:443/redfish/v1/#{resourceURI}")
      
      https = Net::HTTP.new(uri.host, uri.port)
      https.use_ssl = true
      https.verify_mode = OpenSSL::SSL::VERIFY_NONE

      header = {'Content-Type': 'application/json'}
      request = Net::HTTP::Get.new(uri.request_uri, header)
      request.basic_auth(username, getPassword())

      response = https.request(request)

      if response.code == "200"
        return JSON.parse(response.body)
      else 
        raise SecurityError
      end
    end

    #we are using nodeID as the unique identifier for dell iDRAC
    #also, for dell nodeID=SKU=ChassisServiceTag but differs from SN
    def getMachineIdentifier(host)
      res = callRedfishGetAPI(host, @hwtDeviceURI[hardware])
      if @hardware == "Dell_PowerEdge_iDRAC"
        return res["SKU"]
      end
      return res["SerialNumber"]
    end

    def getRackGroupIdentifier(host)
      res = callRedfishGetAPI(host, @deviceRackURI[hardware])
      if @hardware == "Dell_PowerEdge_iDRAC"
        return res["SKU"]
      end
      return res["SerialNumber"]
    end

    def getPassword()
      File.read(passwordFile).strip
    end
  end
end