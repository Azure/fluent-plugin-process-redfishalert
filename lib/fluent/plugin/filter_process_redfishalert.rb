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
        @hwtDeviceURI = Hash["Dell_PowerEdge_iDRAC"=>"Systems/System.Embedded.1", "SDFLEX" => "Chassisss/RMC", "SUPERMICRO" => "Systems/1"]
        @deviceRackURI = Hash["Dell_PowerEdge_iDRAC"=>"Systems/System.Embedded.1", "SDFLEX" => "Chassis/RackGroup", "SUPERMICRO" => "Chassis/1"]
        @deviceIDField = Hash["Dell_PowerEdge_iDRAC"=>"SKU", "SDFLEX" => "SerialNumber", "SUPERMICRO" => "SerialNumber"]
        @alternativeEndpointForSDFlex = "Chassis/RMC"
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
        message = "Status code: #{response.statuscode}. Detailed Error: #{response.body}"
        raise SecurityError, message
      end
    end

    def getMachineIdentifier(host)
      if @coloregion == "DSM05A"
        puts "Entered if block"
        begin
          res = callRedfishGetAPI(host, @hwtDeviceURI[hardware])
        rescue Net::HTTPNotFound
          puts "Entered 404 error block"
          res = callRedfishGetAPI(host, @alternativeEndpointForSDFlex) if @hardware == "SDFLEX"
        end
        return res[@deviceIDField[hardware]]
      else
        puts "Entered else block"
        res = callRedfishGetAPI(host,  @alternativeEndpointForSDFlex) if @hardware == "SDFLEX"
        return res[@deviceIDField[hardware]]
      end
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
      File.read(passwordFile).strip
    end
  end
end
