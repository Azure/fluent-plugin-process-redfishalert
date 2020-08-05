
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

    def configure(conf)
      super
    end

    def start
      super
    end

    def filter(tag, time, record)
     begin
      # REMOTE_ADDR is the IP the event was sent from
      rmcSN = getRMCSerialNumber(record["REMOTE_ADDR"])
      if tag == "redfish.alert"
        rgSN = getRackGroupSerialNumber(record["REMOTE_ADDR"])
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

    def getRMCSerialNumber(host)
      put "WHY\n\n"
      res = callRedfishGetAPI(host, "Chassis/RMC")
      return res["SerialNumber"]
    end

    def getRackGroupSerialNumber(host)
      res = callRedfishGetAPI(host, "Chassis/RackGroup")
      return res["SerialNumber"]
    end

    def getPassword()
      File.read(passwordFile).strip
    end
  end
end