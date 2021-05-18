require 'helper'

class ProcessRedfishAlertFilterTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  SerialNumber = "123456"

  setup do
    Fluent::Test.setup
  end

  CONFIG = %[
    @type process_redfishalert
    coloregion testcolo
    username testuser
    passwordFile
    hardware SDFLEX
  ]

  def create_driver(conf)
        Fluent::Test::Driver::Filter.new(Fluent::ProcessRedfishAlert) do
            # for testing
            def getPassword()
                return 'testPassword'
            end

            def callTestRedfishGetAPI(host, resourceURI)
                res = '{
                    "SerialNumber":"123456"
                }'

                return JSON.parse(res)
            end

            def getRackGroupIdentifier(host)
                res = callTestRedfishGetAPI(host, "uri")
                res["SerialNumber"]
            end

            def getMachineIdentifier(host)
                res = callTestRedfishGetAPI(host, "uri")
                res["SerialNumber"]
            end
        end.configure(conf)
  end

  def test_configure
      d = create_driver(CONFIG)
      assert_equal 'testcolo', d.instance.coloregion
      assert_equal 'testuser', d.instance.username
  end

  def filter(records, conf = CONFIG)
      d = create_driver(conf)
      d.run(default_tag: "redfish.alert") do
         records.each do |record|
             d.feed(record)
         end
      end
      d.filtered_records
  end

  def test_redfish_filter
    records = [
        # A Sample Redfish Event
        {
            "Name":"Events",
            "Events":[
               {
                  "EventTimestamp":"2020-07-08T21:27:34Z",
                  "MessageArgs":[
                     "rack1/chassis_u24/psu3"
                  ],
                  "Severity":"OK",
                  "Message":"Test Message for rack1/chassis_u24/psu3",
                  "MemberId":"1",
                  "MessageId":"MessageId",
                  "OriginOfCondition":"/URI/to/resource",
                  "EventId":"EventID",
                  "Oem":{},
                  "EventType":"Alert"
               }
            ],
            "@odata.type":"#Event.1.1.2.Event",
            "REMOTE_ADDR":"1.2.3.4"
         }
    ]
    filtered_records = filter(records)
    assert_equal(records[0].length, filtered_records[0].length, "Incorrect record size")
    assert_equal(filtered_records[0]["RMCSerialNumber"], SerialNumber)
    assert_equal(filtered_records[0]["BaseChassisSerialNumber"], SerialNumber)
  end

end