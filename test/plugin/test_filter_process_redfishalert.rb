require 'helper'
require 'tempfile'

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
  
  SUPERMICRO_CONFIG = CONFIG.gsub(/hardware SDFLEX/, 'hardware SUPERMICRO')

  def create_driver(conf)
        Fluent::Test::Driver::Filter.new(Fluent::ProcessRedfishAlert) do
            # for testing
            def getPassword()
                return 'testPassword'
            end

            def callTestRedfishGetAPI(host, resourceURI)
                res = '{
                    "SerialNumber":"123456",
                    "PowerState":"On"
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

            def getPowerState(host)
                res = callTestRedfishGetAPI(host, "uri")
                res["PowerState"]
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
    assert_equal(records[0].length, filtered_records[0].length, "Incorrect record size for SDFLEX")
    assert_equal(filtered_records[0]["RMCSerialNumber"], SerialNumber)
    assert_equal(filtered_records[0]["BaseChassisSerialNumber"], SerialNumber)

    # Test for SUPERMICRO
    filtered_records = filter(records, SUPERMICRO_CONFIG)
    assert_equal(records[0].length, filtered_records[0].length, "Incorrect record size for SUPERMICRO")
    assert_equal(filtered_records[0]["ProductSerialNumber"], SerialNumber)
    assert_equal(filtered_records[0]["ChassisSerialNumber"], SerialNumber)
    assert_equal(filtered_records[0]["PowerState"], "On")
  end

  # --- CWE-918 (SSRF) coverage: validate_host! is what protects callRedfishGetAPI
  # from being pointed at an arbitrary attacker-controlled host via REMOTE_ADDR. ---

  def test_validate_host_allows_private_range
    d = create_driver(CONFIG)
    assert_nothing_raised do
      d.instance.validate_host!("10.1.2.3")
    end
  end

  def test_validate_host_rejects_public_ip
    d = create_driver(CONFIG)
    assert_raise(SecurityError) do
      d.instance.validate_host!("8.8.8.8")
    end
  end

  def test_validate_host_rejects_non_ip_input
    d = create_driver(CONFIG)
    assert_raise(SecurityError) do
      d.instance.validate_host!("not-an-ip")
    end
  end

  def test_validate_host_respects_custom_allowed_ranges
    custom_conf = CONFIG + "\n    allowed_host_ranges 203.0.113.0/24\n"
    d = create_driver(custom_conf)
    assert_nothing_raised do
      d.instance.validate_host!("203.0.113.5")
    end
    assert_raise(SecurityError) do
      d.instance.validate_host!("10.1.2.3")
    end
  end

  # --- CWE-522 (insufficiently protected credentials) coverage: validate_password_file_permissions!
  # is what protects getPassword from silently trusting a loosely-permissioned secret file. ---

  def test_validate_password_file_permissions_accepts_owner_only
    Tempfile.create("password") do |f|
      f.write("secret")
      f.flush
      File.chmod(0600, f.path)
      conf = CONFIG.sub(/passwordFile\s*\n/, "passwordFile #{f.path}\n")
      d = create_driver(conf)
      assert_nothing_raised do
        d.instance.validate_password_file_permissions!
      end
    end
  end

  def test_validate_password_file_permissions_rejects_group_readable
    Tempfile.create("password") do |f|
      f.write("secret")
      f.flush
      File.chmod(0640, f.path)
      conf = CONFIG.sub(/passwordFile\s*\n/, "passwordFile #{f.path}\n")
      d = create_driver(conf)
      assert_raise(SecurityError) do
        d.instance.validate_password_file_permissions!
      end
    end
  end

  def test_validate_password_file_permissions_rejects_missing_file
    conf = CONFIG.sub(/passwordFile\s*\n/, "passwordFile /nonexistent/path/to/password\n")
    d = create_driver(conf)
    assert_raise(SecurityError) do
      d.instance.validate_password_file_permissions!
    end
  end
end
