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
    keyVaultName testvault
    msiClientId testclientid
    secretName testsecret
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

  # --- CWE-522 (insufficiently protected credentials) coverage: getPassword fetches
  # the credential live from Key Vault via IMDS and caches it in memory only, with
  # a short retry against transient failures -- there is no password file on disk. ---

  def create_driver_with_stubbed_fetch(conf = CONFIG, &fetch_stub)
    d = Fluent::Test::Driver::Filter.new(Fluent::ProcessRedfishAlert) do
      define_method(:retry_backoff_seconds) { 0 } # don't sleep in tests
    end.configure(conf)
    calls = []
    d.instance.define_singleton_method(:fetch_msi_token) { "test-token" }
    d.instance.define_singleton_method(:fetch_key_vault_secret) do |token|
      calls << token
      fetch_stub.call(calls.length)
    end
    [d, calls]
  end

  def test_get_password_fetches_and_caches
    d, calls = create_driver_with_stubbed_fetch { |_n| "s3cr3t" }
    assert_equal("s3cr3t", d.instance.getPassword())
    assert_equal("s3cr3t", d.instance.getPassword())
    assert_equal(1, calls.length, "second call within TTL should be served from cache, not refetched")
  end

  def test_get_password_refetches_after_cache_expiry
    d, calls = create_driver_with_stubbed_fetch { |n| "s3cr3t-#{n}" }
    assert_equal("s3cr3t-1", d.instance.getPassword())
    d.instance.instance_variable_set(:@cacheExpiresAt, Time.now - 1)
    assert_equal("s3cr3t-2", d.instance.getPassword())
    assert_equal(2, calls.length)
  end

  def test_get_password_retries_then_succeeds
    d, calls = create_driver_with_stubbed_fetch do |n|
      raise "transient failure" if n < 2
      "s3cr3t"
    end
    assert_equal("s3cr3t", d.instance.getPassword())
    assert_equal(2, calls.length)
  end

  def test_get_password_raises_after_max_attempts
    d, calls = create_driver_with_stubbed_fetch { |_n| raise "always fails" }
    assert_raise(SecurityError) do
      d.instance.getPassword()
    end
    assert_equal(2, calls.length)
  end

  # --- Real HTTP-layer coverage for fetch_msi_token / fetch_key_vault_secret: stub
  # only Net::HTTP's network boundary (Net::HTTP.start / Net::HTTP.new(...).request),
  # so the plugin's actual URI/query/header-building and response-parsing code runs
  # for real, instead of being fully bypassed like in the getPassword tests above. ---

  FakeHttpResponse = Struct.new(:code, :body)

  def teardown
    Net::HTTP.singleton_class.send(:define_method, :start, @orig_net_http_start) if @orig_net_http_start
    Net::HTTP.singleton_class.send(:define_method, :new, @orig_net_http_new) if @orig_net_http_new
  end

  def stub_net_http_start(response)
    @orig_net_http_start ||= Net::HTTP.singleton_class.instance_method(:start)
    Net::HTTP.define_singleton_method(:start) do |*_args, &blk|
      fake_http = Object.new
      fake_http.define_singleton_method(:request) { |_req| response }
      blk.call(fake_http)
    end
  end

  def stub_net_http_new(response)
    @orig_net_http_new ||= Net::HTTP.singleton_class.instance_method(:new)
    Net::HTTP.define_singleton_method(:new) do |*_args|
      fake_http = Object.new
      [:use_ssl=, :verify_mode=, :open_timeout=, :read_timeout=].each do |setter|
        fake_http.define_singleton_method(setter) { |_v| }
      end
      fake_http.define_singleton_method(:request) { |_req| response }
      fake_http
    end
  end

  def test_fetch_msi_token_parses_access_token_from_imds_response
    d = create_driver(CONFIG)
    stub_net_http_start(FakeHttpResponse.new('200', '{"access_token":"abc123"}'))
    assert_equal("abc123", d.instance.fetch_msi_token)
  end

  def test_fetch_msi_token_raises_on_non_200
    d = create_driver(CONFIG)
    stub_net_http_start(FakeHttpResponse.new('403', 'forbidden'))
    assert_raise(RuntimeError) do
      d.instance.fetch_msi_token
    end
  end

  def test_fetch_key_vault_secret_parses_value_from_response
    d = create_driver(CONFIG)
    stub_net_http_new(FakeHttpResponse.new('200', '{"value":"s3cr3t"}'))
    assert_equal("s3cr3t", d.instance.fetch_key_vault_secret("test-token"))
  end

  def test_fetch_key_vault_secret_raises_on_non_200
    d = create_driver(CONFIG)
    stub_net_http_new(FakeHttpResponse.new('404', 'not found'))
    assert_raise(RuntimeError) do
      d.instance.fetch_key_vault_secret("test-token")
    end
  end
end
