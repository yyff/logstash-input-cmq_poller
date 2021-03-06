# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/plugin_mixins/http_client"
require "socket" # for Socket.gethostname
require "manticore"
require "rufus/scheduler"
require "json"
require_relative "cmq/cmq"

class LogStash::Inputs::CMQ_Poller < LogStash::Inputs::Base
  include LogStash::PluginMixins::HttpClient

  config_name "cmq_poller"

  default :codec, "json" # ":codec" begin with colon(:) is a symbol: http://rubylearning.com/satishtalim/ruby_symbols.html

  # A Hash of urls in this format : `"name" => "url"`.
  # The name and the url will be passed in the outputed event
  config :urls, :validate => :hash, :required => true

  config :interval, :validate => :number, :obsolete => "The interval options is obsolete. Use schedule instead"

  # Schedule of when to periodically poll from the urls
  # Format: A hash with
  #   + key: "cron" | "every" | "in" | "at"
  #   + value: string
  # Examples:
  #   a) { "every" => "1h" }
  #   b) { "cron" => "* * * * * UTC" }
  # See: rufus/scheduler for details about different schedule options and value string format
  config :schedule, :validate => :hash, :required => true

  # Define the target field for placing the received data. If this setting is omitted, the data will be stored at the root (top level) of the event.
  config :target, :validate => :string

  # If you'd like to work with the request/response metadata.
  # Set this value to the name of the field you'd like to store a nested
  # hash of metadata.
  config :metadata_target, :validate => :string, :default => '@metadata'

  public
  Schedule_types = %w(cron every at in)
  def register
    @host = Socket.gethostname.force_encoding(Encoding::UTF_8)

    @logger.info("Registering http_poller Input", :type => @type, :schedule => @schedule, :timeout => @timeout)

    setup_requests!
  end

  def stop
    Stud.stop!(@interval_thread) if @interval_thread
    @scheduler.stop if @scheduler
  end

  private
  def setup_requests!
    @requests = Hash[@urls.map {|name, url| [name, normalize_request(url)] }]
  end

  private
  def normalize_request(url_or_spec)
    # if url_or_spec.is_a?(String)
    #   res = [:get, url_or_spec] 
    # elsif url_or_spec.is_a?(Hash)
    if url_or_spec.is_a?(Hash)
      # The client will expect keys / values
      spec = Hash[url_or_spec.clone.map {|k,v| [k, v] }] # symbolize keys
      @logger.debug("spec: ", spec)
      # method and url aren't really part of the options, so we pull them out
      # method = (spec.delete(:method) || :get).to_sym.downcase
      # url = spec.delete(:url)

      # Manticore wants auth options that are like {:auth => {:user => u, :pass => p}}
      # We allow that because earlier versions of this plugin documented that as the main way to
      # to do things, but now prefer top level "user", and "password" options
      # So, if the top level user/password are defined they are moved to the :auth key for manticore
      # if those attributes are already in :auth they still need to be transformed to symbols
      # auth = spec[:auth]
      # user = spec.delete(:user) || (auth && auth["user"])
      # password = spec.delete(:password) || (auth && auth["password"])
      
      # if user.nil? ^ password.nil?
      #   raise LogStash::ConfigurationError, "'user' and 'password' must both be specified for input HTTP poller!"
      # end

      # if user && password
      #   spec[:auth] = {
      #     user: user, 
      #     pass: password,
      #     eager: true
      #   } 
      # end
      # res = [method, url, spec]
      if !spec["Url"] || !spec["SecretKey"] || !spec["Region"] || !spec["SecretId"] || !spec["QueueName"] || !spec["PollingWaitSeconds"]
        raise LogStash::ConfigurationError, "lack of one or more configure items: Url, SecretKey, Region, SecretId, QueueName, PollingWaitSeconds"
      end
      @cmq_api = CMQAPI.new(spec)
      res = spec
    else
      raise LogStash::ConfigurationError, "Invalid URL or request spec: '#{url_or_spec}', expected a String or Hash!"
    end

    # validate_request!(url_or_spec, res)
    res
  end

  private
  def validate_request!(url_or_spec, request)
    method, url, spec = request

    raise LogStash::ConfigurationError, "Invalid URL #{url}" unless URI::DEFAULT_PARSER.regexp[:ABS_URI].match(url)

    raise LogStash::ConfigurationError, "No URL provided for request! #{url_or_spec}" unless url
    if spec && spec[:auth]
      if !spec[:auth][:user]
        raise LogStash::ConfigurationError, "Auth was specified, but 'user' was not!"
      end
      if !spec[:auth][:pass]
        raise LogStash::ConfigurationError, "Auth was specified, but 'password' was not!"
      end
    end

    request
  end

  public
  def run(queue)
    setup_schedule(queue)
  end

  def setup_schedule(queue)
    #schedule hash must contain exactly one of the allowed keys
    msg_invalid_schedule = "Invalid config. schedule hash must contain " +
      "exactly one of the following keys - cron, at, every or in"
    raise Logstash::ConfigurationError, msg_invalid_schedule if @schedule.keys.length !=1
    schedule_type = @schedule.keys.first
    schedule_value = @schedule[schedule_type]
    raise LogStash::ConfigurationError, msg_invalid_schedule unless Schedule_types.include?(schedule_type)

    @scheduler = Rufus::Scheduler.new(:max_work_threads => 1)
    #as of v3.0.9, :first_in => :now doesn't work. Use the following workaround instead
    opts = schedule_type == "every" ? { :first_in => 0.01 } : {} 
    @scheduler.send(schedule_type, schedule_value, opts) { run_once(queue) }
    @scheduler.join
  end

  def run_once(queue)
    @requests.each do |name, request|
      request_async(queue, name, request)
    end

    client.execute!
  end

  private
  def request_async(queue, name, request)
    @logger.debug? && @logger.debug("Fetching URL", :name => name, :url => request)
    started = Time.now    
    # method, url, spec = request
    
    # real_url = CMQAPI.get_url(request)
    # if !real_url
    #   raise LogStash::ConfigurationError, "get url failed"
    # end
    url = @cmq_api.gen_recv_url()
    @logger.debug("gen recv url: %s" % url)
    
    # puts "real_url: ", real_url
    # method, *request_opts = request
    # client.async.send(method, *request_opts).
    client.async.send(:get, url).
      on_success {|response| handle_success(queue, name, request, response, Time.now - started)}.
      on_failure {|exception|
      handle_failure(queue, name, request, exception, Time.now - started)
    }
  end

  private
  def handle_success(queue, name, request, response, execution_time)
    body = response.body
    # If there is a usable response. HEAD requests are `nil` and empty get
    # responses come up as "" which will cause the codec to not yield anything
    if body && body.size > 0
      # puts "body: ", body
      @logger.debug("body: %s" % body)
      hashbody = JSON.parse(body)
      @logger.debug("hashbody: %s" % hashbody)
      # puts "hashbody: ", hashbody
      if hashbody["code"] != 0 
        @logger.info("code:%d not 0, response body: %s" % [hashbody["code"], body])
        return
      end
      ok = @cmq_api.delete_msg(hashbody["receiptHandle"])
      if !ok 
        @logger.error("delete msg failed")
        return
      end
      decode_and_flush(@codec, body) do |decoded|
        # puts "decoded: ", decoded
        event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
        logger.debug("event: %s" % event)
        
        handle_decoded_event(queue, name, request, response, event, execution_time)
      end
    else
      event = ::LogStash::Event.new
      handle_decoded_event(queue, name, request, response, event, execution_time)
    end
  end

  private
  def decode_and_flush(codec, body, &yielder)
    codec.decode(body, &yielder)
    codec.flush(&yielder)
  end

  private
  def handle_decoded_event(queue, name, request, response, event, execution_time)
    apply_metadata(event, name, request, response, execution_time)
    decorate(event)
    queue << event
  rescue StandardError, java.lang.Exception => e
    @logger.error? && @logger.error("Error eventifying response!",
                                    :exception => e,
                                    :exception_message => e.message,
                                    :name => name,
                                    :url => request,
                                    :response => response
    )
  end

  private
  # Beware, on old versions of manticore some uncommon failures are not handled
  def handle_failure(queue, name, request, exception, execution_time)
    event = LogStash::Event.new
    apply_metadata(event, name, request)

    event.tag("_http_request_failure")

    # This is also in the metadata, but we send it anyone because we want this
    # persisted by default, whereas metadata isn't. People don't like mysterious errors
    event.set("http_request_failure", {
      "request" => structure_request(request),
      "name" => name,
      "error" => exception.to_s,
      "backtrace" => exception.backtrace,
      "runtime_seconds" => execution_time
   })

    queue << event
  rescue StandardError, java.lang.Exception => e
      @logger.error? && @logger.error("Cannot read URL or send the error as an event!",
                                      :exception => e,
                                      :exception_message => e.message,
                                      :exception_backtrace => e.backtrace,
                                      :name => name)

      # If we are running in debug mode we can display more information about the
      # specific request which could give more details about the connection.
      @logger.debug? && @logger.debug("Cannot read URL or send the error as an event!",
                                      :exception => e,
                                      :exception_message => e.message,
                                      :exception_backtrace => e.backtrace,
                                      :name => name,
                                      :url => request)
  end

  private
  def apply_metadata(event, name, request, response=nil, execution_time=nil)
    return unless @metadata_target
    event.set(@metadata_target, event_metadata(name, request, response, execution_time))
  end

  private
  def event_metadata(name, request, response=nil, execution_time=nil)
    m = {
        "name" => name,
        "host" => @host,
        "request" => structure_request(request),
      }

    m["runtime_seconds"] = execution_time

    if response
      m["code"] = response.code
      m["response_headers"] = response.headers
      m["response_message"] = response.message
      m["times_retried"] = response.times_retried
    end

    m
  end

  private
  # Turn [method, url, spec] requests into a hash for friendlier logging / ES indexing
  def structure_request(request)
    method, url, spec = request
    # Flatten everything into the 'spec' hash, also stringify any keys to normalize
    Hash[(spec||{}).merge({
      "method" => method.to_s,
      "url" => url,
    }).map {|k,v| [k.to_s,v] }]
  end
end
