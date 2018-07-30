require 'date'
require 'openssl'
require "erb"
require "net/http"
require "base64"



class CMQAPI
    public
    def initialize(spec)
        @region = spec["Region"]
        @secret_key = spec["SecretKey"]
        @secret_id = spec["SecretId"]
        @queue_name = spec["QueueName"]
        @pollingWaitSeconds = spec["PollingWaitSeconds"]
        @url = spec["Url"]
    end
    public
    def gen_recv_url()
        para = {
            "Action" => "ReceiveMessage",
            "Region" => @region,
            "Nonce" => DateTime.now.strftime('%s'),
            "SecretId" => @secret_id,
            "SignatureMethod" => "HmacSHA256",
            "Timestamp" => DateTime.now.strftime('%s'),
            "queueName" => @queue_name,
            "pollingWaitSeconds" => @pollingWaitSeconds,
        }

        return get_url(para)
    end
    public
    def delete_msg(receipt_handle)
        max_retry = 5
        i = 0
        while i < max_retry do
            para = {
                "Action" => "DeleteMessage",
                "Region" => @region,
                "Nonce" => DateTime.now.strftime('%s'),
                "SecretId" => @secret_id,
                "SignatureMethod" => "HmacSHA256",
                "Timestamp" => DateTime.now.strftime('%s'),
                "queueName" => @queue_name,
                "receiptHandle" => receipt_handle,
            }
            url = get_url(para)
            res = Net::HTTP.get_response(URI(url))
            # puts res
            if res.is_a?(Net::HTTPSuccess)
                puts "[debug]: res body: %s" % res.body
                hashbody = JSON.parse(res.body)
                if hashbody["code"] != 0
                else
                    return true
                end
            else
                puts "[error] http request failed"
            end
            i += 1
            puts "[info] retry cnt: %d" % i
        end
        return false

    end
    private
    def get_url(para)

        url = @url
        host_uri = ""
        if url[0, "https://".length()] == "https://"
            host_uri = url["https://".length()..url.length()-1]
        elsif url[0, "http://".length()] == "http://"
            host_uri = url["http://".length()..url.length()-1]
        else 
            raise Logstash::ConfigurationError, "invalid url format"  
        end
        sig = gen_signature("GET", host_uri, @secret_key, para)
        para["Signature"] = sig
        querys = gen_url_querys(para)
        url_with_query = url + "?" + querys
        return url_with_query
    end

    private
    def gen_signature(method, url, secret_key, para)
        # puts method, url
        origin_sig_str = method + url + "?"
        sorted_para_keys = para.keys.sort()
        # puts sorted_para_keys
        sorted_para_keys.each do |para_key|
            origin_sig_str = origin_sig_str + para_key + "=" + para[para_key] + "&"
        end
        origin_sig_str = origin_sig_str[0, origin_sig_str.length()-1]
        # puts "origin_sig_str:", origin_sig_str
        digest = OpenSSL::Digest.new('sha256')
        sig = OpenSSL::HMAC.digest(digest, secret_key, origin_sig_str)
        t = Base64.strict_encode64(sig)
        return t
        # return t[0, t.length-1]
    end

    private
    def gen_url_querys(para)
        get_paras = ""
        para.each do |key, value|
            v = ERB::Util.url_encode(value)
            get_paras = get_paras + key + "=" + v + "&"
        end
        get_paras = get_paras[0...-1]
        # puts get_paras
        return get_paras
    end
end
