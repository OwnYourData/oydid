#!/usr/bin/env ruby
# encoding: utf-8

require 'securerandom'
require 'httparty'
require 'optparse'
require 'uri'
require 'oydid'

LOCATION_PREFIX = "@"
DEFAULT_LOCATION = "https://oydid.ownyourdata.eu"
VERSION = "0.4.7"

# internal functions -------------------------------

def delete(did, options)
    doc_location = options[:doc_location]
    if doc_location.to_s == ""
        if did.include?(LOCATION_PREFIX)
            hash_split = did.split(LOCATION_PREFIX)
            did = hash_split[0]
            doc_location = hash_split[1]
        end
    end
    if doc_location.to_s == ""
        doc_location = DEFAULT_LOCATION
    end
    did = did.delete_prefix("did:oyd:")

    if options[:doc_key].nil?
        if options[:doc_pwd].nil?
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: missing document key"
                else
                    puts '{"error": "missing document key"}'
                end
            end
            exit 1
        else
            privateKey, msg = Oydid.generate_private_key(options[:doc_pwd].to_s, 'ed25519-priv')
        end
    else
        privateKey, msg = Oydid.read_private_key(options[:doc_key].to_s)
        if privateKey.nil?
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: missing document key"
                else
                    puts '{"error": "missing document key"}'
                end
            end
            exit 1
        end        
    end
    if options[:rev_key].nil?
        if options[:rev_pwd].nil?
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: missing revocation key"
                else
                    puts '{"error": "missing revocation key"}'
                end
            end
            exit 1
        else
            revocationKey, msg = Oydid.generate_private_key(options[:rev_pwd].to_s, 'ed25519-priv')
        end
    else
        revocationKey, msg = Oydid.read_private_key(options[:rev_key].to_s)
        if revocationKey.nil?
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: missing revocation key"
                else
                    puts '{"error": "missing revocation key"}'
                end
            end
            exit 1
        end
    end

    did_data = {
        "dockey": privateKey,
        "revkey": revocationKey
    }
    oydid_url = doc_location.to_s + "/doc/" + did.to_s
    retVal = HTTParty.delete(oydid_url,
        headers: { 'Content-Type' => 'application/json' },
        body: did_data.to_json )
    if retVal.code != 200
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Registry Error: " + retVal.parsed_response("error").to_s rescue 
                    puts "Error: invalid response from " + oydid_url.to_s
            else
                puts '{"error": "' + retVal.parsed_response['error'].to_s + '", "source": "registry"}' rescue
                    puts '{"error": "invalid response from ' + oydid_url.to_s + '"}'
            end
        end
        exit 1
    end
    return [did, ""]
end

# Semantic Container OYDID functions -------------------------------

def sc_init(options)
    sc_info_url = options[:location].to_s + "/api/info"
    sc_info = HTTParty.get(sc_info_url,
        headers: {'Authorization' => 'Bearer ' + options[:token].to_s}).parsed_response rescue {}

    # build DID doc element
    image_hash = sc_info["image_hash"].to_s.delete_prefix("sha256:") rescue ""
    content = {
        "service_endpoint": sc_info["serviceEndPoint"].to_s + "/api/data",
        "image_hash": image_hash,
        "uid": sc_info["uid"]
    }

    # set options and write DID
    sc_options = options.dup
    sc_options[:location] = sc_info["serviceEndPoint"] || options[:location]
    sc_options[:doc_location] = sc_options[:location]
    sc_options[:log_location] = sc_options[:location]
    sc_options[:silent] = true
    did, msg = Oydid.write([content.to_json], nil, "create", sc_options)
    if did.nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: " + msg.to_s
            else
                puts '{"error": "' + msg + '"}'
            end
        end
        return [nil, ""]
    end

    did_info, msg = Oydid.read(did, options)
    if did_info.nil?
        return [nil, "cannot resolve DID (on sc_init)"]
    end
    if did_info["error"] != 0
        return [nil, did_info["message"].to_s]
    end
    doc_pub_key = did_info["doc"]["key"].split(":")[0].to_s rescue ""

    # create OAuth App for DID in Semantic Container
    response = HTTParty.post(options[:location].to_s + "/oauth/applications",
        headers: { 'Content-Type'  => 'application/json',
                   'Authorization' => 'Bearer ' + options[:token].to_s },
        body: { name: doc_pub_key, 
                scopes: "admin write read" }.to_json )

    # print DID
    if options[:silent].nil? || !options[:silent]
        retVal = {"did": did}.to_json
        puts retVal
    end

end

def sc_token(did, options)
    if options[:doc_key].nil?
        if options[:doc_pwd].nil?
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: private key not found"
                else
                    puts '{"error": "private key not found"}'
                end
            end
            exit 1
        else
            privateKey, msg = Oydid.generate_private_key(options[:doc_pwd].to_s, 'ed25519-priv')
        end
    else
        privateKey, msg = Oydid.read_private_key(options[:doc_key].to_s)
        if privateKey.nil?
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: private key not found"
                else
                    puts '{"error": "private key not found"}'
                end
            end
            exit 1
        end
    end
    if did.include?(LOCATION_PREFIX)
        hash_split = did.split(LOCATION_PREFIX)
        doc_location = hash_split[1]
    end

    # check if provided private key matches pubkey in DID document
    did_info, msg = Oydid.read(did, options)
    if did_info.nil?
        return [nil, "cannot resolve DID (on sc_token)"]
    end
    if did_info["error"] != 0
        return [nil, did_info["message"].to_s]
    end
    if did_info["doc"]["key"].split(":")[0].to_s != Oydid.public_key(privateKey).first
        if options[:silent].nil? || !options[:silent]
            puts "Error: private key does not match DID document"
            if options[:json].nil? || !options[:json]
                puts "Error: private key does not match DID document"
            else
                puts '{"error": "private key does not match DID document"}'
            end
        end
        exit 1
    end

    # authenticate against container
    init_url = doc_location + "/api/oydid/init"
    sid = SecureRandom.hex(20).to_s

    response = HTTParty.post(init_url,
        headers: { 'Content-Type' => 'application/json' },
        body: { "session_id": sid, 
                "public_key": Oydid.public_key(privateKey).first }.to_json ).parsed_response rescue {}
    if response["challenge"].nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: invalid container authentication"
            else
                puts '{"error": "invalid container authentication"}'
            end
        end
        exit 1
    end
    challenge = response["challenge"].to_s

    # sign challenge and request token
    token_url = doc_location + "/api/oydid/token"
    response = HTTParty.post(token_url,
        headers: { 'Content-Type' => 'application/json' },
        body: { "session_id": sid, 
                "signed_challenge": Oydid.sign(challenge, privateKey).first }.to_json).parsed_response rescue {}
    puts response.to_json

end

def sc_create(content, did, options)
    # validation
    c = JSON.parse(content.join("")) rescue {}
    if c["service_endpoint"].nil?
        if options[:json].nil? || !options[:json]
            puts "Error: missing service endpoint"
        else
            puts '{"error": "missing service endpoint"}'
        end
        exit 1
    end
    if c["scope"].nil?
        if options[:json].nil? || !options[:json]
            puts "Error: missing scope"
        else
            puts '{"error": "missing scope"}'
        end
        exit 1
    end

    # get Semantic Container location from DID
    did_info, msg = Oydid.read(did, options)
    if did_info.nil?
        return [nil, "cannot resolve DID (on sc_create)"]
    end
    if did_info["error"] != 0
        return [nil, did_info["message"].to_s]
    end
    sc_url = did_info["doc"]["doc"]["service_endpoint"]
    baseurl = URI.join(sc_url, "/").to_s.delete_suffix("/")

    sc_options = options.dup
    sc_options[:location] = baseurl
    sc_options[:doc_location] = sc_options[:location]
    sc_options[:log_location] = sc_options[:location]
    sc_options[:silent] = true
    new_did, msg = Oydid.write([c.to_json], nil, "create", sc_options)
    if new_did.nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: " + msg.to_s
            else
                puts '{"error": "' + msg + '"}'
            end
        end
        return [nil, ""]
    end

    did_info, msg = Oydid.read(new_did, sc_options)
    if did_info.nil?
        return [nil, "cannot resolve DID (on sc_create - new_did)"]
    end
    if did_info["error"] != 0
        return [nil, did_info["message"].to_s]
    end
    doc_pub_key = did_info["doc"]["key"].split(":")[0].to_s rescue ""

    # create OAuth App for DID in Semantic Container
    response = HTTParty.post(sc_options[:location].to_s + "/oauth/applications",
        headers: { 'Content-Type'  => 'application/json',
                   'Authorization' => 'Bearer ' + options[:token].to_s },
        body: { name: doc_pub_key, 
                scopes: c["scope"],
                query: c["service_endpoint"] }.to_json )

    # !!! add error handling (e.g., for missing token)

    # print DID
    if options[:silent].nil? || !options[:silent]
        retVal = {"did": new_did}.to_json
        puts retVal
    end
end

# user info -------------------------------

def print_version()
    puts VERSION.to_s + " (oydid gem: v" + Gem.loaded_specs["oydid"].version.to_s + ")"
end

def print_help()
    puts "oydid - manage DIDs using the oyd:did method [version " + VERSION + "]"
    puts ""
    puts "Usage: oydid [OPERATION] [OPTION]"
    puts ""
    puts "OPERATION"
    puts "  create    - new DID, reads doc from STDIN"
    puts "  read      - output DID Document for given DID in option"
    puts "  update    - update DID Document, reads doc from STDIN and DID specified"
    puts "              as option"
    puts "  revoke    - revoke DID by publishing revocation entry"
    puts "  delete    - remove DID and all associated records (only for testing)"
    puts "  log       - print relevant log for given DID or log entry hash"
    puts "  logs      - print all available log entries for given DID or log hash"
    puts "  dag       - print graph for given DID"
    puts "  clone     - clone DID to new location"
    puts "  delegate  - add log entry with additional keys for validating signatures"
    puts "              of document or revocation entries"
    puts "  challenge - publish challenge for given DID and revoke specified as"
    puts "              options"
    puts "  confirm   - confirm specified clones or delegates for given DID"
    puts ""
    puts "Semantic Container operations:"
    puts "  sc_init   - create initial DID for a Semantic Container "
    puts "              (requires TOKEN with admin scope)"
    puts "  sc_token  - retrieve OAuth2 bearer token using DID Auth"
    puts "  sc_create - create additional DID for specified subset of data and"
    puts "              scope"
    puts ""
    puts "OPTIONS"
    puts "     --doc-key DOCUMENT-KEY        - filename with Multibase encoded "
    puts "                                     private key for signing documents"
    puts "     --doc-pwd DOCUMENT-PASSWORD   - password for private key for "
    puts "                                     signing documents"
    puts " -h, --help                        - dispay this help text"
    puts "     --json-output                 - write response as JSON object"
    puts " -l, --location LOCATION           - default URL to store/query DID data"
    puts "     --rev-key REVOCATION-KEY      - filename with Multibase encoded "
    puts "                                     private key for signing a revocation"
    puts "     --rev-pwd REVOCATION-PASSWORD - password for private key for signing"
    puts "                                     a revocation"
    puts "     --show-hash                   - for log operation: additionally show"
    puts "                                     hash value of each entry"
    puts "     --show-verification           - display raw data and steps for"
    puts "                                     verifying DID resolution process"
    puts "     --silent                      - suppress any output"
    puts "     --timestamp TIMESTAMP         - timestamp in UNIX epoch to be used"
    puts "                                     (only for testing)"
    puts " -t, --token TOKEN                 - OAuth2 bearer token to access "
    puts "                                     Semantic Container"
    puts "     --trace                       - display trace/debug information when"
    puts "                                     processing request"
    puts " -v, --version                     - display version number"
    puts "     --w3c-did                     - display DID Document in W3C conform"
    puts "                                     format"
end

# main -------------------------------

# commandline options
options = { }
opt_parser = OptionParser.new do |opt|
  opt.banner = "Usage: #{$0} OPERATION [OPTIONS]"
  opt.separator  ""
  opt.separator  "OPERATION"
  opt.separator  "OPTIONS"

  options[:log_complete] = false
  options[:show_hash] = false
  options[:show_verification] = false
  opt.on("-l","--location LOCATION","default URL to store/query DID data") do |loc|
    options[:location] = loc
  end
  opt.on("-t","--trace","show trace information when reading DID") do |trc|
    options[:trace] = true
  end
  opt.on("--silent") do |s|
    options[:silent] = true
  end
  opt.on("--show-hash") do |s|
    options[:show_hash] = true
  end
  opt.on("--show-verification") do |s|
    options[:show_verification] = true
  end
  opt.on("--w3c-did") do |w3c|
    options[:w3cdid] = true
  end
  opt.on("--json-output") do |j|
    options[:json] = true
  end
  opt.on("--doc-key DOCUMENT-KEY") do |dk|
    options[:doc_key] = dk
  end
  opt.on("--rev-key REVOCATION-KEY") do |rk|
    options[:rev_key] = rk
  end
  opt.on("--doc-pwd DOCUMENT-PASSWORD") do |dp|
    options[:doc_pwd] = dp
  end
  opt.on("--rev-pwd REVOCATION-PASSWORD") do |rp|
    options[:rev_pwd] = rp
  end
  opt.on("-t", "--token TOKEN", "token to access Semantic Container") do |t|
    options[:token] = t
  end
  opt.on("--ts TIMESTAMP") do |ts|
    options[:ts] = ts.to_i
  end
  opt.on("-h", "--help") do |h|
    print_help()
    exit(0)
  end
  opt.on("-v", "--version") do |h|
    print_version()
    exit(0)
  end
end
opt_parser.parse!

operation = ARGV.shift rescue ""
input_did = ARGV.shift rescue ""
if input_did.to_s == "" && operation.to_s.start_with?("did:oyd:")
    input_did = operation
    operation = "read"
end

if operation == "create" || operation == "sc_create" || operation == "update" 
    content = []
    ARGF.each_line { |line| content << line }
end

if options[:doc_location].nil?
    options[:doc_location] = options[:location]
end
if options[:log_location].nil?
    options[:log_location] = options[:location]
end

case operation.to_s
when "create"
    did, msg = Oydid.create(content,options)
    if did.nil?
        if msg.to_s != ""
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: " + msg.to_s
                else
                    puts '{"error": "' + msg + '"}'
                end
            end
        end
        exit(-1)
    else
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "created " + did
            else
                puts '{"did": "did:oyd:"' + did.to_s + '", "operation": "create"}'
            end
        end
    end
when "read"
    result, msg = Oydid.read(input_did, options)
    if result.nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                if  options[:show_verification]
                    puts result["verification"]
                    puts "=== end of verification output ==="
                    puts ""
                end
                puts "Error: cannot resolve DID (on reading DID)"
            else
                puts '{"error": "cannot resolve DID (on reading DID)"}'
            end
        end
        exit (-1)
    end
    if result["error"] != 0
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                if  options[:show_verification]
                    puts result["verification"]
                    puts "=== end of verification output ==="
                    puts ""
                end
                puts "Error: " + result["message"].to_s
            else
                puts '{"error": "' + result["message"].to_s + '"}'
            end
        end
        exit(-1)
    end
    if !options[:trace]
        if options[:w3cdid]
            w3c_did = Oydid.w3c(result, options)
            if options[:silent].nil? || !options[:silent]
                puts w3c_did.to_json
            end
        else
            if (options[:silent].nil? || !options[:silent])
                if  options[:show_verification]
                    puts result["verification"]
                    puts "=== end of verification output ==="
                    puts ""
                end
                puts result["doc"].to_json
            end
        end
    end
when "clone"
    did, msg = Oydid.clone(input_did, options)
    if did.nil?
        if msg.to_s != ""
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: " + msg.to_s
                else
                    puts '{"error": "' + msg + '"}'
                end
            end
        end
        exit(-1)
    else
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "cloned " + did
            else
                puts '{"did": "did:oyd:"' + did.to_s + '", "operation": "clone"}'
            end
        end
    end
when "log", "logs"
    if operation.to_s == "logs"
        options[:log_complete] = true
    end
    log_hash = input_did
    result, msg = Oydid.read(input_did, options)
    if result.nil?
        if options[:log_location].nil?
            if input_did.include?(LOCATION_PREFIX)
                retVal = input_did.split(LOCATION_PREFIX)
                log_hash = retVal[0]
                log_location = retVal[1]
            end
        else
            log_location = options[:log_location]
        end
        if log_location.to_s == ""
            log_location = DEFAULT_LOCATION
        end
        if !(log_location == "" || log_location == "local")
            if !log_location.start_with?("http")
                log_location = "https://" + log_location
            end
        end
        result = HTTParty.get(log_location.to_s + "/log/" + log_hash.to_s)
        if options[:silent].nil? || !options[:silent]
            result = JSON.parse(result.to_s)
            if options[:show_hash]
                result = Oydid.add_hash(result)
            end
            puts result.to_json
        end
    else
        if result["error"] != 0
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: " + result["message"].to_s
                else
                    puts '{"error": "' + result["message"].to_s + '"}'
                end
            end
        else
            if options[:silent].nil? || !options[:silent]
                result = result["log"]
                if options[:show_hash]
                    result = Oydid.add_hash(result)
                end
                puts result.to_json
            end
        end
    end
when "dag"
    options[:trace] = true
    result, msg = Oydid.read(input_did, options)
    if result.nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: cannot resolve DID (on writing DAG)"
            else
                puts '{"error": "cannot resolve DID (on writing DAG)"}'
            end
        end
        exit (-1)
    end
    if result["error"] != 0
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: " + result["message"].to_s
            else
                puts '{"error": "' + result["message"].to_s + '"}'
            end
        end
        exit(-1)
    end
when "update"
    did, msg = Oydid.update(content, input_did, options)
    if did.nil?
        if msg.to_s != ""
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: " + msg.to_s
                else
                    puts '{"error": "' + msg + '"}'
                end
            end
        end
        exit(-1)
    else
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "updated " + did
            else
                puts '{"did": "did:oyd:"' + did.to_s + '", "operation": "update"}'
            end
        end
    end
when "revoke"
    did, msg = Oydid.revoke(input_did, options)
    if did.nil?
        if msg.to_s != ""
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: " + msg.to_s
                else
                    puts '{"error": "' + msg + '"}'
                end
            end
        end
        exit(-1)
    else
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "revoked " + did
            else
                puts '{"did": "did:oyd:"' + did.to_s + '", "operation": "revoke"}'
            end
        end
    end

when "delete"
    did, msg = delete(input_did, options)
    if did.nil?
        if msg.to_s != ""
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: " + msg.to_s
                else
                    puts '{"error": "' + msg + '"}'
                end
            end
        end
        exit(-1)
    else
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "deleted " + did
            else
                puts '{"did": "did:oyd:"' + did.to_s + '", "operation": "delete"}'
            end
        end
    end
when "sc_init"
    sc_init(options)
when "sc_token"
    sc_token(input_did, options)
when "sc_create"
    sc_create(content, input_did, options)

when "delegate", "challenge", "confirm"
    if options[:json].nil? || !options[:json]
        puts "Error: function not yet available"
    else
        puts '{"error": "function not yet available"}'
    end
else
    print_help()
end
