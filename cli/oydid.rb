#!/usr/bin/env ruby
# encoding: utf-8

require 'securerandom'
require 'httparty'
require 'optparse'
require 'uri'
require 'oydid'

LOCATION_PREFIX = "@"
DEFAULT_LOCATION = "https://oydid.ownyourdata.eu"
VERSION = "0.5.0"
LOG_HASH_OPTIONS = {:digest => "sha2-256", :encode => "base58btc"}

# internal functions -------------------------------

def delete(did, options)
    did_orig = did.dup
    doc_location = options[:doc_location]
    if doc_location.to_s == ""
        if did.include?(LOCATION_PREFIX)
            tmp = did.split(LOCATION_PREFIX)
            did = tmp[0]
            doc_location = tmp[1]
        end
        if did.include?(CGI.escape LOCATION_PREFIX)
            tmp = did.split(CGI.escape LOCATION_PREFIX)
            did = tmp[0] 
            doc_location = tmp[1]
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
            privateKey, msg = Oydid.generate_private_key(options[:doc_pwd].to_s, 'ed25519-priv', options)
        end
    else
        privateKey, msg = Oydid.read_private_key(options[:doc_key].to_s, options)
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
            revocationKey, msg = Oydid.generate_private_key(options[:rev_pwd].to_s, 'ed25519-priv', options)
        end
    else
        revocationKey, msg = Oydid.read_private_key(options[:rev_key].to_s, options)
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
    return [did_orig, ""]
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
            privateKey, msg = Oydid.generate_private_key(options[:doc_pwd].to_s, 'ed25519-priv', options)
        end
    else
        privateKey, msg = Oydid.read_private_key(options[:doc_key].to_s, options)
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
    if did_info["doc"]["key"].split(":")[0].to_s != Oydid.public_key(privateKey, options).first
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
                "public_key": Oydid.public_key(privateKey, options).first }.to_json ).parsed_response rescue {}
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
                "signed_challenge": Oydid.sign(challenge, privateKey, options).first }.to_json).parsed_response rescue {}
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
    puts "supported digests: " + Oydid::SUPPORTED_DIGESTS.join(", ") + " (default: " + Oydid::DEFAULT_DIGEST + ")"
    puts "supported encodings: " + Oydid::SUPPORTED_ENCODINGS.join(", ") + " (default: " + Oydid::DEFAULT_ENCODING + ")"
end

def print_help()
    puts "oydid - manage DIDs using the oyd:did method [version " + VERSION + "]"
    puts ""
    puts "Usage: oydid [OPERATION] [OPTION]"
    puts ""
    puts "OPERATION"
    puts " -- DID management --"
    puts "  create     - new DID, reads doc from STDIN"
    puts "  read       - output DID Document for given DID in option"
    puts "  update     - update DID Document, reads doc from STDIN and DID specified"
    puts "               as option (if STDIN is empty payload is unchanged)"
    puts "  revoke     - revoke DID by publishing revocation entry"
    puts ""
    puts " -- Verifiable Credentials & Presentations --"
    puts "  vc         - new VC, reads claim(s) from STDIN"
    puts "  vc-read    - output VC for given identifier in option"
    puts "  vc-push    - new VC and store to repo, reads claim(s) from STDIN"
    puts "  vp         - new VP, reads VC(s) from STDIN"
    puts "  vp-push    - new VP and store in repo, reads VC(s) from STDIN"
    puts "  vp-verify  - read VP from STDIN and verify proof"
    puts ""
    puts " -- OYDID specific --"
    puts "  delete     - remove DID and all associated records (only for testing)"
    puts "  log        - print relevant log for given DID or log entry hash"
    puts "  logs       - print all available log entries for given DID or log hash"
    puts "  dag        - print graph for given DID"
    puts "  fromW3C    - read W3C-conform DID document and convert to OYDID format"
    puts "  toW3C      - read OYDID internal document and convert to W3C-conform"
    puts "               DID document"
    puts "  clone      - clone DID to new location"
    puts "  delegate   - add log entry with additional keys for validating signatures"
    puts "               of document or revocation entries"
    # puts "  challenge - publish challenge for given DID and revoke specified as"
    # puts "              options"
    puts "  confirm    - confirm specified clones or delegates for given DID"
    puts ""
    puts " -- DIDComm messaging --"
    puts "  message    - output plain DIDComm message, reads from STDIN"
    puts "  jws        - output signed DIDComm message, reads from STDIN"
    puts "  jws-verify - read JWS and verify signature"
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
    puts "     --encode ENCODING-ALGORITHM   - specify encoding algorithm for"
    puts "                                     identifier digest (default: base58btc)"
    puts "     --digest HASH-ALGORITHM       - specify digest algorithm for"
    puts "                                     identifier (default: sha2-256)"
    puts " -h, --help                        - dispay this help text"
    puts "     --json-output                 - write response as JSON object"
    puts " -l, --location LOCATION           - default URL to store/query DID data"
    puts "     --rev-key REVOCATION-KEY      - filename with Multibase encoded "
    puts "                                     private key for signing a revocation"
    puts "     --rev-pwd REVOCATION-PASSWORD - password for private key for signing"
    puts "                                     a revocation"
    puts "     --simulate                    - for create/update/revoke operations:"
    puts "                                     only show DID, DID document, logs"
    puts "     --show-hash                   - for log operation: additionally show"
    puts "                                     hash value of each entry"
    puts "     --show-verification           - display raw data and steps for"
    puts "                                     verifying DID resolution process"
    puts "     --silent                      - suppress any output"
    puts " -z  --timestamp TIMESTAMP         - timestamp in UNIX epoch to be used"
    puts "                                     (only for testing)"
    puts " -t, --token TOKEN                 - OAuth2 bearer token to access "
    puts "                                     Semantic Container"
    puts "     --trace                       - display trace/debug information when"
    puts "                                     processing request"
    puts " -v, --version                     - display version number"
    puts "     --w3c-did                     - display DID Document in W3C conform"
    puts "                                     format"
    # fix me: describe DIDComm options
end

# main -------------------------------

# trace = TracePoint.new(:call) { |tp| 
#         if tp.path.include?("oydid-0.5.0") 
#                 p [tp.path, tp.lineno, tp.event, tp.method_id] 
#         end }
# trace.enable

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
  options[:simulate] = false
  options[:encode] = LOG_HASH_OPTIONS[:encode] # base58btc
  options[:digest] = LOG_HASH_OPTIONS[:digest] # sha2-256
  opt.on("-l","--location LOCATION","default URL to store/query DID data") do |loc|
    if !loc.start_with?("http")
        loc = "https://" + loc
    end
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
  opt.on("--digest HASH-ALGORITHM") do |digest|
    options[:digest] = digest
  end
  opt.on("--encode ENCODING-ALGORITHM") do |encode|
    options[:encode] = encode
  end
  opt.on("--doc-key DOCUMENT-KEY-FILE") do |dk|
    options[:doc_key] = dk
  end
  opt.on("--old-doc-key DOCUMENT-KEY-FILE") do |dk|
    options[:old_doc_key] = dk
  end
  opt.on("--rev-key REVOCATION-KEY-FILE") do |rk|
    options[:rev_key] = rk
  end
  opt.on("--old-rev-key REVOCATION-KEY-FILE") do |rk|
    options[:old_rev_key] = rk
  end
  opt.on("--doc-pwd DOCUMENT-PASSWORD") do |dp|
    options[:doc_pwd] = dp
  end
  opt.on("--old-doc-pwd OLD-DOCUMENT-PASSWORD") do |dp|
    options[:old_doc_pwd] = dp
  end
  opt.on("--rev-pwd REVOCATION-PASSWORD") do |rp|
    options[:rev_pwd] = rp
  end
  opt.on("--old-rev-pwd OLD-REVOCATION-PASSWORD") do |rp|
    options[:old_rev_pwd] = rp
  end
  opt.on("--doc-enc DOCUMENTKEY-ENCODED") do |dp|
    options[:doc_enc] = dp
  end
  opt.on("--old-doc-enc OLD-DOCUMENTKEY-ENCODED") do |dp|
    options[:old_doc_enc] = dp
  end
  opt.on("--rev-enc REVOCATIONKEY-ENCODED") do |rp|
    options[:rev_enc] = rp
  end
  opt.on("--old-rev-enc OLD-REVOCATIONKEY-ENCODED") do |rp|
    options[:old_rev_enc] = rp
  end
  opt.on("--simulate") do |simulate|
    options[:simulate] = true
  end
  opt.on("--return-secrets") do |rs|
    options[:return_secrets] = true
  end
  opt.on("-t", "--token TOKEN", "token to access Semantic Container") do |t|
    options[:token] = t
  end
  opt.on("-z", "--timestamp TIMESTAMP") do |ts|
    options[:ts] = ts.to_i
  end

  # VC options
  opt.on("--issuer ISSUER") do |key|
    options[:issuer] = key.to_s
  end
  opt.on("--holder HOLDER") do |key|
    options[:holder] = key.to_s
  end
  
  # auxiliary options
  opt.on("-h", "--help") do |h|
    print_help()
    exit(0)
  end
  opt.on("-v", "--version") do |h|
    print_version()
    exit(0)
  end

  # DIDComm Options
  opt.on("--sign-did DID") do |sign_did|
    options[:sign_did] = sign_did
  end
  opt.on("--type TYPE") do |t|
    options[:didcomm_type] = t.to_s
  end
  opt.on("--from FROM_DID") do |fd|
    options[:didcomm_from_did] = fd.to_s
  end
  opt.on("--to TO_DID") do |td|
    options[:didcomm_to_did] = td.to_s
  end
  opt.on("--hmac_secret HMAC_SECRET") do |secret|
    options[:hmac_secret] = secret.to_s
  end

end
opt_parser.parse!

operation = ARGV.shift rescue ""
input_did = ARGV.shift rescue ""
if input_did.to_s == "" && operation.to_s.start_with?("did:oyd:")
    input_did = operation
    operation = "read"
end
if input_did.to_s != "" && input_did.include?("%40")
    input_did = input_did.sub "%40", "@"
end

case operation.to_s
# JSON input
when "create", # "update", 
     "fromW3C", "toW3C",
     "message", "jws", "encrypt-message", "sign-message",
     "vc", "vc-push", "vp", "vp-push", "vp-verify"
    input_content = []
    ARGF.each_line { |line| input_content << line }
    content = JSON.parse(input_content.join("")) rescue nil
    if content.nil?
        if input_content.collect{|e| e.strip}.join("") != ""
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: invalid payload"
                else
                    puts '{"error": "invalid payload"}'
                end
            end
            exit(-1)
        end
    end
when "update"
    content = []
    ARGF.each_line { |line| content << line }
    content = JSON.parse(content.join("")) rescue nil
    if content.nil?
        result, msg = Oydid.read(input_did, options)
        if result.nil?
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: cannot resolve DID (on updating DID)"
                else
                    puts '{"error": "cannot resolve DID (on updating DID)"}'
                end
            end
            exit (-1)
        end
        if result["error"] == 0
            content = result["doc"]["doc"]
        else
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: " + result["message"].to_s
                else
                    puts '{"error": "' + result["message"].to_s + '"}'
                end
            end
            exit(-1)
        end
    end
# JWT input
when "decrypt-jwt", "verify-jws", "verify-signed-message"
    content = []
    ARGF.each_line { |line| content << line }
    content = content.join('').strip
    if content.nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: empty or invalid payload"
            else
                puts '{"error": "empty or invalid payload"}'
            end
        end
        exit(-1)
    end
end

if options[:doc_location].nil?
    options[:doc_location] = options[:location]
end
if options[:log_location].nil?
    options[:log_location] = options[:location]
end

case operation.to_s
when "create"
    if options[:simulate]
        did_doc, did_key, did_log, msg = Oydid.generate_base(content, "", "create", options)
        did = did_doc[:did]
        didDocument = did_doc[:didDocument]
        l1 = did_log[:l1]
        l2 = did_log[:l2]
        r1 = did_log[:r1]

        # did, didDocument, revoc_log, l1, l2, r1, privateKey, revocationKey, did_old, log_old, msg = Oydid.generate_base(content, "", "create", options)
        # did_doc = [did, didDocument, did_old]
        # did_log = [revoc_log, l1, l2, r1, log_old]
        # did_key = [privateKey, revocationKey]
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
        end
        retVal = {}
        retVal["did"] = Oydid.percent_encode(did.to_s)
        retVal["doc"] = didDocument
        retVal["log_create"] = l1
        retVal["log_terminate"] = l2
        retVal["log_revoke"] = r1
        puts retVal.to_json
    else
        retVal, msg = Oydid.create(content,options)
        if retVal.nil?
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
                    puts "created " + Oydid.percent_encode(retVal["did"].to_s)
                else
                    puts '{"did": "' + Oydid.percent_encode(retVal["did"].to_s) + '", "operation": "create"}'
                end
            end
        end
    end
when "update"
    if options[:simulate]
        did_doc, did_key, did_log, msg = Oydid.generate_base(content, input_did, "update", options)
        did = did_doc[:did]
        didDocument = did_doc[:didDocument]
        did_old = did_doc[:did_old]
        revoc_log = did_log[:revoc_log]
        l1 = did_log[:l1]
        l2 = did_log[:l2]
        r1 = did_log[:r1]
        log_old = did_log[:log_old]
        # did, didDocument, revoc_log, l1, l2, r1, privateKey, revocationKey, did_old, log_old, msg = Oydid.generate_base(content, input_did, "update", options)
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
        end
        retVal = {}
        retVal["did"] = Oydid.percent_encode(did.to_s)
        retVal["did_old"] = Oydid.percent_encode(input_did.to_s)
        retVal["doc"] = didDocument
        retVal["log_revoke_old"] = revoc_log
        retVal["log_update"] = l1
        retVal["log_terminate"] = l2
        retVal["log_revoke"] = r1
        puts retVal.to_json
    else
        didHash = input_did.split(LOCATION_PREFIX)[0] rescue input_did
        didHash = didHash.delete_prefix("did:oyd:")
        # options[:digest] = Oydid.get_digest(didHash).first
        # options[:encode] = Oydid.get_encoding(didHash).first
        retVal, msg = Oydid.update(content, input_did, options)
        if retVal.nil?
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
                    puts "updated " + Oydid.percent_encode(retVal["did"].to_s)
                else
                    puts '{"did": "' + Oydid.percent_encode(retVal["did"].to_s) + '", "operation": "update"}'
                end
            end
        end
    end
when "read"
    # didIdentifier = input_did.split(LOCATION_PREFIX)[0] rescue input_did
    # didIdentifier = didIdentifier.delete_prefix("did:oyd:")
    # options[:digest] = Oydid.get_digest(didIdentifier).first
    # options[:encode] = Oydid.get_encoding(didIdentifier).first
    result, msg = Oydid.read(input_did, options)
    if result.nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
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
    retVal, msg = Oydid.clone(input_did, options)
    if retVal.nil?
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
                puts "cloned " + Oydid.percent_encode(retVal["did"].to_s)
            else
                puts '{"did": "' + Oydid.percent_encode(retVal["did"].to_s) + '", "operation": "clone"}'
            end
        end
    end
when "fromW3C"
    # check if valif W3C DID document
    if content["id"].to_s == ""
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: invalid input (cannot parse DID document)"
            else
                puts '{"error": "invalid input (cannot parse DID document)"}'
            end
        end
        exit(-1)
    end
    if !content["id"].to_s.start_with?("did:oyd:")
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: invalid input (non did:oyd method)"
            else
                puts '{"error": "invalid input (non did:oyd method)"}'
            end
        end
        exit(-1)
    end
    did = content["id"].to_s
    if did.include?(LOCATION_PREFIX)
        tmp = did.split(LOCATION_PREFIX)
        did = tmp[0]
        doc_location = tmp[1]
    end
    if did.include?(CGI.escape LOCATION_PREFIX)
        tmp = did.split(CGI.escape LOCATION_PREFIX)
        did = tmp[0] 
        doc_location = tmp[1]
    end
    retVal, msg = Oydid.retrieve_document_raw(did, "", doc_location, options)
    if retVal.nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: cannot resolve DID"
            else
                puts '{"error": "cannot resolve DID"}'
            end
        end
        exit (-1)
    end
    puts retVal["doc"].to_json
when "toW3C"
    # check if valif did:oyd document
    if content["doc"].to_s == "" || content["key"].to_s == "" || content["log"].to_s == ""
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: invalid input (can't parse OYDID document)"
            else
                puts '{"error": "invalid input (cannot parse OYDID document)"}'
            end
        end
        exit(-1)
    end
    did = Oydid.multi_hash(Oydid.canonical(content.to_json_c14n), options).first
    did_info = {}
    did_info["did"] = Oydid.percent_encode(did)
    did_info["doc"] = content
    retVal, msg = Oydid.w3c(did_info, options)
    if retVal.nil?
        if msg.to_s == ""
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: unknown error"
                else
                    puts '{"error": "unknown error"}'
                end
            end
        else
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
        puts retVal.to_json
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

when "revoke"
    if options[:old_doc_pwd].nil? && !options[:doc_pwd].nil?
        options[:old_doc_pwd] = options[:doc_pwd]
    end
    if options[:old_rev_pwd].nil? && !options[:rev_pwd].nil?
        options[:old_rev_pwd] = options[:rev_pwd]
    end
    did = input_did.delete_prefix("did:oyd:")
    didHash = input_did.split(LOCATION_PREFIX)[0] rescue input_did
    didHash = didHash.delete_prefix("did:oyd:")
    options[:digest] = Oydid.get_digest(didHash).first
    options[:encode] = Oydid.get_encoding(didHash).first    
    if options[:simulate]
        result, msg = Oydid.revoke_base(did, options)
        if result.nil?
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
        end
        retVal = {
            "did": Oydid.percent_encode(input_did.to_s),
            "log": result
        }
        puts retVal.to_json
    else
        did, msg = Oydid.revoke(did, options)
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
                    puts "revoked " + Oydid.percent_encode(did.to_s)
                else
                    puts '{"did": "did:oyd:"' + Oydid.percent_encode(did.to_s) + '", "operation": "revoke"}'
                end
            end
        end
    end

when "delete"
    didHash = input_did.split(LOCATION_PREFIX)[0] rescue input_did
    didHash = didHash.delete_prefix("did:oyd:")
    options[:digest] = Oydid.get_digest(didHash).first
    options[:encode] = Oydid.get_encoding(didHash).first    
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
                puts "deleted " + Oydid.percent_encode(did.to_s)
            else
                puts '{"did": "did:oyd:"' + Oydid.percent_encode(did.to_s) + '", "operation": "delete"}'
            end
        end
    end

# DIDComm Functions =============
when "message"
    didcomm_message, err_msg = Oydid.dcpm(content, options)
    puts JSON.pretty_generate(didcomm_message)
when "jws"
    did10 = options[:sign_did].to_s.delete_prefix("did:oyd:")[0,10]
    f = File.open(did10 + "_private_key.enc")
    private_key_encoded = f.read
    f.close
    didcomm_signed_message, err_msg = Oydid.dcsm(content, private_key_encoded, options)
    puts didcomm_signed_message.to_s
when "verify-jws"
    msg_verified, err_msg = Oydid.dcsm_verify(content, options)
    if !msg_verified.nil?
        if options[:json].nil? || !options[:json]
            puts "✅ Signature verified for: "
            puts JSON.pretty_generate(msg_verified)
        else
            puts JSON.pretty_generate(msg_verified)
        end
    else
        if options[:json].nil? || !options[:json]
            puts "⛔ " + err_msg
        else
            puts JSON.pretty_generate("error": err_msg)
        end
    end

when "encrypt-message"
    from_did = options[:didcomm_from_did].to_s
    did10 = from_did.delete_prefix("did:oyd:")[0,10]
    f = File.open(did10 + "_private_key.enc")
    key_encoded = f.read
    f.close
    msg_encrypted, msg = Oydid.msg_encrypt(content, key_encoded, from_did, options)
    puts msg_encrypted.to_s
when "decrypt-jwt"
    from_did = options[:didcomm_from_did].to_s
    result, msg = Oydid.read(from_did, options)
    public_key_encoded = result["doc"]["key"].split(':').first
    msg_decrypted, msg = Oydid.msg_decrypt(content, public_key_encoded, options)
    puts JSON.pretty_generate(msg_decrypted.first)
when "sign-message"
    msg_signed, msg = Oydid.msg_sign(content, options[:hmac_secret].to_s)
    puts msg_signed.to_s
when "verify-signed-message"
    msg_verified, msg = Oydid.msg_verify_jws(content, options[:hmac_secret].to_s)
    if !msg_verified.nil?
        if options[:json].nil? || !options[:json]
            puts "✅ Signature verified for: "
            puts JSON.pretty_generate(msg_verified)
        else
            puts JSON.pretty_generate(msg_verified)
        end
    else
        if options[:json].nil? || !options[:json]
            puts "⛔ " + msg
        else
            puts JSON.pretty_generate("error": msg)
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
        puts "Warning: function not yet available"
    else
        puts '{"warning": "function not yet available"}'
    end
when "vc", "vc-push"
    # get private key from issuer
    did_issuer = options[:issuer]
    if options[:doc_enc].nil?
        did10_issuer = did_issuer.delete_prefix("did:oyd:")[0,10]
        options[:issuer_privateKey] = Oydid.read_private_storage(did10_issuer + "_private_key.enc")
    else
        options[:issuer_privateKey] = options[:doc_enc].to_s
    end
    vc, msg = Oydid.create_vc(content, options)

    if operation == "vc-push"
        retVal, msg = Oydid.publish_vc(vc, options)
        if retVal.nil?
            if options[:json].nil? || !options[:json]
                puts "Error: " + msg
            else
                puts '{"error": "' + msg + '"}'
            end
            exit(-1)
        else
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "created " + retVal.to_s
                else
                    puts JSON.pretty_generate(vc)
                end
            end
        end
    else
        puts JSON.pretty_generate(vc)
    end

when "vc-read", "read-vc"
    vc, msg = Oydid.read_vc(input_did, options)
    if vc.nil?
        if options[:json].nil? || !options[:json]
            puts "Error: " + msg
        else
            puts '{"error": "' + msg + '"}'
        end
        exit(-1)
    else
        puts JSON.pretty_generate(vc)
    end

when "vp", "vp-push"
    did_holder = options[:holder]
    if options[:doc_enc].nil?
        did10_holder = did_holder.delete_prefix("did:oyd:")[0,10]
        options[:holder_privateKey] = Oydid.read_private_storage(did10_holder + "_private_key.enc")
    else
        options[:holder_privateKey] = options[:doc_enc].to_s
    end
    vp, msg = Oydid.create_vp(content, options)

    if operation == "vp-push"
        retVal, msg = Oydid.publish_vp(vp, options)
        if retVal.nil?
            if options[:json].nil? || !options[:json]
                puts "Error: " + msg
            else
                puts '{"error": "' + msg + '"}'
            end
            exit(-1)
        else
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "created " + retVal.to_s
                else
                    puts JSON.pretty_generate(vp)
                end
            end
        end
    else
        puts JSON.pretty_generate(vp)
    end

when "vp-read", "read-vp"
    vp, msg = Oydid.read_vp(input_did, options)
    if vp.nil?
        if options[:json].nil? || !options[:json]
            puts "Error: " + msg
        else
            puts '{"error": "' + msg + '"}'
        end
        exit(-1)
    else
        puts JSON.pretty_generate(vp)
    end

when "vp-verify"
    result, msg = Oydid.verify_vp(content, options)
    if result.nil?
        if options[:json].nil? || !options[:json]
            puts "invalid proof: " + msg
        else
            puts '{"error": "' + msg + '"}'
        end
    else
        if options[:json].nil? || !options[:json]
            puts "valid proof for " + result[:identifier].to_s
        else
            puts '{"VerifiablePresentation":"' + result[:identifier].to_s + '", "valid": true}'
        end
    end

else
    print_help()
end
