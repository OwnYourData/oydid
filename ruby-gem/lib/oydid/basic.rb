# -*- encoding: utf-8 -*-
# frozen_string_literal: true

class Oydid

    # basic functions ---------------------------
    # %w[multibases multihashes rbnacl json].each { |f| require f }
    def self.multi_encode(message, options)
        method = options[:encode] || DEFAULT_ENCODING rescue DEFAULT_ENCODING
        case method
        when *SUPPORTED_ENCODINGS
            return [Multibases.pack(method, message).to_s, ""]
        else
            return [nil, "unsupported encoding: '" + method + "'"]
        end
    end

    def self.multi_decode(message)
        begin
            [Multibases.unpack(message).decode.to_s('ASCII-8BIT'), ""]
        rescue => error
            [nil, error.message] 
        end
    end

    def self.hash(message)
        return multi_hash(message, {:digest => DEFAULT_DIGEST}).first
    end

    def self.multi_hash(message, options)
        method = options[:digest] || DEFAULT_DIGEST
        case method.to_s
        when "sha2-256"
            digest = RbNaCl::Hash.sha256(message)
        when "sha2-512"
            digest = RbNaCl::Hash.sha512(message)
        when "sha3-224", "sha3-256", "sha3-384", "sha3-512"
            digest = OpenSSL::Digest.digest(method, message)
        when "blake2b-16"
            digest = RbNaCl::Hash.blake2b(message, {digest_size: 16})
        when "blake2b-32"
            digest = RbNaCl::Hash.blake2b(message, {digest_size: 32})
        when "blake2b-64"
            digest = RbNaCl::Hash.blake2b(message)
        else
            return [nil, "unsupported digest: '" + method.to_s + "'"]
        end
        encoded = multi_encode(Multihashes.encode(digest, method.to_s), options)
        if encoded.first.nil?
            return [nil, encoded.last]
        else
            return [encoded.first, ""]
        end
    end

    def self.get_digest(message)
        retVal = Multihashes.decode Oydid.multi_decode(message).first
        if retVal[:hash_function].to_s != ""
            return [retVal[:hash_function].to_s, ""]
        end
        case Oydid.multi_decode(message).first[0..1].to_s
        when "\x02\x10"
            return ["blake2b-16", ""]
        when "\x04 "
            return ["blake2b-32", ""]
        when "\b@"
            return ["blake2b-64", ""]
        else
            return [nil, "unknown digest"]
        end
    end

    def self.get_encoding(message)
        # from https://github.com/multiformats/multibase/blob/master/multibase.csv 
        begin
            [Multibases.unpack(message).encoding, ""]
        rescue => error
            [nil, error.message] 
        end
    end

    def self.canonical(message)
        if message.is_a? String
            message = JSON.parse(message) rescue message
        else
            message = JSON.parse(message.to_json) rescue message
        end
        message.to_json_c14n
    end

    def self.percent_encode(did)
        # remove "https://" from string as it is default
        did = did.sub("https://","").sub("@", "%40").sub("http://","http%3A%2F%2F").gsub(":","%3A").sub("did%3Aoyd%3A", "did:oyd:")
    end

    # key management ----------------------------
    def self.generate_private_key(input, method = "ed25519-priv", options)
        begin
            omc = Multicodecs[method].code
        rescue
            return [nil, "unknown key codec"]
        end
        
        case Multicodecs[method].name 
        when 'ed25519-priv'
            if input != ""
                raw_key = Ed25519::SigningKey.new(RbNaCl::Hash.sha256(input)).to_bytes
            else
                raw_key = Ed25519::SigningKey.generate.to_bytes
            end
        else
            return [nil, "unsupported key codec"]
        end
        length = raw_key.bytesize
        encoded = multi_encode([omc, length, raw_key].pack("SCa#{length}"), options)
        if encoded.first.nil?
            return [nil, encoded.last]
        else
            return [encoded.first, ""]
        end
    end

    def self.public_key(private_key, options, method = "ed25519-pub")
        code, length, digest = multi_decode(private_key).first.unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            case method
            when 'ed25519-pub'
                public_key = Ed25519::SigningKey.new(digest).verify_key
            when 'x25519-pub'
                public_key = RbNaCl::PrivateKey.new(digest).public_key
            else
                return [nil, "unsupported key codec"]
            end
            length = public_key.to_bytes.bytesize
            encoded = multi_encode([Multicodecs[method].code, length, public_key].pack("CCa#{length}"), options)
            if encoded.first.nil?
                return [nil, encoded.last]
            else
                return [encoded.first, ""]
            end
        else
            return [nil, "unsupported key codec"]
        end
    end

    def self.getPubKeyFromDID(did)
        identifier = did.split(LOCATION_PREFIX).first.split(CGI.escape LOCATION_PREFIX).first rescue did
        identifier = identifier.delete_prefix("did:oyd:")

        # check if identifier is already PubKey
        if decode_public_key(identifier).first.nil?
            did_document, msg = read(did, {})
            if did_document.nil?
                return [nil, msg]
                exit
            end
            pubKey = did_document["doc"]["key"].split(":").first rescue nil
            if pubKey.nil?
                return [nil, "cannot resolve " + did.to_s]
            else
                return [pubKey, ""]
            end
        else
            return [identifier, ""]
        end
    end

    def self.sign(message, private_key, options)
        code, length, digest = multi_decode(private_key).first.unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            encoded = multi_encode(Ed25519::SigningKey.new(digest).sign(message), options)
            if encoded.first.nil?
                return [nil, encoded.last]
            else
                return [encoded.first, ""]
            end
        else
            return [nil, "unsupported key codec"]
        end
    end

    def self.verify(message, signature, public_key)
        begin
            code, length, digest = multi_decode(public_key).first.unpack('CCa*')
            case Multicodecs[code].name
            when 'ed25519-pub'
                verify_key = Ed25519::VerifyKey.new(digest)
                signature_verification = false
                begin
                    verify_key.verify(multi_decode(signature).first, message)
                    signature_verification = true
                rescue Ed25519::VerifyError
                    signature_verification = false
                end
                return [signature_verification, ""]
            else
                return [nil, "unsupported key codec"]
            end
        rescue
            return [nil, "unknown key codec"]
        end
    end

    def self.encrypt(message, public_key, options)
        begin
            code, length, digest = multi_decode(public_key).first.unpack('CCa*')
            case Multicodecs[code].name
            when 'x25519-pub'
                pubKey = RbNaCl::PublicKey.new(digest)
                authHash = RbNaCl::Hash.sha256('auth'.dup.force_encoding('ASCII-8BIT'))
                authKey = RbNaCl::PrivateKey.new(authHash)
                box = RbNaCl::Box.new(pubKey, authKey)
                nonce = RbNaCl::Random.random_bytes(box.nonce_bytes)
                msg = message.force_encoding('ASCII-8BIT')
                cipher = box.encrypt(nonce, msg)
                return [
                    { 
                        value: cipher.unpack('H*')[0], 
                        nonce: nonce.unpack('H*')[0]
                    }, ""
                ]
            else
                return [nil, "unsupported key codec"]
            end
        rescue
            return [nil, "encryption failed"]
        end
    end

    def self.decrypt(message, private_key, options)
        begin
            cipher = [JSON.parse(message)["value"]].pack('H*')
            nonce = [JSON.parse(message)["nonce"]].pack('H*')
            code, length, digest = multi_decode(private_key).first.unpack('SCa*')
            case Multicodecs[code].name
            when 'ed25519-priv'
                privKey = RbNaCl::PrivateKey.new(digest)
                authHash = RbNaCl::Hash.sha256('auth'.dup.force_encoding('ASCII-8BIT'))
                authKey = RbNaCl::PrivateKey.new(authHash).public_key
                box = RbNaCl::Box.new(authKey, privKey)
                retVal = box.decrypt(nonce, cipher)
                return [retVal, ""]
            else
                return [nil, "unsupported key codec"]
            end
        rescue
            return [nil, "decryption failed"]
        end
    end

    def self.read_private_key(filename, options)
        begin
            f = File.open(filename)
            key_encoded = f.read
            f.close
        rescue
            return [nil, "cannot read file"]
        end
        decode_private_key(key_encoded, options)
    end

    def self.decode_private_key(key_encoded, options)
        begin
            code, length, digest = multi_decode(key_encoded).first.unpack('SCa*')
            case Multicodecs[code].name
            when 'ed25519-priv'
                private_key = Ed25519::SigningKey.new(digest).to_bytes
            else
                return [nil, "unsupported key codec"]
            end
            length = private_key.bytesize
            return multi_encode([code, length, private_key].pack("SCa#{length}"), options)
        rescue
            return [nil, "invalid key"]
        end
    end

    def self.decode_public_key(key_encoded)
        begin
            code, length, digest = multi_decode(key_encoded).first.unpack('CCa*')
            case Multicodecs[code].name
            when 'ed25519-pub'
                verify_key = Ed25519::VerifyKey.new(digest)
                return [verify_key, ""]
            else
                return [nil, "unsupported key codec"]
            end
        rescue
            return [nil, "unknown key codec"]
        end
    end

    # storage functions -----------------------------
    def self.write_private_storage(payload, filename)
        File.open(filename, 'w') {|f| f.write(payload)}
    end

    def self.read_private_storage(filename)
        begin
            File.open(filename, 'r') { |f| f.read }
        rescue
            nil
        end
    end

    def self.get_location(id)
        if id.include?(LOCATION_PREFIX)
            id_split = id.split(LOCATION_PREFIX)
            return id_split[1]
        else
            if id.include?(CGI.escape(LOCATION_PREFIX))
                id_split = id.split(CGI.escape(LOCATION_PREFIX))
                return id_split[1]
            else
                return DEFAULT_LOCATION
            end
        end
    end

    def self.retrieve_document(doc_identifier, doc_file, doc_location, options)
        if doc_location == ""
            doc_location = DEFAULT_LOCATION
        end
        if !(doc_location == "" || doc_location == "local")
            if !doc_location.start_with?("http")
                doc_location = "https://" + doc_location
            end
        end
        case doc_location
        when /^http/
            doc_location = doc_location.sub("%3A%2F%2F","://").sub("%3A", ":")
            retVal = HTTParty.get(doc_location + "/doc/" + doc_identifier)
            if retVal.code != 200
                msg = retVal.parsed_response("error").to_s rescue "invalid response from " + doc_location.to_s + "/doc/" + doc_identifier.to_s
                return [nil, msg]
            end
            if options.transform_keys(&:to_s)["trace"]
                if options[:silent].nil? || !options[:silent]
                    puts "GET " + doc_identifier + " from " + doc_location
                end
            end
            return [retVal.parsed_response, ""]
        when "", "local"
            doc = JSON.parse(read_private_storage(doc_file)) rescue {}
            if doc == {}
                return [nil, "cannot read file"]
            else
                return [doc, ""]
            end
        end
    end

    def self.retrieve_document_raw(doc_hash, doc_file, doc_location, options)
        doc_hash = doc_hash.split(LOCATION_PREFIX).first.split(CGI.escape LOCATION_PREFIX).first rescue doc_hash
        doc_hash = doc_hash.delete_prefix("did:oyd:")

        if doc_location == ""
            doc_location = DEFAULT_LOCATION
        end
        if !(doc_location == "" || doc_location == "local")
            if !doc_location.start_with?("http")
                doc_location = "https://" + doc_location
            end
        end

        case doc_location
        when /^http/
            doc_location = doc_location.sub("%3A%2F%2F","://").sub("%3A", ":")
            retVal = HTTParty.get(doc_location + "/doc_raw/" + doc_hash)
            if retVal.code != 200
                msg = retVal.parsed_response("error").to_s rescue "invalid response from " + doc_location.to_s + "/doc/" + doc_hash.to_s
                return [nil, msg]
            end
            if options.transform_keys(&:to_s)["trace"]
                if options[:silent].nil? || !options[:silent]
                    puts "GET " + doc_hash + " from " + doc_location
                end
            end
            return [retVal.parsed_response, ""]
        when "", "local"
            doc = JSON.parse(read_private_storage(doc_file)) rescue {}
            log = JSON.parse(read_private_storage(doc_file.sub(".doc", ".log"))) rescue {}
            if doc == {}
                return [nil, "cannot read file"]
            else
                obj = {"doc" => doc, "log" => log}
                return [obj, ""]
            end
        end
    end

end