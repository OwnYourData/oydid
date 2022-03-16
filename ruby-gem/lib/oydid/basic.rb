# -*- encoding: utf-8 -*-
# frozen_string_literal: true

class Oydid

    # basic functions ---------------------------
    def self.encode(message, method = "base58btc")
        Multibases.pack(method, message).to_s
    end

    def self.decode(message)
        Multibases.unpack(message).decode.to_s('ASCII-8BIT')
    end

    def self.hash(message)
        encode(Multihashes.encode(RbNaCl::Hash.sha256(message), "sha2-256").unpack('C*'))
    end

    def self.canonical(message)
        if message.is_a? String
            message = JSON.parse(message) rescue message
        else
            message = JSON.parse(message.to_json) rescue message
        end
        message.to_json_c14n
    end

    # key management ----------------------------
    def self.generate_private_key(input, method = "ed25519-priv")
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
        return [encode([omc, length, raw_key].pack("SCa#{length}")), ""]
    end

    def self.public_key(private_key)
        code, length, digest = decode(private_key).unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            public_key = Ed25519::SigningKey.new(digest).verify_key
            length = public_key.to_bytes.bytesize
            return [encode([Multicodecs['ed25519-pub'].code, length, public_key].pack("CCa#{length}")), ""]
        else
            return [nil, "unsupported key codec"]
        end
    end

    def self.sign(message, private_key)
        code, length, digest = decode(private_key).unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            return [encode(Ed25519::SigningKey.new(digest).sign(message)), ""]
        else
            return [nil, "unsupported key codec"]
        end
    end

    def self.verify(message, signature, public_key)
        begin
            code, length, digest = decode(public_key).unpack('CCa*')
            case Multicodecs[code].name
            when 'ed25519-pub'
                verify_key = Ed25519::VerifyKey.new(digest)
                signature_verification = false
                begin
                    verify_key.verify(decode(signature), message)
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

    def self.read_private_key(filename)
        begin
            f = File.open(filename)
            key_encoded = f.read
            f.close
        rescue
            return [nil, "cannot read file"]
        end
        decode_private_key(key_encoded)
    end

    def self.decode_private_key(key_encoded)
        begin
            code, length, digest = decode(key_encoded).unpack('SCa*')
            case Multicodecs[code].name
            when 'ed25519-priv'
                private_key = Ed25519::SigningKey.new(digest).to_bytes
            else
                return [nil, "unsupported key codec"]
            end
            length = private_key.bytesize
            return [Oydid.encode([code, length, private_key].pack("SCa#{length}")), ""]
        rescue
            return [nil, "invalid key"]
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

    def self.retrieve_document(doc_hash, doc_file, doc_location, options)
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
            retVal = HTTParty.get(doc_location + "/doc/" + doc_hash)
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
            if doc == {}
                return [nil, "cannot read file"]
            else
                return [doc, ""]
            end
        end
    end

    def self.retrieve_document_raw(doc_hash, doc_file, doc_location, options)
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