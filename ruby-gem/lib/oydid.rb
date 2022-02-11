# -*- encoding: utf-8 -*-
# frozen_string_literal: true

require 'rbnacl'
require 'ed25519'
require 'multibases'
require 'multihashes'
require 'multicodecs'
require 'json/canonicalization'

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
        File.open(filename, 'r') { |f| f.read }
    end

    # log functions -----------------------------
    def self.add_hash(log)
        log.map do |item|
            i = item.dup
            i.delete("previous")
            item["entry-hash"] = hash(canonical(item))
            if item.transform_keys(&:to_s)["op"] == 1
                item["sub-entry-hash"] = hash(canonical(i))
            end
            item
        end
    end

end