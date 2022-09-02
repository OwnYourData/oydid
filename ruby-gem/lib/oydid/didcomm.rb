# -*- encoding: utf-8 -*-
# frozen_string_literal: true

class Oydid

    # DIDComm Plain Message ---------------------
    def self.dcpm(payload, options)
        dcDoc = {}
        dcDoc["id"] = SecureRandom.random_number(10e14).to_i
        dcDoc["type"] = options[:didcomm_type]
        if !options[:didcomm_from_did].nil?
            dcDoc["from"] = options[:didcomm_from_did]
        end
        dcDoc["to"] = [options[:didcomm_to_did]]
        dcDoc["created_time"] = Time.now.utc.to_i
        dcDoc["body"] = payload
        return [dcDoc, ""]

    end

    # DIDComm Signed Message --------------------
    def self.dcsm(payload, private_key_encoded, options)
        error = ""
        code, length, digest = decode(private_key_encoded).unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            private_key = RbNaCl::Signatures::Ed25519::SigningKey.new(digest)
            token = JWT.encode payload, private_key, 'ED25519', { typ: 'JWM', kid: options[:sign_did].to_s, alg: 'ED25519' }
        else
            token = nil
            error = "unsupported key codec"
        end
        return [token, error]
    end

    def self.dcsm_verify(token, options)
        error = ""
        decoded_payload = JWT.decode token, nil, false
        pubkey_did = decoded_payload.last["kid"]
        result, msg = Oydid.read(pubkey_did, options)
        public_key_encoded = Oydid.w3c(result, options)["authentication"].first["publicKeyMultibase"]
        begin
            code, length, digest = Oydid.decode(public_key_encoded).unpack('CCa*')
            case Multicodecs[code].name
            when 'ed25519-pub'
                public_key = RbNaCl::Signatures::Ed25519::VerifyKey.new(digest)
                payload = JWT.decode token.to_s, public_key, true, { algorithm: 'ED25519' }
            else
                payload = nil
                error = "unsupported key codec"
            end
            return [payload, error]
        rescue
            return [nil, "verification failed"]
        end
    end

    # encryption -----------------------------------
    def self.msg_encrypt(payload, private_key_encoded, did)
        error = ""
        code, length, digest = decode(private_key_encoded).unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            private_key = RbNaCl::Signatures::Ed25519::SigningKey.new(digest)
            token = JWT.encode payload, private_key, 'ED25519'
        else
            token = nil
            error = "unsupported key codec"
        end
        return [token, error]
    end

    def self.msg_decrypt(token, public_key_encoded)
        error = ""
        code, length, digest = Oydid.decode(public_key_encoded).unpack('CCa*')
        case Multicodecs[code].name
        when 'ed25519-pub'
            public_key = RbNaCl::Signatures::Ed25519::VerifyKey.new(digest)
            payload = JWT.decode token.to_s, public_key, true, { algorithm: 'ED25519' }
        else
            payload = nil
            error = "unsupported key codec"
        end
        return [payload, error]
    end

    # signing for JWS ---------------------------
    def self.msg_sign(payload, hmac_secret)
        token = JWT.encode payload, hmac_secret, 'HS256'
        return [token, ""]
    end

    def self.msg_verify_jws(token, hmac_secret)
        begin
            decoded_token = JWT.decode token, hmac_secret, true, { algorithm: 'HS256' }
            return [decoded_token, ""]
        rescue
            return [nil, "verification failed"]
        end
    end

    # DID Auth for data container with challenge ---
    def self.token_from_challenge(host, pwd)
        sid = SecureRandom.hex(20).to_s
        retVal = HTTParty.post(host + "/oydid/init",
                    headers: { 'Content-Type' => 'application/json' },
                    body: { "session_id": sid }.to_json )
        challenge = retVal.parsed_response["challenge"]
        signed_challenge = Oydid.sign(challenge, Oydid.generate_private_key(pwd).first).first
        public_key = Oydid.public_key(Oydid.generate_private_key(pwd).first).first
        retVal = HTTParty.post(host + "/oydid/token",
                    headers: { 'Content-Type' => 'application/json' },
                    body: {
                        "session_id": sid,
                        "signed_challenge": signed_challenge,
                        "public_key": public_key
                    }.to_json)
        return retVal.parsed_response["access_token"]
    end
end