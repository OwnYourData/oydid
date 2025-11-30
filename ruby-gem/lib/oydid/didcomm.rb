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
        code, length, digest = multi_decode(private_key_encoded).first.unpack('SCa*')
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
            code, length, digest = multi_decode(public_key_encoded).first.unpack('CCa*')
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
    def self.msg_encrypt(payload, private_key_encoded, did, options)
        error = ""
        code, length, digest = multi_decode(private_key_encoded).first.unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            private_key = RbNaCl::Signatures::Ed25519::SigningKey.new(digest)
            token = JWT.encode payload, private_key, 'ED25519'
        when 'p256-priv'
            group = OpenSSL::PKey::EC::Group.new('prime256v1')
            pub_key = group.generator.mul(OpenSSL::BN.new(digest, 2))
            pub_oct = pub_key.to_bn.to_s(2)

            parameters = OpenSSL::ASN1::ObjectId("prime256v1")
            parameters.tag = 0
            parameters.tagging = :EXPLICIT
            parameters.tag_class = :CONTEXT_SPECIFIC

            public_key_bitstring = OpenSSL::ASN1::BitString(pub_oct)
            public_key_bitstring.tag = 1
            public_key_bitstring.tagging = :EXPLICIT
            public_key_bitstring.tag_class = :CONTEXT_SPECIFIC

            ec_private_key_asn1 = OpenSSL::ASN1::Sequence([
                OpenSSL::ASN1::Integer(1),
                OpenSSL::ASN1::OctetString(digest),
                parameters,
                public_key_bitstring
            ])
            ec_key = OpenSSL::PKey.read(ec_private_key_asn1.to_der) 
            token = JWT.encode(payload, ec_key, 'ES256')         
        else
            token = nil
            error = "unsupported key codec"
        end
        return [token, error]
    end

    def self.msg_decrypt(token, public_key_encoded, options)
        error = ""
        code, length, digest = Oydid.multi_decode(public_key_encoded).first.unpack('CCa*')
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
    def self.token_from_challenge(host, pwd, options = {})
        sid = SecureRandom.hex(20).to_s
        public_key = public_key(generate_private_key(pwd, options).first, options).first
        retVal = HTTParty.post(host + "/oydid/init",
                    headers: { 'Content-Type' => 'application/json' },
                    body: { "session_id": sid, "public_key": public_key }.to_json )
        challenge = retVal.parsed_response["challenge"]
        signed_challenge = sign(challenge, Oydid.generate_private_key(pwd, options).first, options).first
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