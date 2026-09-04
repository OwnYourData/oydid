# -*- encoding: utf-8 -*-
# frozen_string_literal: true

class Oydid

    # jwt-eddsa normalises the algorithm name to 'EdDSA' in the JOSE header, but
    # dcsm writes an explicit 'ED25519' header. Accept both spellings of the same
    # Ed25519 signature algorithm when verifying.
    ED25519_ALGS = ['EdDSA', 'ED25519'].freeze

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
            # jwt-eddsa signs with an Ed25519::SigningKey from the ed25519 gem;
            # an RbNaCl signing key is rejected with JWT::EncodeError.
            private_key = Ed25519::SigningKey.new(digest)
            token = JWT.encode payload, private_key, 'ED25519', { typ: 'JWM', kid: options[:sign_did].to_s, alg: 'ED25519' }
        else
            token = nil
            error = "unsupported key codec"
        end
        return [token, error]
    end

    # w3c() mixes string keys at the top level with symbol keys inside a
    # verification method, so read every attribute through this helper.
    def self.dd_attr(hash, key)
        return nil unless hash.is_a?(Hash)
        hash[key].nil? ? hash[key.to_sym] : hash[key]
    end

    # The 'authentication' section of a DID document may embed a verification
    # method or - which is how did:oyd resolves it - reference one by id. Only
    # keys listed there may be used to authenticate the DID subject, so a
    # document without an authentication section is rejected rather than
    # silently falling back to some other key.
    def self.authentication_key(didDocument)
        verification_methods = dd_attr(didDocument, "verificationMethod") || []
        entry = (dd_attr(didDocument, "authentication") || []).first
        vm = case entry
             when Hash   then entry
             when String then verification_methods.find { |v| dd_attr(v, "id").to_s == entry }
             end
        key = dd_attr(vm, "publicKeyMultibase")
        if key.to_s == ""
            return [nil, "no authentication key in DID document"]
        end
        return [key, ""]
    end

    # A DID may be written with or without the default location and with the
    # location separator in either spelling, so compare the normalised forms.
    # A fragment ("#key-doc") names a key within the DID, not another subject.
    def self.same_did?(one, other)
        percent_encode(one.to_s.split("#").first.to_s) ==
            percent_encode(other.to_s.split("#").first.to_s)
    end

    # Verifying a token proves that whoever controls the DID named in its own
    # 'kid' header signed it - not that the expected party did. Callers that
    # read the result as an authorisation have to say which DID they expect,
    # which is what options[:expect_did] is for. Checked before resolving, so a
    # token from a foreign DID costs no network round trip.
    def self.dcsm_verify(token, options)
        error = ""
        decoded_payload = JWT.decode token, nil, false
        pubkey_did = decoded_payload.last["kid"]
        if options[:expect_did].to_s != "" && !same_did?(pubkey_did, options[:expect_did])
            return [nil, "token was signed by " + pubkey_did.to_s +
                         ", expected " + options[:expect_did].to_s]
        end
        result, msg = Oydid.read(pubkey_did, options)
        if result.nil?
            return [nil, msg.to_s == "" ? "cannot resolve " + pubkey_did.to_s : msg.to_s]
        end
        public_key_encoded, error = authentication_key(Oydid.w3c(result, options))
        if public_key_encoded.nil?
            return [nil, error]
        end
        begin
            code, length, digest = multi_decode(public_key_encoded).first.unpack('CCa*')
            case Multicodecs[code].name
            when 'ed25519-pub'
                public_key = Ed25519::VerifyKey.new(digest)
                payload = JWT.decode token.to_s, public_key, true, { algorithms: ED25519_ALGS }
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
            private_key = Ed25519::SigningKey.new(digest)
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
            public_key = Ed25519::VerifyKey.new(digest)
            payload = JWT.decode token.to_s, public_key, true, { algorithms: ED25519_ALGS }
        else
            payload = nil
            error = "unsupported key codec"
        end
        return [payload, error]
    end

    # signing for JWS ---------------------------
    # An empty HMAC key is no key at all: OpenSSL::HMAC.digest('SHA256', '', data)
    # returns a valid digest, so anyone can recompute the signature. jwt >= 3.2.0
    # refuses it (CVE-2026-45363), earlier versions happily accepted forged
    # tokens - most notably via the CLI, where a missing --hmac_secret arrives
    # here as "". Reject it ourselves so the behaviour does not depend on which
    # jwt version a consumer resolves.
    def self.msg_sign(payload, hmac_secret)
        if hmac_secret.to_s == ""
            return [nil, "HMAC secret must not be empty"]
        end
        token = JWT.encode payload, hmac_secret, 'HS256'
        return [token, ""]
    end

    def self.msg_verify_jws(token, hmac_secret)
        if hmac_secret.to_s == ""
            return [nil, "HMAC secret must not be empty"]
        end
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

    # other helpers -----------------------------
    def self.build_jwks(content, input_did, options)

        tmp_did_hash = input_did.delete_prefix("did:oyd:") rescue ""
        tmp_did10 = tmp_did_hash[0,10] + "_private_key.enc" rescue ""
        privateKey, msg = getPrivateKey(options[:doc_enc], options[:doc_pwd], options[:doc_key], tmp_did10, options)
        if privateKey.nil?
            return [nil, "private document key not available: " + msg.to_s]
        end

        code, length, digest = multi_decode(privateKey).first.unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'        
            signing_key = Ed25519::SigningKey.new(digest)
        else
            return [nil, "unsupported key codec: " + Multicodecs[code].name.to_s]
        end

        jwk = content
        jwk['iss'] = input_did
        jwk['sub'] = input_did
        jwk['iat'] = Time.now.to_i
        jwk['exp'] = Time.now.to_i + 120
        jwk['jti'] = SecureRandom.uuid

        algorithm = 'EdDSA'
        headers = {
            alg: algorithm,
            typ: 'JWT',
            kid: input_did + '#key-doc' }

        jwks = JWT.encode(jwk, signing_key, algorithm, headers)
        return [jwks, nil]
    end
end