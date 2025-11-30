# -*- encoding: utf-8 -*-
# frozen_string_literal: true

class Oydid
    def self.read_vc(identifier, options)
        vc_location = ""
        if !options[:location].nil?
            vc_location = options[:location]
        end
        if vc_location.to_s == ""
            vc_location = DEFAULT_LOCATION
        end
        vc_url = vc_location.sub(/(\/)+$/,'') + "/credentials/" + identifier

        holder = options[:holder].to_s rescue nil
        if holder.to_s == ""
            msg = "missing holder information"
            return [nil, msg]
            exit
        end

        private_key = options[:holder_privateKey].to_s rescue nil
        if private_key.to_s == ""
            msg = "missing private document key information"
            return [nil, msg]
            exit
        end

        # authenticate against repository
        init_url = vc_location + "/oydid/init"
        sid = SecureRandom.hex(20).to_s
        response = HTTParty.post(init_url,
            headers: { 'Content-Type' => 'application/json' },
            body: { "session_id": sid, 
                    "public_key": Oydid.public_key(private_key, options).first }.to_json ).parsed_response rescue {}
        if response["challenge"].nil?
            msg = "missing challenge for repository authentication"
            return [nil, msg]
            exit
        end
        challenge = response["challenge"].to_s

        # sign challenge and request token
        token_url = vc_location + "/oydid/token"
        response = HTTParty.post(token_url,
            headers: { 'Content-Type' => 'application/json' },
            body: { "session_id": sid, 
                    "signed_challenge": Oydid.sign(challenge, private_key, options).first }.to_json).parsed_response rescue {}
        access_token = response["access_token"].to_s rescue nil
        if access_token.nil?
            msg = "invalid repository authentication (access_token)"
            return [nil, msg]
            exit
        end
        retVal = HTTParty.get(vc_url,
            headers: {'Authorization' => 'Bearer ' + access_token})
        if retVal.code != 200
            if retVal.code == 401
                msg = "unauthorized (valid Bearer token required)"
            else
                msg = retVal.parsed_response("error").to_s rescue "invalid response from " + vc_url.to_s
            end
            return [nil, msg]
        end
        return [retVal.parsed_response, ""]
    end

    def self.vc_proof_prep(vc, proof)
        cntxt = vc["@context"].dup
        if !cntxt.is_a?(Array)
            cntxt = [cntxt]
        end
        cntxt << ED25519_SECURITY_SUITE unless cntxt.include?(ED25519_SECURITY_SUITE)
        vc["@context"] = cntxt.dup
        vc.delete("proof")
        vc = JSON::LD::API.compact(JSON.parse(vc.to_json), JSON.parse(cntxt.to_json))
        graph = RDF::Graph.new << JSON::LD::Reader.new(vc.to_json)
        norm_graph = graph.dump(:normalize).to_s
        if norm_graph.strip == ""
            return [nil, nil, "empty VC"]
        end
        hash1 = Multibases.pack("base16", RbNaCl::Hash.sha256(norm_graph)).to_s[1..]

        remove_context = false
        if proof["@context"].nil?
            proof["@context"] = cntxt.dup
            remove_context = true
        else
            cntxt = proof["@context"]
        end
        if proof["created"].nil?
            proof["created"] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        end        
        proof.delete("proofValue")
        proof = JSON::LD::API.compact(JSON.parse(proof.to_json), JSON.parse(cntxt.to_json))
        graph = RDF::Graph.new << JSON::LD::Reader.new(proof.to_json)
        norm_graph = graph.dump(:normalize).to_s
        if norm_graph.strip == ""
            return [nil, nil, "empty proof"]
        end
        hash2 = Multibases.pack("base16", RbNaCl::Hash.sha256(norm_graph)).to_s[1..]
        if remove_context
            proof.delete("@context")
        end
        vc["proof"] = proof

        return [vc, hash2+hash1, nil]
    end

    # Verifiable Credential hash
    # vc = {"@context", "type", "issuer", "issuanceDate", "credentialSubject"}
    #      but no "proof"!
    # proof = {"type", "verificationMethod", "proofPurpose", "created"}
    #      but no "proofValue"
    # private_key_encoded (string) "z..."
    # https://www.w3.org/TR/vc-di-eddsa/#representation-ed25519signature2020
    def self.vc_proof(vc, proof, private_key_encoded, options)
        vc, vc_hash, errmsg = vc_proof_prep(vc, proof)
        if vc.nil?
            return [nil, errmsg]
        end
        code, length, digest = multi_decode(private_key_encoded).first.unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            signing_key = Ed25519::SigningKey.new(digest)
            vc["proof"]["proofValue"] = multi_encode(signing_key.sign([vc_hash].pack('H*')).bytes, options).first
        when 'p256-priv'
            vc["proof"]["proofValue"] = sign("message", private_key_encoded, options)
        else
            return [nil, "unsupported key codec"]
        end
        return [vc, nil]

    end

    def self.create_vc(content, options)
        if options[:issuer_privateKey].to_s == ""
            return [nil, "missing issuer private key"]
        end
        code, length, digest = multi_decode(options[:issuer_privateKey]).first.unpack('SCa*')
        case options[:vc_type].to_s
        when 'Ed25519Signature2020'
            if Multicodecs[code].name != 'ed25519-priv'
                return [nil, "combination of credential type '" + options[:vc_type].to_s + "' and key type '" + Multicodecs[code].name.to_s + "' not supported"]
            end
        when 'JsonWebSignature2020'
            if Multicodecs[code].name != 'p256-priv'
                return [nil, "combination of credential type '" + options[:vc_type].to_s + "' and key type '" + Multicodecs[code].name.to_s + "' not supported"]
            end
        else
            return [nil, "unsupported credential type '" + options[:vc_type].to_s + "'"]
        end
        vercred = content
        # set the context, which establishes the special terms used
        if content["@context"].nil?
            case options[:vc_type].to_s
            when "Ed25519Signature2020"
                vercred["@context"] = ["https://www.w3.org/ns/credentials/v2"]
            when "JsonWebSignature2020"
                vercred["@context"] = ["https://www.w3.org/2018/credentials/v1"]
            else
                return [nil, "invalid credential type '" + options[:vc_type].to_s + "'"]
            end
        else
            vercred["@context"] = content["@context"]
        end
        if vercred["@context"].to_s == "" || vercred["@context"].to_s == "{}" || vercred["@context"].to_s == "[]"
            return [nil, "invalid '@context'"]
        end
        if content["type"].nil?
            vercred["type"] = ["VerifiableCredential"]
        else
            vercred["type"] = content["type"]
        end
        if vercred["type"].to_s == "" || vercred["type"].to_s == "{}" || vercred["type"].to_s == "[]"
            return [nil, "invalid 'type'"]
        end
        if content["issuer"].nil?
            vercred["issuer"] = options[:issuer]
        else
            vercred["issuer"] = content["issuer"]
        end
        if vercred["issuer"].to_s == "" || vercred["issuer"].to_s == "{}" || vercred["issuer"].to_s == "[]"
            return [nil, "invalid 'issuer'"]
        end
        if options[:ts].nil?
            vercred["issuanceDate"] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        else
            vercred["issuanceDate"] = Time.at(options[:ts]).utc.iso8601
        end
        if content["credentialSubject"].nil?
            vercred["credentialSubject"] = {"id": options[:holder]}.merge(content)
        else
            vercred["credentialSubject"] = content["credentialSubject"]
            if vercred["credentialSubject"]["id"].nil?
                if options[:holder].nil?
                    return [nil, "missing 'id' (of holder) in 'credentialSubject'"]
                end
                vercred["credentialSubject"]["id"] = options[:holder]
            end
        end
        if vercred["credentialSubject"].to_s == "" || vercred["credentialSubject"].to_s == "{}" || vercred["credentialSubject"].to_s == "[]"
            return [nil, "invalid 'credentialSubject'"]
        end

        case options[:vc_type].to_s
        when 'Ed25519Signature2020'
            if content["proof"].nil?
                proof = {}
                proof["type"] = "Ed25519Signature2020"
                proof["verificationMethod"] = options[:issuer].to_s + "#key-doc"
                proof["proofPurpose"] = "assertionMethod"
                id_vc = vercred.dup
                id_vc["proof"] = proof
                identifier_str = multi_hash(canonical(id_vc), options).first
                if options[:vc_location].nil?
                    vercred["identifier"] = identifier_str
                else
                    vc_location = options[:vc_location].to_s
                    if !vc_location.start_with?("http")
                        vc_location = "https://" + token_url
                    end
                    if !vc_location.end_with?('/')
                        vc_location += '/'
                    end
                    if !vc_location.end_with?('credentials/')
                        vc_location += 'credentials/'
                    end
                    vercred["id"] = vc_location + identifier_str
                end

                vercred, errmsg = vc_proof(vercred, proof, options[:issuer_privateKey], options)
                if vercred.nil?
                    return [nil, errmsg]
                end
                # proof["proofValue"] = sign(vercred["credentialSubject"].transform_keys(&:to_s).to_json_c14n, options[:issuer_privateKey], []).first
            else
                id_vc = vercred.dup
                content["proof"].delete("proofValue")
                id_vc["proof"] = content["proof"]
                identifier_str = multi_hash(canonical(id_vc), options).first
                if options[:vc_location].nil?
                    vercred["identifier"] = identifier_str
                else
                    vercred["id"] = options[:vc_location].to_s + identifier_str
                end

                vercred, errmsg = vc_proof(vercred, content["proof"], options[:issuer_privateKey], options)
                if vercred.nil?
                    return [nil, errmsg]
                end
            end
            if vercred["proof"].to_s == "" || vercred["proof"].to_s == "{}" || vercred["proof"].to_s == "[]"
                return [nil, "invalid 'proof'"]
            end

        when 'JsonWebSignature2020'
            jwt_vc = {}
            jwt_vc["vc"] = vercred.dup
            jwt_vc["exp"] = (Time.now + (3 * 30 * 24 * 60 * 60)).to_i
            jwt_vc["iss"] = vercred["issuer"]
            jwt_vc["nbf"] = 
            if options[:ts].nil?
                jwt_vc["nbf"] = Time.now.utc.to_i
            else
                jwt_vc["nbf"] = options[:ts].to_i
            end
            identifier_str = multi_hash(canonical(vercred), options).first
            jwt_vc["jti"] = identifier_str
            jwt_vc["sub"] = options[:holder]

            vercred = jwt_vc.dup
        else
            return [nil, "unsupported credential type '" + options[:vc_type].to_s + "'"]
        end

        return [vercred, ""]
    end

    def self.create_vc_proof(content, options)
        if content["id"].nil?
            content["id"] = options[:issuer]
        end
        proof = {}
        proof["type"] = "Ed25519Signature2020"
        proof["verificationMethod"] = options[:issuer].to_s
        proof["proofPurpose"] = "assertionMethod"

        content, errmsg = vc_proof(content, proof, options[:issuer_privateKey], options)
        if content.nil?
            return [nil, errmsg]
        end
        # proof["proofValue"] = sign(content.to_json_c14n, options[:issuer_privateKey], []).first

        return [content["proof"], ""]
    end

    def self.publish_vc(vc, options)
        vc = vc.transform_keys(&:to_s)
        identifier = vc["identifier"] rescue nil
        if identifier.nil?
            identifier = vc["id"] rescue nil
        end
        if identifier.nil?
            return [nil, "invalid format (missing identifier)"]
            exit
        end
        if vc["credentialSubject"].is_a?(Array)
            cs = vc["credentialSubject"].last.transform_keys(&:to_s) rescue nil
        else
            cs = vc["credentialSubject"].transform_keys(&:to_s) rescue nil
        end
        holder = cs["id"] rescue nil
        if holder.nil?
            return [nil, "invalid format (missing holder)"]
            exit
        end

        vc_location = ""
        if !options[:location].nil?
            vc_location = options[:location]
        end
        if vc_location.to_s == ""
            vc_location = DEFAULT_LOCATION
        end
        if !identifier.start_with?('http')
            identifier = vc_location.sub(/(\/)+$/,'') + "/credentials/" + identifier
        end

        # build object to post
        vc_data = {
            "identifier": identifier,
            "vc": vc,
            "holder": holder
        }
        vc_url = vc_location.sub(/(\/)+$/,'') + "/credentials"
        retVal = HTTParty.post(vc_url,
            headers: { 'Content-Type' => 'application/json' },
            body: vc_data.to_json )
        if retVal.code != 200
            err_msg = retVal.parsed_response("error").to_s rescue "invalid response from " + vc_url.to_s
            return [nil, err_msg]
        end
        return [retVal["identifier"], ""]
    end

    def self.read_vp(identifier, options)
        vp_location = ""
        if !options[:location].nil?
            vp_location = options[:location]
        end
        if vp_location.to_s == ""
            vp_location = DEFAULT_LOCATION
        end
        vp_url = vp_location.sub(/(\/)+$/,'') + "/presentations/" + identifier
        retVal = HTTParty.get(vp_url)
        if retVal.code != 200
            msg = retVal.parsed_response("error").to_s rescue "invalid response from " + vp_url.to_s
            return [nil, msg]
        end
        return [retVal.parsed_response, ""]
    end

    def self.create_vp(content, options)
        verpres = {}
        # set the context, which establishes the special terms used
        if !content["@context"].nil?
            verpres["@context"] = content["@context"].dup
        else
            verpres["@context"] = ["https://www.w3.org/ns/credentials/v2", ED25519_SECURITY_SUITE]
        end
        verpres["type"] = ["VerifiablePresentation"]
        verpres["verifiableCredential"] = [content].flatten

        proof = {}
        case options[:vc_type].to_s
        when 'Ed25519Signature2020'
            proof['type'] = 'Ed25519Signature2020'
                if !options[:ts].nil?
                    proof["created"] = Time.at(options[:ts]).utc.strftime("%Y-%m-%dT%H:%M:%SZ")
                end
                proof["verificationMethod"] = options[:holder].to_s
                proof["proofPurpose"] = "authentication"
                verpres, errmsg = vc_proof(verpres, proof, options[:holder_privateKey], options)
        when 'JsonWebSignature2020'
            verpres["holder"] = options[:holder].to_s
            proof['type'] = 'JsonWebSignature2020'
            if options[:ts].nil?
                proof['created'] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
            else
                proof["created"] = Time.at(options[:ts]).utc.strftime("%Y-%m-%dT%H:%M:%SZ")
            end
            proof["proofPurpose"] = "authentication"
            proof["verificationMethod"] = options[:holder].to_s + '#key-doc'

            verpres["proof"] = proof

            options[:issuer] = options[:holder]
            options[:issuer_privateKey] = options[:holder_privateKey]
            jwt, msg = Oydid.jwt_from_vc(verpres, options)
            parts = jwt.split('.')
            detached_jws = "#{parts[0]}..#{parts[2]}"

            proof['jws'] = detached_jws
            verpres["proof"] = proof
        else
            return [nil, "unsupported credential type '" + options[:vc_type].to_s + "'"]
        end

        # private_key = generate_private_key(options[:issuer_privateKey], "ed25519-priv", []).first
        # proof["proofValue"] = sign([content].flatten.to_json_c14n, options[:holder_privateKey], []).first
        # verpres["proof"] = proof

        # specify the identifier of the credential
        verpres["identifier"] = hash(canonical(verpres.to_json))
        return [verpres, ""]
    end

    def self.publish_vp(vp, options)
        vp = vp.transform_keys(&:to_s)
        identifier = vp["identifier"] rescue nil
        if identifier.nil?
            return [nil, "invalid format (missing identifier)"]
            exit
        end

        proof = vp["proof"].transform_keys(&:to_s) rescue nil
        holder = vp["holder"] rescue nil
        if holder.nil?
            return [nil, "invalid format (missing holder)"]
            exit
        end

        vp_location = ""
        if !options[:location].nil?
            vp_location = options[:location]
        end
        if vp_location.to_s == ""
            vp_location = DEFAULT_LOCATION
        end
        vp["identifier"] = vp_location.sub(/(\/)+$/,'') + "/presentations/" + identifier

        # build object to post
        vp_data = {
            "identifier": identifier,
            "vp": vp,
            "holder": holder
        }
        vp_url = vp_location.sub(/(\/)+$/,'') + "/presentations"
        retVal = HTTParty.post(vp_url,
            headers: { 'Content-Type' => 'application/json' },
            body: vp_data.to_json )
        if retVal.code != 200
            err_msg = retVal.parsed_response("error").to_s rescue "invalid response from " + vp_url.to_s
            return [nil, err_msg]
        end
        return [vp["identifier"], ""]
    end

    def self.verify_vc(content, options)
        retVal = {}
        vercred = content.to_json_c14n rescue nil
        if vercred.nil?
            return [nil, "invalid verifiableCredential input"]
        end
        retVal[:id] = content["id"] rescue nil
        if retVal[:id].nil?
            retVal[:id] = content["identifier"] rescue nil
            if retVal[:id].nil?
                return [nil, "invalid VC (missing id)"]
            end
        end
        issuer = content["issuer"].to_s rescue nil
        if issuer.nil?
            return [nil, "invalid VC (unknown issuer)"]
            exit
        end
        publicKey, msg = getPubKeyFromDID(issuer)
        if publicKey.nil?
            return [nil, "cannot verify public key"]
            exit
        end
        vc, vc_hash, errmsg = vc_proof_prep(JSON.parse(content.to_json), JSON.parse(content["proof"].to_json))
        begin
            pubkey = Oydid.multi_decode(publicKey).first
            code = pubkey.bytes.first
            digest = pubkey[-32..]
            case Multicodecs[code].name
            when 'ed25519-pub'
                verify_key = Ed25519::VerifyKey.new(digest)
                signature_verification = false
                begin
                    verify_key.verify(multi_decode(content["proof"]["proofValue"]).first, [vc_hash].pack('H*'))
                    signature_verification = true
                rescue Ed25519::VerifyError
                    signature_verification = false
                end
                if signature_verification
                    return [retVal, nil]
                else
                    return [nil, "proof signature does not match VC"]
                end
            else
                return [nil, "unsupported key codec"]
            end
        rescue
            return [nil, "unknown key codec"]
        end
    end

    def self.verify_vp(content, options)
        retVal = {}
        verpres = content.to_json_c14n rescue nil
        if verpres.nil?
            return [nil, "invalid verifiablePresetation input"]
        end
        retVal[:id] = content["id"] rescue nil
        if retVal[:id].nil?
            retVal[:id] = content["identifier"] rescue nil
            if retVal[:id].nil?
                return [nil, "invalid VP (missing id)"]
            end
        end
        holder = content["proof"]["verificationMethod"].to_s rescue nil
        if holder.nil?
            return [nil, "invalid VP (unknown holder"]
        end
        publicKey, msg = getPubKeyFromDID(holder)
        if publicKey.nil?
            return [nil, "cannot verify public key"]
        end
        # begin
            key_type = get_keytype(publicKey)
            case key_type
            # pubkey = Oydid.multi_decode(publicKey).first
            # code = pubkey.bytes.first
            # digest = pubkey[-32..]
            # case Multicodecs[code].name
            when 'ed25519-pub'
                pubkey = Oydid.multi_decode(publicKey).first
                code = pubkey.bytes.first
                digest = pubkey[-32..]
                verify_key = Ed25519::VerifyKey.new(digest)
                vp, vp_hash, errmsg = vc_proof_prep(JSON.parse(content.to_json), JSON.parse(content["proof"].to_json))

                signature_verification = false
                begin
                    verify_key.verify(multi_decode(content["proof"]["proofValue"]).first, [vp_hash].pack('H*'))
                    signature_verification = true
                rescue Ed25519::VerifyError
                    signature_verification = false
                end
                if signature_verification
                    return [retVal, nil]
                else
                    return [nil, "proof signature does not match VP"]
                end
            when 'p256-pub'
                jws = content["proof"]["jws"]
                head_b64, _, sig_b64 = jws.split('.')
                verpres = JSON.parse(verpres)
                verpres["proof"].delete("jws")
                verpres.delete("identifier")
                encoded_payload = Base64.urlsafe_encode64(verpres.to_json_c14n, padding: false)
                data_to_sign = "#{head_b64}.#{encoded_payload}"
# puts 'data_to_sign: ' + data_to_sign.to_s
# puts 'encoded_signature: ' + sig_b64.to_s
# puts 'publicKey: ' + publicKey.to_s

                valid = verify(data_to_sign, sig_b64, publicKey).first
                if valid
                    return [retVal, nil]
                else
                    return [nil, "proof signature does not match VP"]
                end
            else
                return [nil, "unsupported key codec"]
            end
        # rescue
        #     return [nil, "unknown key codec"]
        # end
    end

    def self.jwt_from_vc(vc, options)
        if options[:issuer].to_s == ''
            return [nil, 'missing issuer DID']
        end
        header = {
            alg: 'ES256',
            typ: 'JWT',
            kid: options[:issuer] + '#key-doc'
        }

        if options[:issuer_privateKey].to_s == ''
            return [nil, 'missing issuer private key']
        end
        private_key = decode_private_key(options[:issuer_privateKey]).first

        encoded_header = Base64.urlsafe_encode64(header.to_json, padding: false)
        encoded_payload = Base64.urlsafe_encode64(vc.to_json_c14n, padding: false)
        data_to_sign = "#{encoded_header}.#{encoded_payload}"
# puts 'data_to_sign: ' + data_to_sign.to_s
# puts 'privateKey: ' + options[:issuer_privateKey].to_s

        jwt_digest = OpenSSL::Digest::SHA256.new
        asn1_signature = OpenSSL::ASN1.decode(private_key.dsa_sign_asn1(jwt_digest.digest(data_to_sign)))
        raw_signature = asn1_signature.value.map { |i| i.value.to_s(2).rjust(32, "\x00") }.join()
        encoded_signature = Base64.urlsafe_encode64(raw_signature, padding: false)
# puts 'encoded_signature: ' + encoded_signature.to_s

        jwt = "#{encoded_header}.#{encoded_payload}.#{encoded_signature}"

        return [jwt, nil]
    end

end
