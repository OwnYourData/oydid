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

    def self.create_vc(content, options)
        vercred = {}
        # set the context, which establishes the special terms used
        if content["@context"].nil?
            vercred["@context"] = ["https://www.w3.org/ns/credentials/v2"]
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
            vercred["issuanceDate"] = Time.now.utc.iso8601
        else
            vercred["issuanceDate"] = Time.at(options[:ts]).utc.iso8601
        end
        if content["credentialSubject"].nil?
            vercred["credentialSubject"] = {"id": options[:holder]}.merge(content)
        else
            vercred["credentialSubject"] = content["credentialSubject"]
        end
        if vercred["credentialSubject"].to_s == "" || vercred["credentialSubject"].to_s == "{}" || vercred["credentialSubject"].to_s == "[]"
            return [nil, "invalid 'credentialSubject'"]
        end
        if content["proof"].nil?
            proof = {}
            proof["type"] = "Ed25519Signature2020"
            proof["verificationMethod"] = options[:issuer].to_s
            proof["proofPurpose"] = "assertionMethod"
            proof["proofValue"] = sign(vercred["credentialSubject"].transform_keys(&:to_s).to_json_c14n, options[:issuer_privateKey], []).first
            vercred["proof"] = proof
        else
            vercred["proof"] = content["proof"]
        end
        if vercred["proof"].to_s == "" || vercred["proof"].to_s == "{}" || vercred["proof"].to_s == "[]"
            return [nil, "invalid 'proof'"]
        end

        # specify the identifier of the credential
        vercred["identifier"] = hash(vercred.to_json)
        return [vercred, ""]
    end

    def self.create_vc_proof(content, options)
        if content["id"].nil?
            content["id"] = options[:holder]
        end
        proof = {}
        proof["type"] = "Ed25519Signature2020"
        proof["verificationMethod"] = options[:issuer].to_s
        proof["proofPurpose"] = "assertionMethod"
        proof["proofValue"] = sign(content.to_json_c14n, options[:issuer_privateKey], []).first

        return [proof, ""]
    end

    def self.publish_vc(vc, options)
        vc = vc.transform_keys(&:to_s)
        identifier = vc["identifier"] rescue nil
        if identifier.nil?
            return [nil, "invalid format (missing identifier"]
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
        vc["identifier"] = vc_location.sub(/(\/)+$/,'') + "/credentials/" + identifier

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
        return [vc["identifier"], ""]
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
        verpres["@context"] = ["https://www.w3.org/ns/credentials/v2"]
        verpres["type"] = ["VerifiablePresentation"]
        verpres["verifiableCredential"] = [content].flatten

        proof = {}
        proof["type"] = "Ed25519Signature2020"
        if options[:ts].nil?
            proof["created"] = Time.now.utc.iso8601
        else
            proof["created"] = Time.at(options[:ts]).utc.iso8601
        end
        proof["verificationMethod"] = options[:holder].to_s
        proof["proofPurpose"] = "authentication"

        # private_key = generate_private_key(options[:issuer_privateKey], "ed25519-priv", []).first
        proof["proofValue"] = sign([content].flatten.to_json_c14n, options[:holder_privateKey], []).first
        verpres["proof"] = proof

        # specify the identifier of the credential
        verpres["identifier"] = hash(verpres.to_json)
        return [verpres, ""]
    end

    def self.publish_vp(vp, options)
        vc = vp.transform_keys(&:to_s)
        identifier = vp["identifier"] rescue nil
        if identifier.nil?
            return [nil, "invalid format (missing identifier"]
            exit
        end

        proof = vp["proof"].transform_keys(&:to_s) rescue nil
        holder = proof["verificationMethod"] rescue nil
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

    def self.verify_vp(content, options)
        retVal = {}
        if content["identifier"].nil?
            return [nil, "invalid VP (unknown identifier"]
            exit
        end
        retVal[:identifier] = content["identifier"].to_s

        proofValue = content["proof"]["proofValue"].to_s rescue nil
        if proofValue.nil?
            return [nil, "invalid VP (unknown proofValue"]
            exit
        end

        vercred = content["verifiableCredential"].to_json_c14n rescue nil
        if vercred.nil?
            return [nil, "invalid VP (unknown verifiableCredential"]
            exit
        end

        holder = content["proof"]["verificationMethod"].to_s rescue nil
        if holder.nil?
            return [nil, "invalid VP (unknown holder"]
            exit
        end
        pubKey, msg = getPubKeyFromDID(holder)
        if pubKey.nil?
            return [nil, "cannot verify public key"]
            exit
        end
        result, msg = verify(vercred, proofValue, pubKey)
        if result.to_s == ""
            return [nil, msg]
            exit
        end
        if result
            return [retVal, ""]
        else
            return [nil, "signature verification failed"]
        end
    end

end
