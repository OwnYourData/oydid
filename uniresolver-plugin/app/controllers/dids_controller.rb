class DidsController < ApplicationController
    include ApplicationHelper
    include ApplicationHelperLegacy
    include ActionController::MimeResponds

    # respond only to JSON requests
    respond_to :json
    respond_to :html, only: []
    respond_to :xml, only: []

    def uniresolver_resolve
        did = params[:did]
        fragment = params[:fragment]
        options = {}
        didLocation = did.split(LOCATION_PREFIX)[1] rescue ""
        didHash = did.split(LOCATION_PREFIX)[0] rescue did
        didHash = didHash.delete_prefix("did:oyd:")

        # check for pub-key identifier
        if didHash.start_with?("z6M") && didHash.length == 48

        else
            options[:digest] = Oydid.get_digest(didHash).first
            options[:encode] = Oydid.get_encoding(didHash).first
        end
        options[:followAlsoKnownAs] = ENV['FOLLOW_ALSOKNOWNAS'].to_s.downcase != 'false'
        result = Oydid.read(did, options).first rescue nil
        if result.nil? || result["error"] != 0
            result = resolve_did_legacy(did, options)
        end
        if result.nil?
            render json: {"error": "not found"},
                   status: 404
            return
        end
        if result["error"] != 0
            render json: {"error": result["message"].to_s},
                   status: result["error"]
            return
        end

        didResolutionMetadata = {}
        if !ENV["UNIRESOLVER_DEBUG"].nil?
            didResolutionMetadata = {
              "contentType": "application/did+ld+json",
              "pattern": "^(did:oyd:.+)$",
              "driverUrl": "https://oydid-resolver.data-container.net/1.0/identifiers/$1",
              "duration": 1,
              "did": {
                "didString": did,
                "methodSpecificId": didHash,
                "method": "oyd"
              }
            }
        end

        pubDocKey = result["doc"]["key"].split(":")[0]
        pubkey = Oydid.multi_decode(pubDocKey).first
        if pubkey.bytes.length == 34
            code = pubkey.bytes.first
            digest = pubkey[-32..]
        else
            if pubkey.start_with?("\x80\x24".dup.force_encoding('ASCII-8BIT'))
                code = 4608 # Bytes 0x80 0x24 sind das Varint-Encoding des Multicodec-Codes 0x1200 (p256-pub)
                            # 4608 == Oydid.read_varint("\x80$") oder "\x80\x24".force_encoding('ASCII-8BIT')
            else
                code = pubkey.unpack('n').first
            end
            digest = pubkey[-1*(pubkey.bytes.length-2)..]
        end
        keys = []
        case Multicodecs[code].name
        when 'ed25519-pub'
            # document key
            keys << {
                "kid": Oydid.percent_encode("did:oyd:" + result["did"].to_s) + '#key-doc',
                "kms": "local",
                "type": "Ed25519", 
                "publicKeyHex": Oydid.multi_decode(result["doc"]["key"].split(":").first).first.unpack('H*').first
            }

            # revocation key
            keys << {
                "kid": Oydid.percent_encode("did:oyd:" + result["did"].to_s) + '#key-rev',
                "kms": "local",
                "type": "Ed25519", 
                "publicKeyHex": Oydid.multi_decode(result["doc"]["key"].split(":").last).first.unpack('H*').first
            }
        when 'p256-pub'
            pubDocKey_jwk, msg = Oydid.public_key_to_jwk(result["doc"]["key"].split(":").first)
            if pubDocKey_jwk.nil?
                return {"error": "document key: " + msg.to_s}
            end
            pubRevKey_jwk, msg = Oydid.public_key_to_jwk(result["doc"]["key"].split(":").last)
            if pubRevKey_jwk.nil?
                return {"error": "revocation key: " + msg.to_s}
            end

            # document key
            keys << {
                "kid": Oydid.percent_encode("did:oyd:" + result["did"].to_s) + '#key-doc',
                "kms": "local",
                "type": "JsonWebKey2020",
                "publicKeyJwk": pubDocKey_jwk
            }

            # revocation key
            keys << {
                "kid": Oydid.percent_encode("did:oyd:" + result["did"].to_s) + '#key-rev',
                "kms": "local",
                "type": "JsonWebKey2020",
                "publicKeyJwk": pubRevKey_jwk
            }
        else
            return {"error": "unsupported key codec (" + Multicodecs[code].name.to_s + ")"}
        end

        oydid_W3C = Oydid.w3c(Marshal.load(Marshal.dump(result)), {})
        # if oydid_W3C["id"].split(":").take(2).join(":") == "did:oyd"
        #     key_ids = {}
        #     key_doc = oydid_W3C["verificationMethod"].first
        #     code, length, digest = Multibases.unpack(key_doc[:publicKeyMultibase]).decode.to_s('ASCII-8BIT').unpack('CCa*')
        #     pubKeyOyd_bytes = Ed25519::VerifyKey.new(digest).to_bytes
        #     key_doc[:publicKeyMultibase] = Multibases.pack("base58btc", pubKeyOyd_bytes).to_s
        #     # key_doc["publicKeyHex"] = Oydid.multi_decode(result["doc"]["key"].split(":").first).first.unpack('H*').first
        #     key_ids[key_doc[:id]] = key_doc.transform_keys(&:to_s)

        #     key_rev = oydid_W3C["verificationMethod"].last
        #     code, length, digest = Multibases.unpack(key_rev[:publicKeyMultibase]).decode.to_s('ASCII-8BIT').unpack('CCa*')
        #     pubKeyOyd_bytes = Ed25519::VerifyKey.new(digest).to_bytes
        #     key_rev[:publicKeyMultibase] = Multibases.pack("base58btc", pubKeyOyd_bytes).to_s
        #     # key_rev["publicKeyHex"] = Oydid.multi_decode(result["doc"]["key"].split(":").last).first.unpack('H*').first
        #     key_ids[key_rev[:id]] = key_rev.transform_keys(&:to_s)
        #     oydid_W3C["verificationMethod"] = [key_doc, key_rev]

        #     if !oydid_W3C["authentication"].nil? && 
        #         oydid_W3C["authentication"].count == 1 &&
        #         !oydid_W3C["authentication"].first.is_a?(String) &&
        #         oydid_W3C["authentication"].first.keys == ["id"]
        #             auth_obj = key_ids[oydid_W3C["authentication"].first["id"]]
        #             auth_obj["publicKeyHex"] = Multibases.unpack(auth_obj["publicKeyMultibase"]).decode.to_s('ASCII-8BIT').unpack('H*').first
        #             auth_obj.delete("publicKeyMultibase")
        #             oydid_W3C["authentication"] = [auth_obj]
        #     end
        # end

        if result["did"].to_s.start_with?("did:oyd")
            did_identifier = Oydid.percent_encode(result["did"].to_s)
        else
            did_identifier = Oydid.percent_encode("did:oyd:" + result["did"].to_s)
        end
        retVal = {
            "didResolutionMetadata": didResolutionMetadata,
            "didDocument": oydid_W3C,
            "didDocumentMetadata": {
                "did": did_identifier,
                "keys": keys,
                "registry": Oydid.get_location(result["did"].to_s),
                "log_hash": result["doc"]["log"].to_s,
                "log": result["log"],
                "document_log_id": result["doc_log_id"].to_i,
                "termination_log_id": result["termination_log_id"].to_i
            }
        }
        equivalentIds = []
        result["log"].each do |log|
            if log["op"] == 2 || log["op"] == 3
                equivalentIds << Oydid.percent_encode("did:oyd:" + log["doc"])
            end
        end unless result["log"].nil?

        if equivalentIds.length > 1
            retVal[:didDocumentMetadata][:equivalentId] = equivalentIds
        end

        # if oydid_W3C["id"].split(":").take(2).join(":") == "did:oyd"
        #     # == temporary fix to handle wrong encoding ==
        #     # fix publicKeyMultibase for doc-key
        #     old_key = retVal[:didDocument]["verificationMethod"].first[:publicKeyMultibase]
        #     retVal[:didDocument]["verificationMethod"].first[:publicKeyMultibase] = Multibases.pack("base58btc", Multibases::DecodedByteArray.new((["0xED".to_i(16), 1] << Multibases.decode(old_key)[-32..]).flatten).to_s(Encoding::BINARY)).to_s

        #     # fix publicKeyMultibase for rev-key
        #     old_key = retVal[:didDocument]["verificationMethod"].last[:publicKeyMultibase]
        #     retVal[:didDocument]["verificationMethod"].last[:publicKeyMultibase] = Multibases.pack("base58btc", Multibases::DecodedByteArray.new((["0xED".to_i(16), 1] << Multibases.decode(old_key)[-32..]).flatten).to_s(Encoding::BINARY)).to_s

        #     # fix publicKeyMultibase in keyAgreement
        #     if !retVal[:didDocument]["keyAgreement"].nil?
        #         old_key = retVal[:didDocument]["keyAgreement"].first["publicKeyMultibase"]
        #         retVal[:didDocument]["keyAgreement"].first["publicKeyMultibase"] = Multibases.pack("base58btc", Multibases::DecodedByteArray.new((["0xEC".to_i(16), 1] << Multibases.decode(old_key)[-32..]).flatten).to_s(Encoding::BINARY)).to_s
        #     end


    #         if did == "did:oyd:zQmYSydHP5A1nRuqMcAoxpb971mfJrKJxpGJPEsxc5mw5Wt" ||
    #            did == "did:oyd:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
    # puts ">>> HACK for did:oyd:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2 - retVal: "
    #             retVal[:didDocument] = {
    #               "@context": retVal[:didDocument]["@context"],
    #               id: "did:oyd:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#key-doc",
    #               type: "Ed25519VerificationKey2020",
    #               controller: "did:oyd:zQmYSydHP5A1nRuqMcAoxpb971mfJrKJxpGJPEsxc5mw5Wt",
    #               publicKeyMultibase: "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"  
    #             }
    #             # publicKeyMultibase: Multibases.pack("base58btc", Multibases::DecodedByteArray.new(([237, 1] << Ed25519::SigningKey.new(RbNaCl::Hash.sha256("issuer-doc")).verify_key.to_bytes.bytes).flatten).to_s(Encoding::BINARY)).to_s
    #             # publicKeyMultibase: "z6Mkw5uiH8qNUCf3mXra9a2S3FLmqM4LsWj5oDyimLKt6AwE"
    #             # publicKeyMultibase: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    #             # publicKeyMultibase: "z6Mv9CjCfb8y5fWsT68XC1Xd36Cwaf1Mxxv1noYoStZg6hZn"
    #             # publicKeyMultibase: "zHdefgtaw8fAaf31sU14bC9nn1mnVTdUj7D4nw4MsAx9r"
    #             retVal[:didDocumentMetadata][:keys] = [{
    #                 kid: "did:oyd:zQmYSydHP5A1nRuqMcAoxpb971mfJrKJxpGJPEsxc5mw5Wt#key-doc",
    #                 kms: "local",
    #                 type: "Ed25519",
    #                 publicKeyHex: "f71e7d7d6d1723d4dd248c4a4fd209e1c1f6e886f99d2bea7f0dcdee79f8e285"
    #               }]
    # puts JSON.pretty_generate(retVal)
    # puts ">>> ------------"
    #         end

    #         if did == "did:oyd:zQmTxrzHj3vJ4SmWm9a2gB6q3JdshvBLbxmU9j1Z4y9tPP2"
    #             $counter += 1
    #             puts "counter: " + $counter.to_s
    # puts ">>> HACK for did:oyd:zQmTxrzHj3vJ4SmWm9a2gB6q3JdshvBLbxmU9j1Z4y9tPP2 - retVal: "
    #             # if $counter % 2 == 0
    #             #     retVal[:didDocument] = {
    #             #       "@context": retVal[:didDocument]["@context"],
    #             #       id: "did:oyd:zQmTxrzHj3vJ4SmWm9a2gB6q3JdshvBLbxmU9j1Z4y9tPP2#key-doc",
    #             #       type: "Ed25519VerificationKey2020",
    #             #       controller: "did:oyd:zQmTxrzHj3vJ4SmWm9a2gB6q3JdshvBLbxmU9j1Z4y9tPP2",
    #             #       publicKeyMultibase: "z6MkiVNMZbyMswTujRUvZqJpztuiCEQCatHPYJR6e7iYphPB"  
    #             #     }
    #             # else
    #                 retVal[:didDocument] = {
    #                   "@context": retVal[:didDocument]["@context"],
    #                   "id": "did:oyd:zQmTxrzHj3vJ4SmWm9a2gB6q3JdshvBLbxmU9j1Z4y9tPP2",
    #                   "verificationMethod": [
    #                     {
    #                       "id": "did:oyd:zQmTxrzHj3vJ4SmWm9a2gB6q3JdshvBLbxmU9j1Z4y9tPP2#key-doc",
    #                       "type": "Ed25519VerificationKey2020",
    #                       "controller": "did:oyd:zQmTxrzHj3vJ4SmWm9a2gB6q3JdshvBLbxmU9j1Z4y9tPP2",
    #                       "publicKeyMultibase": "z6MkiVNMZbyMswTujRUvZqJpztuiCEQCatHPYJR6e7iYphPB"
    #                     }
    #                   ],
    #                   "authentication": ["did:oyd:zQmTxrzHj3vJ4SmWm9a2gB6q3JdshvBLbxmU9j1Z4y9tPP2#key-doc"],
    #                   "assertionMethod": ["did:oyd:zQmTxrzHj3vJ4SmWm9a2gB6q3JdshvBLbxmU9j1Z4y9tPP2#key-doc"]
    #                 }
    #             # end
    #             retVal[:didDocumentMetadata][:keys] = [{
    #                 kid: "did:oyd:zQmTxrzHj3vJ4SmWm9a2gB6q3JdshvBLbxmU9j1Z4y9tPP2#key-doc",
    #                 kms: "local",
    #                 type: "Ed25519",
    #                 publicKeyHex: "fed013bf90b3d19867fc60c4e1dc434dbbc5653071d68a6a583f0ea5f563d96b8068e"
    #               }]
    # puts JSON.pretty_generate(retVal)
    # puts ">>> ------------"
    #         end
        # end

        if fragment.to_s != ""
            vms = retVal[:didDocument]["verificationMethod"]
            vms.each do |vm|
                if vm[:id].split('#').last == fragment
                    retVal[:didDocument] = {
                        "@context": retVal[:didDocument]["@context"],
                        id: vm[:id],
                        type: vm[:type],
                        controller: vm[:controller],
                        publicKeyMultibase: vm[:publicKeyMultibase]
                    }
                end
            end
        end


        render plain: retVal.to_json,
               mime_type: Mime::Type.lookup("application/ld+json"),
               content_type: 'application/ld+json',
               status: 200
    end

    def resolve
        render plain: {"status": "in progress", "did": params[:did].to_s}.to_json,
               mime_type: Mime::Type.lookup("application/ld+json"),
               content_type: 'application/ld+json',
               status: 200

    end

    def resolve_representation
        render plain: {"status": "in progress", "did": params[:did].to_s}.to_json,
               mime_type: Mime::Type.lookup("application/ld+json"),
               content_type: 'application/ld+json',
               status: 200

    end

    def dereference
        render plain: {"status": "in progress", "did": params[:did].to_s}.to_json,
               mime_type: Mime::Type.lookup("application/ld+json"),
               content_type: 'application/ld+json',
               status: 200

    end

end