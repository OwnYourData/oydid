class DidsController < ApplicationController
    include ApplicationHelper
    include ApplicationHelperLegacy
    include ActionController::MimeResponds

    # respond only to JSON requests
    respond_to :json
    respond_to :html, only: []
    respond_to :xml, only: []

    # Media types of the DID Resolution HTTP(S) binding
    # (https://w3c.github.io/did-resolution/#bindings-https). The Universal
    # Resolver sends the legacy profile form, newer clients the short form;
    # both mean the same thing.
    MEDIA_TYPE_RESOLUTION        = "application/did-resolution"
    MEDIA_TYPE_RESOLUTION_LEGACY = 'application/ld+json;profile="https://w3id.org/did-resolution"'
    MEDIA_TYPE_DEREFERENCING     = "application/did-url-dereferencing"
    MEDIA_TYPE_DOCUMENT          = "application/did"
    MEDIA_TYPE_DOCUMENT_LD       = "application/did+ld+json"

    # GET /1.0/identifiers/<did>
    # Binding used by the Universal Resolver driver: answers with the full
    # DID Resolution Result as application/ld+json - unchanged behaviour, no
    # content negotiation, because that is what the driver configuration in
    # uni-resolver-web expects.
    def uniresolver_resolve
        payload, status = resolution_result(params[:did], params[:fragment])
        if status != 200
            render json: payload, status: status
            return
        end
        render plain: payload.to_json,
               mime_type: Mime::Type.lookup("application/ld+json"),
               content_type: 'application/ld+json',
               status: 200
    end

    # GET /1.0/resolve/<did>
    # `resolve` function of the DID Resolution spec. Content negotiated:
    #   Accept: application/did-resolution            -> DID Resolution Result
    #   Accept: application/ld+json;profile="...did-resolution"  (legacy) -> ditto
    #   Accept: application/did (or application/did+ld+json)     -> DID Document only
    #   no/other Accept                               -> DID Resolution Result
    # The default stays the Resolution Result so that this path can be used
    # interchangeably with /1.0/identifiers/.
    def resolve
        payload, status = resolution_result(params[:did], params[:fragment])
        response.headers["Vary"] = "Accept"
        if status != 200
            render json: payload, status: status
            return
        end
        shape, content_type = negotiated_media_type(:resolution)
        payload[:didResolutionMetadata][:contentType] = MEDIA_TYPE_DOCUMENT if shape == :resolution
        body = (shape == :document) ? payload[:didDocument] : payload
        render plain: body.to_json,
               mime_type: Mime::Type.lookup("application/ld+json"),
               content_type: content_type,
               status: 200
    end

    # GET /1.0/resolveRepresentation/<did>
    # `resolveRepresentation` function: the DID Document in a concrete
    # representation. Defaults to the document; a client that explicitly asks
    # for application/did-resolution still gets the full result.
    def resolve_representation
        payload, status = resolution_result(params[:did], params[:fragment])
        response.headers["Vary"] = "Accept"
        if status != 200
            render json: payload, status: status
            return
        end
        shape, content_type = negotiated_media_type(:document)
        payload[:didResolutionMetadata][:contentType] = MEDIA_TYPE_DOCUMENT if shape == :resolution
        body = (shape == :document) ? payload[:didDocument] : payload
        render plain: body.to_json,
               mime_type: Mime::Type.lookup("application/ld+json"),
               content_type: content_type,
               status: 200
    end

    # GET /1.0/dereference/<did-url>
    # `dereference` function. Supported DID URL syntax: a plain DID and a
    # fragment (did:oyd:...#key-doc). Path, query and service parameters are
    # not part of the OYDID method and are reported as notSupported instead of
    # being silently ignored.
    def dereference
        did_url = params[:did].to_s
        did_url, _, fragment = did_url.partition("#")
        # a slash *after* the method-specific id would be a DID URL path
        path_start = did_url.index("/", (did_url.index(":oyd:").to_i + 5))
        if did_url.include?("?") || !path_start.nil?
            render json: {"dereferencingMetadata": {"error": "notSupported",
                                                    "errorMessage": "OYDID does not define path or query parameters in DID URLs"},
                          "contentStream": nil,
                          "contentMetadata": {}},
                   status: 501
            return
        end
        payload, status = resolution_result(did_url, fragment)
        response.headers["Vary"] = "Accept"
        if status != 200
            render json: {"dereferencingMetadata": payload,
                          "contentStream": nil,
                          "contentMetadata": {}},
                   status: status
            return
        end
        retVal = {
            "dereferencingMetadata": {"contentType": MEDIA_TYPE_DOCUMENT},
            "contentStream": payload[:didDocument],
            "contentMetadata": payload[:didDocumentMetadata]
        }
        render plain: retVal.to_json,
               mime_type: Mime::Type.lookup("application/ld+json"),
               content_type: MEDIA_TYPE_DEREFERENCING,
               status: 200
    end

    private

    # Reads the Accept header and decides what to send back.
    # Returns [:resolution|:document, content_type]; `default_shape` is used
    # when the client states no preference we recognise.
    def negotiated_media_type(default_shape)
        accept = request.headers["Accept"].to_s
        accept.split(",").each do |entry|
            entry = entry.strip.downcase.delete('"')
            next if entry.empty? || entry.start_with?("*/*")
            base_type = entry.split(";").first.to_s.strip
            profile = entry.include?("profile=") ? entry.split("profile=").last.to_s.split(";").first.to_s.strip : nil
            if base_type == MEDIA_TYPE_RESOLUTION
                return [:resolution, MEDIA_TYPE_RESOLUTION]
            elsif profile == "https://w3id.org/did-resolution"
                return [:resolution, MEDIA_TYPE_RESOLUTION_LEGACY]
            elsif base_type == MEDIA_TYPE_DOCUMENT
                return [:document, MEDIA_TYPE_DOCUMENT]
            elsif base_type == MEDIA_TYPE_DOCUMENT_LD || base_type == "application/did+json"
                return [:document, base_type]
            end
        end
        default_shape == :document ? [:document, MEDIA_TYPE_DOCUMENT_LD] : [:resolution, 'application/ld+json']
    end

    # Resolves `did` and builds the DID Resolution Result.
    # Returns [payload, http_status]; on failure the payload is the error
    # object the endpoints render as-is.
    def resolution_result(did, fragment)
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
        result, read_msg = (Oydid.read(did, options) rescue [nil, ""])
        # A revoked DID is reported two ways: as error 410 when this process
        # resolved the log itself, and as the message "revoked" when the hosting
        # repository answered 410 (retrieve_document collapses every non-200 into
        # nil, so without the message the revocation would degrade to "not found").
        revoked = (!result.nil? && result["error"].to_i == REVOKED_ERROR) ||
                  read_msg.to_s == "revoked"
        # a revoked DID must not fall through to the legacy resolver: that path
        # does not evaluate the revocation record and would serve the old
        # DID Document again
        if !revoked && (result.nil? || result["error"] != 0)
            result = resolve_did_legacy(did, options)
        end
        if revoked
            response.headers["Cache-Control"] = "no-store"
            return [{"error": "revoked"},
                    (ENV["REVOKED_HTTP_STATUS"].to_s == "404" ? 404 : 410)]
        end
        if result.nil?
            return [{"error": "not found"}, 404]
        end
        if result["error"] != 0
            # internal error codes (1, 2, ...) are not HTTP status codes
            return [{"error": result["message"].to_s},
                    (result["error"].to_i == 404 ? 404 : 500)]
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
                "kid": Oydid.document_id(result) + '#key-doc',
                "kms": "local",
                "type": "Ed25519", 
                "publicKeyHex": Oydid.multi_decode(result["doc"]["key"].split(":").first).first.unpack('H*').first
            }

            # revocation key
            keys << {
                "kid": Oydid.document_id(result) + '#key-rev',
                "kms": "local",
                "type": "Ed25519", 
                "publicKeyHex": Oydid.multi_decode(result["doc"]["key"].split(":").last).first.unpack('H*').first
            }
        when 'p256-pub'
            pubDocKey_jwk, msg = Oydid.public_key_to_jwk(result["doc"]["key"].split(":").first)
            if pubDocKey_jwk.nil?
                return [{"error": "document key: " + msg.to_s}, 500]
            end
            pubRevKey_jwk, msg = Oydid.public_key_to_jwk(result["doc"]["key"].split(":").last)
            if pubRevKey_jwk.nil?
                return [{"error": "revocation key: " + msg.to_s}, 500]
            end

            # document key
            keys << {
                "kid": Oydid.document_id(result) + '#key-doc',
                "kms": "local",
                "type": "JsonWebKey2020",
                "publicKeyJwk": pubDocKey_jwk
            }

            # revocation key
            keys << {
                "kid": Oydid.document_id(result) + '#key-rev',
                "kms": "local",
                "type": "JsonWebKey2020",
                "publicKeyJwk": pubRevKey_jwk
            }
        else
            return [{"error": "unsupported key codec (" + Multicodecs[code].name.to_s + ")"}, 500]
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

        # the identifier the document carries as `id` - after an update that is
        # the requested version, not the one the log resolves to; canonicalId
        # below names the current one
        did_identifier = Oydid.document_id(result)
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
        # The version identifiers used to be collected here with a rule of their
        # own: the current DID ended up in its own equivalentId list, and a DID
        # with exactly one earlier version reported none at all. Oydid.version_ids
        # is the single source now, shared with the repository and with the
        # alsoKnownAs that Oydid.w3c writes into the document itself.
        canonical_id, equivalent_ids = Oydid.version_ids(result)
        retVal[:didDocumentMetadata][:canonicalId] = canonical_id
        retVal[:didDocumentMetadata][:equivalentId] = equivalent_ids if equivalent_ids.any?

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


        [retVal, 200]
    end

end