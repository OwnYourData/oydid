# -*- encoding: utf-8 -*-
# frozen_string_literal: true

class Hash
    def except(*keys)
        self.reject { |key, _| keys.include?(key) }
    end
end

class Oydid

    # basic functions ---------------------------
    # %w[multibases multihashes rbnacl json multicodecs].each { |f| require f }
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
        decoded_message, error = Oydid.multi_decode(message)
        if decoded_message.nil?
            return [nil, error]
        end
        retVal = Multihashes.decode decoded_message
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
    def self.generate_private_key(input, method = "ed25519-priv", options = {})
        begin
            omc = Multicodecs[method].code
        rescue
            return [nil, "unknown key codec"]
        end
        
        case Multicodecs[method].name 
        when 'ed25519-priv'
            if input != ""
                raw_key = Ed25519::SigningKey.new(RbNaCl::Hash.sha256(input))
            else
                raw_key = Ed25519::SigningKey.generate
            end
            raw_key = raw_key.to_bytes
            length = raw_key.bytesize
        else
            return [nil, "unsupported key codec"]
        end
        
        encoded = multi_encode([omc, length, raw_key].pack("SCa#{length}"), options)
        # encoded = multi_encode(raw_key.to_bytes, options)
        if encoded.first.nil?
            return [nil, encoded.last]
        else
            return [encoded.first, ""]
        end
    end

    def self.public_key(private_key, options = {}, method = "ed25519-pub")
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
            # encoded = multi_encode(public_key.to_bytes, options)
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

    def self.getPrivateKey(enc, pwd, dsk, dfl, options)
        if enc.to_s == "" # usually read from options[:doc_enc]
            if pwd.to_s == "" # usually read from options[:doc_pwd]
                if dsk.to_s == "" # usually read from options[:doc_key]
                    if dfl.to_s == "" # default file name for key
                        return [nil, "no reference"]
                    else
                        privateKey, msg = read_private_key(dfl.to_s, options)
                    end
                else
                    privateKey, msg = read_private_key(dsk.to_s, options)
                end
            else
                privateKey, msg = generate_private_key(pwd, 'ed25519-priv', options)
            end
        else
            privateKey, msg = decode_private_key(enc.to_s, options)
        end
        return [privateKey, msg]
    end

    # if the identifier is already the public key there is no validation if it is a valid key
    # (this is a privacy-preserving feature)
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

    # available key_types
    # * doc - document key
    # * rev - revocation key
    def self.getDelegatedPubKeysFromDID(did, key_type = "doc")
        # retrieve DID
        did_document, msg = read(did, {})
        keys, msg = getDelegatedPubKeysFromFullDidDocument(did_document, key_type)
        if keys.nil?
            return [nil, msg]
        else
            return [keys, ""]
        end
    end

    def self.getDelegatedPubKeysFromFullDidDocument(did_document, key_type = "doc")
        # get current public key
        case key_type
        when "doc"
            keys = [did_document["doc"]["key"].split(":").first] rescue nil
        when "rev"
            keys = [did_document["doc"]["key"].split(":").last] rescue nil
        else
            return [nil, "invalid key type: " + key_type]
        end
        if keys.nil?
            return [nil, "cannot retrieve current key"]
        end

        # travers through log and get active delegation public keys
        log = did_document["log"]
        log.each do |item|
            if item["op"] == 5 # DELEGATE
                # !!!OPEN: check if log entry is confirmed / referenced in a termination entry
                item_keys = item["doc"]
                if key_type == "doc" && item_keys[0..3] == "doc:"
                    keys << item_keys[4-item_keys.length..]
                elsif key_type == "rev" && item_keys[0..3] == "rev:"
                    keys << item_keys[4-item_keys.length..]
                end
            end
        end unless log.nil?

        # return array
        return [keys.uniq, ""]
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

    def self.encrypt(message, public_key, options = {})
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

    def self.decrypt(message, private_key, options = {})
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

    # key="812b578d2e357270cbbd26a9dd44f93e5c8a3b44462e271348ce8f742dfe08144d06fd1f64d5a15c5b21564695d0dca9d65af322e8f96ef394400fe255d288cf"
    def jweh(key)
        pub_key=key[-64..-1]
        prv_key=key[0..-65]
        
        hex_pub=pub_key
        bin_pub=[hex_pub].pack('H*')
        int_pub=RbNaCl::PublicKey.new(bin_pub)
        len_pub=int_pub.to_bytes.bytesize
        enc_pub=Oydid.multi_encode([Multicodecs["x25519-pub"].code,len_pub,int_pub].pack("CCa#{len_pub}"),{}).first

        hex_prv=prv_key
        bin_prv=[hex_prv].pack('H*')
        int_prv=RbNaCl::PrivateKey.new(bin_prv)
        len_prv=int_prv.to_bytes.bytesize
        enc_prv=Oydid.multi_encode([Multicodecs["ed25519-priv"].code,len_prv,int_prv].pack("SCa#{len_prv}"),{}).first
        return [enc_pub, enc_prv]
    end

    # public_key=jweh(key).first
    # require 'oydid'
    # message="hallo"
    # public_key="z6Mv4uEoFYJ369NoE9xUzxG5sm8KpPnvHX6YH6GsYFGSQ32J"
    # jwe=Oydid.encryptJWE(message, public_key).first
    def self.encryptJWE(message, public_key, options = {})

        jwe_header = {"enc":"XC20P"}
        recipient_alg = 'ECDH-ES+XC20PKW'

        # Content Encryption ---
        # random nonce for XChaCha20-Poly1305: uses a 192-bit nonce (24 bytes)
        cnt_nnc = RbNaCl::Random.random_bytes(RbNaCl::AEAD::XChaCha20Poly1305IETF.nonce_bytes)
        # random key for XChaCha20-Poly1305: uses a 256-bit key (32 bytes)
        cnt_key = RbNaCl::Random.random_bytes(RbNaCl::AEAD::XChaCha20Poly1305IETF.key_bytes)
        # addtional data
        cnt_aad = jwe_header.to_json
        # setup XChaCha20-Poly1305 for Authenticated Encryption with Associated Data (AEAD)
        cnt_aead = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(cnt_key)
        # encrypt
        msg_enc = cnt_aead.encrypt(cnt_nnc, message, cnt_aad)
        cnt_enc = msg_enc[0...-cnt_aead.tag_bytes]
        cnt_tag = msg_enc[-cnt_aead.tag_bytes .. -1]

        # Key Encryption ---
        snd_prv = RbNaCl::PrivateKey.generate
        code, length, digest = Oydid.multi_decode(public_key).first.unpack('CCa*')
        buffer = RbNaCl::Util.zeros(RbNaCl::Boxes::Curve25519XSalsa20Poly1305::PublicKey::BYTES)
        RbNaCl::Signatures::Ed25519::VerifyKey.crypto_sign_ed25519_pk_to_curve25519(buffer, digest)
        shared_secret = RbNaCl::GroupElement.new(buffer).mult(snd_prv.to_bytes)
        jwe_const = [0, 0, 0, 1] + 
            shared_secret.to_bytes.unpack('C*') + 
            [0,0,0,15] + 
            recipient_alg.bytes + 
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
        kek = RbNaCl::Hash.sha256(jwe_const.pack('C*'))
        snd_nnc = RbNaCl::Random.random_bytes(RbNaCl::AEAD::XChaCha20Poly1305IETF.nonce_bytes)
        snd_aead = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(kek)
        snd_enc = snd_aead.encrypt(snd_nnc, cnt_key, nil)
        snd_key = snd_enc[0...-snd_aead.tag_bytes]
        snd_aut = snd_enc[-snd_aead.tag_bytes .. -1]

        # create JWE ---
        jwe_protected = Base64.urlsafe_encode64(jwe_header.to_json).delete("=")
        jwe_encrypted_key = Base64.urlsafe_encode64(snd_key).delete("=")
        jwe_init_vector = Base64.urlsafe_encode64(cnt_nnc).delete("=")
        jwe_cipher_text = Base64.urlsafe_encode64(cnt_enc).delete("=")
        jwe_auth_tag = Base64.urlsafe_encode64(cnt_tag).delete("=")
        rcp_nnc_enc = Base64.urlsafe_encode64(snd_nnc).delete("=")
        rcp_tag_enc = Base64.urlsafe_encode64(snd_aut).delete("=")

        jwe_full = {
            protected: jwe_protected,
            iv: jwe_init_vector,
            ciphertext: jwe_cipher_text,
            tag: jwe_auth_tag,
            recipients: [
                {
                    encrypted_key: jwe_encrypted_key,
                    header: {
                        alg: recipient_alg,
                        iv: rcp_nnc_enc,
                        tag: rcp_tag_enc,
                        epk: {
                            kty: "OKP",
                            crv: "X25519",
                            x: Base64.urlsafe_encode64(snd_prv.public_key.to_bytes).delete("=")
                        }
                    }
                }
            ]
        }

        jwe = jwe_protected
        jwe += "." + jwe_encrypted_key
        jwe += "." + jwe_init_vector
        jwe += "." + jwe_cipher_text
        jwe += "." + jwe_auth_tag

        return [jwe_full, ""]
    end

    # require 'oydid'
    # message = '{"protected":"eyJlbmMiOiJYQzIwUCJ9","iv":"G24pK06HSbL0vTlRZMIEBLfa074tJ1tq","ciphertext":"N5bgUr8","tag":"CJeq8cuaercgoBZmrYoGUA","recipients":[{"encrypted_key":"chR8HQh1CRYRU4TdlfBbvon4fcb5PKfWPSo0SgkMC_8","header":{"alg":"ECDH-ES+XC20PKW","iv":"K7lUo8shyJhxC7Nl45VlXes4tbDeZyBL","tag":"2sLCGRv70ESqEAqos3ZhSg","epk":{"kty":"OKP","crv":"X25519","x":"ZpnKcI7Kac6HPwVAGwM0PBweTFKM6wHHVljTHMRWpD4"}}}]}'
    # message = jwe.to_json
    # private_key = "z1S5USmDosHvi2giCLHCCgcq3Cd31mrhMcUy2fcfszxxLkD7"
    # Oydid.decryptJWE(jwe.to_json, private_key)
    def self.decryptJWE(message, private_key, options = {})

        # JWE parsing
        jwe_full = JSON.parse(message)
        snd_pub_enc = jwe_full["recipients"].first["header"]["epk"]["x"]
        snd_key_enc = jwe_full["recipients"].first["encrypted_key"]
        snd_nnc_enc = jwe_full["recipients"].first["header"]["iv"]
        snd_tag_enc = jwe_full["recipients"].first["header"]["tag"]
        cnt_cip_enc = jwe_full["ciphertext"]
        cnt_tag_enc = jwe_full["tag"]
        cnt_nnc_enc = jwe_full["iv"]
        cnt_aad_enc = jwe_full["protected"]
        recipient_alg = jwe_full["recipients"].first["header"]["alg"]

        snd_pub = Base64.urlsafe_decode64(snd_pub_enc)
        snd_nnc = Base64.urlsafe_decode64(snd_nnc_enc)
        snd_key = Base64.urlsafe_decode64(snd_key_enc)
        snd_tag = Base64.urlsafe_decode64(snd_tag_enc)
        cnt_nnc = Base64.urlsafe_decode64(cnt_nnc_enc)
        cnt_cip = Base64.urlsafe_decode64(cnt_cip_enc)
        cnt_tag = Base64.urlsafe_decode64(cnt_tag_enc)
        cnt_aad = Base64.urlsafe_decode64(cnt_aad_enc)

        # Key Decryption
        code, length, digest = Oydid.multi_decode(private_key).first.unpack('SCa*')
        buffer = RbNaCl::Util.zeros(RbNaCl::Boxes::Curve25519XSalsa20Poly1305::PublicKey::BYTES)
        RbNaCl::Signatures::Ed25519::SigningKey.crypto_sign_ed25519_sk_to_curve25519(buffer, digest)
        shared_secret = RbNaCl::GroupElement.new(snd_pub).mult(buffer)
        jwe_const = [0, 0, 0, 1] + 
            shared_secret.to_bytes.unpack('C*') + 
            [0,0,0,15] + 
            recipient_alg.bytes + 
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
        kek = RbNaCl::Hash.sha256(jwe_const.pack('C*'))
        snd_aead = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(kek)
        cnt_key = snd_aead.decrypt(snd_nnc, snd_key+snd_tag, nil)

        # Content Decryption
        cnt_aead = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(cnt_key)
        cnt_dec = cnt_aead.decrypt(cnt_nnc, cnt_cip+cnt_tag, cnt_aad)

        return [cnt_dec, ""]
    end

    def self.read_private_key(filename, options)
        begin
            f = File.open(filename)
            key_encoded = f.read.strip
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
            when 'x25519-pub'
                pub_key = RbNaCl::PublicKey.new(digest)
                return [pub_key, ""]
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
            option_str = ""
            if options[:followAlsoKnownAs]
                option_str = "?followAlsoKnownAs=true"
            end
            retVal = HTTParty.get(doc_location + "/doc/" + doc_identifier + option_str)
            if retVal.code != 200
                msg = retVal.parsed_response["error"].to_s rescue ""
                if msg.to_s == ""
                    msg = "invalid response from " + doc_location.to_s + "/doc/" + doc_identifier.to_s
                end
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