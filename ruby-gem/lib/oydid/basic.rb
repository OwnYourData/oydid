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
        code = Multicodecs[method].code
        length = digest.bytesize
        encoded = multi_encode([code, length, digest].pack("CCa#{length}"), options)
        # encoded = multi_encode(Multihashes.encode(digest, method.to_s), options)
        if encoded.first.nil?
            return [nil, encoded.last]
        else
            return [encoded.first, ""]
        end
    end

    def self.get_digest(message)
        decoded_message, error = multi_decode(message)
        if decoded_message.nil?
            return [nil, error]
        end
        # retVal = Multihashes.decode decoded_message
        # if retVal[:hash_function].to_s != ""
        #     return [retVal[:hash_function].to_s, ""]
        # end
        case decoded_message[0..1].to_s
        when "\x02\x10"
            return ["blake2b-16", ""]
        when "\x04 "
            return ["blake2b-32", ""]
        when "\b@"
            return ["blake2b-64", ""]
        else
            code, length, digest = decoded_message.unpack('CCa*')
            retVal = Multicodecs[code].name rescue nil
            if !retVal.nil?
                return [retVal, ""]
            else
                return [nil, "unknown digest"]
            end
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

    def self.to_varint(n)
        bytes = []
        loop do
            byte = n & 0x7F
            n >>= 7
            if n == 0
                bytes << byte
                break
            else
                bytes << (byte | 0x80)
            end
        end
        bytes
    end

    def self.read_varint(str)
        n = shift = 0
        str.each_byte do |byte|
            n |= (byte & 0x7f) << shift
            break unless (byte & 0x80) == 0x80
            shift += 7
        end
        return n
    end

    # key management ----------------------------
    def self.get_keytype(input)
        code, length, digest = multi_decode(input).first.unpack('SCa*')
        case Multicodecs[code]&.name
        when 'ed25519-priv', 'p256-priv'
            return Multicodecs[code].name
        else
            pubkey = multi_decode(input).first
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
            case Multicodecs[code]&.name
            when 'ed25519-pub', 'p256-pub'
                return Multicodecs[code].name
            else
                return nil
            end
        end
    end

    def self.generate_private_key(input, method = "ed25519-priv", options = {})
        begin
            omc = Multicodecs[method].code
        rescue
            return [nil, "unknown key codec"]
        end
        
        case Multicodecs[method].name 
        when 'ed25519-priv'
            if input == ""
                raw_key = Ed25519::SigningKey.generate
            else
                raw_key = Ed25519::SigningKey.new(RbNaCl::Hash.sha256(input))
            end
            raw_key = raw_key.to_bytes
        when 'p256-priv'
            key = OpenSSL::PKey::EC.new('prime256v1')
            if input == ""
                key = OpenSSL::PKey::EC.generate('prime256v1')
            else
                # input for p256-priv requires valid base64 encoded private key
                begin
                    key = OpenSSL::PKey.read Base64.decode64(input)
                rescue
                    return [nil, "invalid input"]
                end
            end
            raw_key = key.private_key.to_s(2)
        else
            return [nil, "unsupported key codec"]
        end

        # only encoding without specifying key-type
        # encoded = multi_encode(raw_key, options)

        # encoding with specyfying key-type
        length = raw_key.bytesize
        encoded = multi_encode([omc, length, raw_key].pack("SCa#{length}"), options)
        if encoded.first.nil?
            return [nil, encoded.last]
        else
            return [encoded.first, ""]
        end
    end

    def self.public_key(private_key, options = {}, method = nil)
        code, length, digest = multi_decode(private_key).first.unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            method = 'ed25519-pub' if method.nil?
            case method
            when 'ed25519-pub'
                public_key = Ed25519::SigningKey.new(digest).verify_key
            when 'x25519-pub'
                public_key = RbNaCl::PrivateKey.new(digest).public_key
            else
                return [nil, "unsupported key codec"]
            end

            # encoding according to https://www.w3.org/TR/vc-di-eddsa/#ed25519verificationkey2020
            encoded = multi_encode(
                Multibases::DecodedByteArray.new(
                    ([Multicodecs[method].code, 1] << 
                        public_key.to_bytes.bytes).flatten)
                    .to_s(Encoding::BINARY),
                options)

            # previous (up until oydid 0.5.6) wrong encoding (length should not be set!):
            # length = public_key.to_bytes.bytesize
            # encoded = multi_encode([Multicodecs[method].code, length, public_key].pack("CCa#{length}"), options)
            if encoded.first.nil?
                return [nil, encoded.last]
            else
                return [encoded.first, ""]
            end
        when 'p256-priv'
            method = 'p256-pub' if method.nil?
            group = OpenSSL::PKey::EC::Group.new('prime256v1')
            public_key = group.generator.mul(OpenSSL::BN.new(digest, 2))
            encoded = multi_encode(
                Multibases::DecodedByteArray.new(
                    (to_varint(0x1200) << public_key.to_bn.to_s(2).bytes)
                    .flatten).to_s(Encoding::BINARY),
                options)
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
            if msg.nil?
                privateKey = enc.to_s
            end
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

    def self.sign(message, private_key, options = {})
        key_type = get_keytype(private_key)
        case key_type
        when 'ed25519-priv'
            code, length, digest = multi_decode(private_key).first.unpack('SCa*')
            encoded = multi_encode(Ed25519::SigningKey.new(digest).sign(message), options)
            if encoded.first.nil?
                return [nil, encoded.last]
            else
                return [encoded.first, ""]
            end
        when 'p256-priv'
            # non-deterministic signing
            # ec_key = decode_private_key(private_key).first
            # dgst_bin = OpenSSL::Digest::SHA256.digest(message)
            # der = ec_key.dsa_sign_asn1(dgst_bin)
            # asn1 = OpenSSL::ASN1.decode(der)
            # r_hex = asn1.value[0].value.to_s(16).rjust(64, '0')
            # s_hex = asn1.value[1].value.to_s(16).rjust(64, '0')
            # sig_bin = [r_hex + s_hex].pack('H*')
            # encoded_signature = Base64.strict_encode64(sig_bin).tr('+/', '-_').delete('=')

            # === deterministic signing with P-256 =====
            # key & constants
            ec_key = decode_private_key(private_key).first
            if (ec_key.respond_to?(:private_key) ? ec_key.private_key : nil).nil?
                return [nil, "invalild private key"]
            end

            group = OpenSSL::PKey::EC::Group.new('prime256v1')
            n = group.order
            qlen = n.num_bits
            holen = 256
            bx = ec_key.private_key

            # hash message
            h1_bin = OpenSSL::Digest::SHA256.digest(message)
            h1_int = h1_bin.unpack1('H*').to_i(16)

            # helper (RFC 6979 Section 2.3)
            int2octets = lambda do |int|
                bin = int.to_s(16).rjust((qlen + 7) / 8 * 2, '0')
                [bin].pack('H*')
            end
            bits2octets = lambda do |bits|
                z1 = bits % n
                int2octets.call(z1)
            end

            # initialize HMAC-DRBG
            v = "\x01" * (holen / 8)
            k = "\x00" * (holen / 8)
            key_oct = int2octets.call(bx)
            hash_oct = bits2octets.call(h1_int)

            k = OpenSSL::HMAC.digest('SHA256', k, v + "\x00" + key_oct + hash_oct)
            v = OpenSSL::HMAC.digest('SHA256', k, v)
            k = OpenSSL::HMAC.digest('SHA256', k, v + "\x01" + key_oct + hash_oct)
            v = OpenSSL::HMAC.digest('SHA256', k, v)

            # identify k (step H in RFC 6979)
            loop do
                v = OpenSSL::HMAC.digest('SHA256', k, v)
                t = v.unpack1('H*').to_i(16)

                k_candidate = t % n
                if k_candidate.positive? && k_candidate < n
                    k_bn = OpenSSL::BN.new(k_candidate)
                    # calculate signature (r,s)
                    r_bn = group.generator.mul(k_bn).to_bn                     # Point → BN (uncompressed)
                    # extract x
                    r_int = r_bn.to_s(2)[1, 32].unpack1('H*').to_i(16) % n
                    next if r_int.zero?

                    kinv = k_bn.mod_inverse(n)
                    s_int = (kinv * (h1_int + bx.to_i * r_int)) % n
                    next if s_int.zero?
                    s_int = n.to_i - s_int if s_int > n.to_i / 2

                    # encode r||s -> URL-safe Base64
                    r_hex = r_int.to_s(16).rjust(64, '0')
                    s_hex = s_int.to_s(16).rjust(64, '0')
                    sig   = [r_hex + s_hex].pack('H*')
                    return [Base64.urlsafe_encode64(sig, padding: false), ""]
                end

                k = OpenSSL::HMAC.digest('SHA256', k, v + "\x00")
                v = OpenSSL::HMAC.digest('SHA256', k, v)
            end            

            return [encoded_signature, ""]
        else
            return [nil, "unsupported key codec"]
        end
    end

    def self.verify(message, signature, public_key)
        begin
            pubkey = multi_decode(public_key).first
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
            when 'p256-pub'
                asn1_public_key = OpenSSL::ASN1::Sequence.new([
                  OpenSSL::ASN1::Sequence.new([
                    OpenSSL::ASN1::ObjectId.new('id-ecPublicKey'),
                    OpenSSL::ASN1::ObjectId.new('prime256v1')
                  ]),
                  OpenSSL::ASN1::BitString.new(digest)
                ])
                key = OpenSSL::PKey::EC.new(asn1_public_key.to_der)

                sig_raw = Base64.urlsafe_decode64(signature + "=" * ((4 - signature.size % 4) % 4))
                r_hex   = sig_raw[0, 32].unpack1("H*")
                s_hex   = sig_raw[32, 32].unpack1("H*")
                asn_r   = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(r_hex, 16))
                asn_s   = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(s_hex, 16))
                sig_der = OpenSSL::ASN1::Sequence.new([asn_r, asn_s]).to_der

                message_digest = OpenSSL::Digest::SHA256.new
                valid = key.dsa_verify_asn1(message_digest.digest(message), sig_der)
                return [valid, ""]
            else
                return [nil, "unsupported key codec"]
            end
        rescue
            return [nil, "unknown key codec"]
        end
    end

    def self.encrypt(message, public_key, options = {})
        begin
            if options[:key_type].to_s == ''
                pk = multi_decode(public_key).first
                code = pk.bytes.first
                digest = pk[-32..]
                key_type = Multicodecs[code].name rescue ''
            else
                key_type = options[:key_type]
            end
            case key_type
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
            when 'p256-pub'
                recipient_pub_key = decode_public_key(public_key).first

                # a) Ephemeren Sender-Key erzeugen + ECDH
                ephemeral_key = OpenSSL::PKey::EC.generate('prime256v1')
                shared_secret = ephemeral_key.dh_compute_key(recipient_pub_key.public_key)

                # b) Ableitung Content-Encryption-Key (CEK) – simple HKDF-Light
                cek = OpenSSL::Digest::SHA256.digest(shared_secret)

                # c) Symmetrische Verschlüsselung (AES-256-GCM)
                cipher = OpenSSL::Cipher.new('aes-256-gcm')
                cipher.encrypt
                cipher.key = cek
                iv = OpenSSL::Random.random_bytes(12) # 96-bit IV wie empfohlen
                cipher.iv = iv
                cipher.auth_data = '' # kein AAD
                ciphertext = cipher.update(message) + cipher.final
                tag = cipher.auth_tag

                # d) JWE-Header (nur die nötigen Felder)
                header = {
                  alg: 'ECDH-ES',
                  enc: 'A256GCM',
                  kid: options[:kid],
                  epk: JWT::JWK.new(ephemeral_key).export.slice(:kty, :crv, :x, :y)
                }

                # e) JWE-Compact-Serialisierung (EncryptedKey leer bei ECDH-ES)
                jwe_compact = [
                    Base64.urlsafe_encode64(header.to_json).delete("="),
                    '',
                    Base64.urlsafe_encode64(iv).delete("="),
                    Base64.urlsafe_encode64(ciphertext).delete("="),
                    Base64.urlsafe_encode64(tag).delete("="),
                ].join('.')
                return [jwe_compact, nil]
            else
                return [nil, "unsupported key codec"]
            end
        rescue
            return [nil, "encryption failed"]
        end
    end

    def self.decrypt(message, private_key, options = {})
        begin
            key_type = get_keytype(private_key)
            case key_type
            when 'ed25519-priv'
                cipher = [JSON.parse(message)["value"]].pack('H*')
                nonce = [JSON.parse(message)["nonce"]].pack('H*')
                code, length, digest = multi_decode(private_key).first.unpack('SCa*')
                if length != 32 # support only encoded keys
                    digest = Multibases.unpack(private_key).decode.to_s('ASCII-8BIT')
                    code = Multicodecs["ed25519-priv"].code
                end
                privKey = RbNaCl::PrivateKey.new(digest)
                authHash = RbNaCl::Hash.sha256('auth'.dup.force_encoding('ASCII-8BIT'))
                authKey = RbNaCl::PrivateKey.new(authHash).public_key
                box = RbNaCl::Box.new(authKey, privKey)
                retVal = box.decrypt(nonce, cipher)
                return [retVal, ""]
            when 'p256-priv'
                private_key = decode_private_key(private_key).first
                head_b64, _, iv_b64, cipher_b64, tag_b64 = message.split('.')
                decoded_header = JSON.parse(Base64.urlsafe_decode64(head_b64))
                epk_pub = Oydid.decode_public_key(Oydid.public_key_from_jwk(decoded_header['epk']).first).first

                shared_secret2 = private_key.dh_compute_key(epk_pub.public_key) # ECDH (Gegenseite)
                cek2 = OpenSSL::Digest::SHA256.digest(shared_secret2)

                decipher = OpenSSL::Cipher.new('aes-256-gcm')
                decipher.decrypt
                decipher.key = cek2
                decipher.iv = Base64.urlsafe_decode64(iv_b64)
                decipher.auth_tag = Base64.urlsafe_decode64(tag_b64)
                decipher.auth_data = ''
                plaintext = decipher.update(Base64.urlsafe_decode64(cipher_b64)) + decipher.final

                return [plaintext, nil]
            else
                return [nil, "unsupported key codec"]
            end
        rescue
            return [nil, "decryption failed"]
        end
    end

    def jweh(key)
        pub_key=key[-64..-1]
        prv_key=key[0..-65]
        
        hex_pub=pub_key
        bin_pub=[hex_pub].pack('H*')
        int_pub=RbNaCl::PublicKey.new(bin_pub)
        len_pub=int_pub.to_bytes.bytesize
        enc_pub=multi_encode([Multicodecs["x25519-pub"].code,len_pub,int_pub].pack("CCa#{len_pub}"),{}).first

        hex_prv=prv_key
        bin_prv=[hex_prv].pack('H*')
        int_prv=RbNaCl::PrivateKey.new(bin_prv)
        len_prv=int_prv.to_bytes.bytesize
        enc_prv=multi_encode([Multicodecs["ed25519-priv"].code,len_prv,int_prv].pack("SCa#{len_prv}"),{}).first
        return [enc_pub, enc_prv]
    end

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
        code, length, digest = multi_decode(public_key).first.unpack('CCa*')
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
        code, length, digest = multi_decode(private_key).first.unpack('SCa*')
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
        key_type = get_keytype(key_encoded) || options[:key_type] rescue options[:key_type]
        if key_type.include?('-')
            key_type = key_type.split('-').first || options[:key_type] rescue options[:key_type]
        end
        if key_type == 'p256'
            begin
                key = decode_private_key(key_encoded).first
                private_key = key.private_key.to_s(2)
                code = Multicodecs["p256-priv"].code
            rescue
                return [nil, "invalid base64 encoded p256-priv key"]
            end
        else
            begin
                code, length, digest = multi_decode(key_encoded).first.unpack('SCa*')
                case Multicodecs[code].name
                when 'ed25519-priv'
                    private_key = Ed25519::SigningKey.new(digest).to_bytes
                # when 'p256-priv'
                #     key = OpenSSL::PKey::EC.new('prime256v1')
                #     key.private_key = OpenSSL::BN.new(digest, 2)
                #     private_key = key.private_key.to_s(2)
                else
                    return [nil, "unsupported key codec"]
                end
            rescue
                return [nil, "invalid key"]
            end
        end
        length = private_key.bytesize
        return multi_encode([code, length, private_key].pack("SCa#{length}"), options)

    end

    def self.decode_private_key(key_encoded, options = {})
        code, length, digest = multi_decode(key_encoded).first.unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            private_key = Ed25519::SigningKey.new(digest).to_bytes
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
            private_key = OpenSSL::PKey.read(ec_private_key_asn1.to_der)

        else
            return [nil, "unsupported key codec"]
        end
        return [private_key, nil]

    end

    def self.decode_public_key(key_encoded)
        begin
            pubkey = multi_decode(key_encoded).first
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
            case Multicodecs[code].name
            when 'ed25519-pub'
                verify_key = Ed25519::VerifyKey.new(digest)
                return [verify_key, ""]
            when 'x25519-pub'
                pub_key = RbNaCl::PublicKey.new(digest)
                return [pub_key, ""]
            when 'p256-pub'
                asn1_public_key = OpenSSL::ASN1::Sequence.new([
                  OpenSSL::ASN1::Sequence.new([
                    OpenSSL::ASN1::ObjectId.new('id-ecPublicKey'),
                    OpenSSL::ASN1::ObjectId.new('prime256v1')
                  ]),
                  OpenSSL::ASN1::BitString.new(digest)
                ])
                pub_key = OpenSSL::PKey::EC.new(asn1_public_key.to_der)

                return [pub_key, ""]
            else
                return [nil, "unsupported key codec"]
            end
        rescue
            return [nil, "unknown key codec"]
        end
    end

    def self.private_key_to_jwk(private_key)
        code, length, digest = multi_decode(private_key).first.unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            return [nil, "not supported yet"]
        when 'p256-priv'
            group = OpenSSL::PKey::EC::Group.new('prime256v1')
            public_key = group.generator.mul(OpenSSL::BN.new(digest, 2))
            point = public_key.to_bn.to_s(2) 

            x_bin = point[1, 32]
            y_bin = point[33, 32]
            x = Base64.urlsafe_encode64(x_bin, padding: false)
            y = Base64.urlsafe_encode64(y_bin, padding: false)
            d = Base64.urlsafe_encode64(digest, padding: false)

            jwk = {
              kty: "EC",
              crv: "P-256",
              x: x,
              y: y,
              d: d
            }
            return [jwk, ""]
        else
            return [nil, "unsupported key codec"]
        end
    end

    def self.public_key_to_jwk(public_key)
        begin
            pubkey = multi_decode(public_key).first
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
            case Multicodecs[code].name
            when 'ed25519-pub'
                return [nil, "not supported yet"]
            when 'p256-pub'
                if digest.bytes.first == 4
                    # Unkomprimiertes Format: X (32 Bytes) || Y (32 Bytes)
                    x_coord = digest[1..32]
                    y_coord = digest[33..64]
                    x_base64 = Base64.urlsafe_encode64(x_coord, padding: false)
                    y_base64 = Base64.urlsafe_encode64(y_coord, padding: false)
                else 
                    asn1_public_key = OpenSSL::ASN1::Sequence.new([
                      OpenSSL::ASN1::Sequence.new([
                        OpenSSL::ASN1::ObjectId.new('id-ecPublicKey'),
                        OpenSSL::ASN1::ObjectId.new('prime256v1')
                      ]),
                      OpenSSL::ASN1::BitString.new(digest)
                    ])
                    key = OpenSSL::PKey::EC.new(asn1_public_key.to_der)
                    x, y = key.public_key.to_octet_string(:uncompressed)[1..].unpack1('H*').scan(/.{64}/)
                    x_base64 = Base64.urlsafe_encode64([x].pack('H*'), padding: false)
                    y_base64 = Base64.urlsafe_encode64([y].pack('H*'), padding: false)
                end
                jwk = {
                    "kty" => "EC",
                    "crv" => "P-256",
                    "x" => x_base64,
                    "y" => y_base64 }
                return [jwk, ""]
            else
                return [nil, "unsupported key codec"]
            end
        rescue
            return [nil, "unknown key codec"]
        end
    end

    def self.base64_url_decode(str)
        Base64.urlsafe_decode64(str + '=' * (4 - str.length % 4))
    end

    def self.public_key_from_jwk(jwk, options = {})
        begin
            if jwk.is_a?(String)
                jwk = JSON.parse(jwk)
            end
        rescue
            return [nil, "invalid input"]
        end
        jwk = jwk.transform_keys(&:to_s)
        if jwk["kty"] == "EC" && jwk["crv"] == "P-256"
            x = base64_url_decode(jwk["x"])
            y = base64_url_decode(jwk["y"])
            digest = OpenSSL::ASN1::BitString.new(OpenSSL::BN.new("\x04" + x + y, 2).to_s(2))
            encoded = multi_encode(
                Multibases::DecodedByteArray.new(
                    (to_varint(0x1200) << digest.value.bytes)
                    .flatten).to_s(Encoding::BINARY),
                options)

            # asn1_public_key = OpenSSL::ASN1::Sequence.new([
            #   OpenSSL::ASN1::Sequence.new([
            #     OpenSSL::ASN1::ObjectId.new('id-ecPublicKey'),
            #     OpenSSL::ASN1::ObjectId.new('prime256v1')
            #   ]),
            #   OpenSSL::ASN1::BitString.new(OpenSSL::BN.new("\x04" + x + y, 2).to_s(2))
            # ])
            # pub_key = OpenSSL::PKey::EC.new(asn1_public_key.to_der)
            # encoded = multi_encode(
            #     Multibases::DecodedByteArray.new(
            #         (to_varint(0x1200) << pub_key.to_bn.to_s(2).bytes)
            #         .flatten).to_s(Encoding::BINARY),
            #     options)


            if encoded.first.nil?
                return [nil, encoded.last]
            else
                return [encoded.first, ""]
            end
        else
            return [nil, "unsupported key codec"]
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