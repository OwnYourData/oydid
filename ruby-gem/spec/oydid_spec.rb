require_relative 'spec_helper'
require 'tmpdir'
require 'securerandom'
require 'digest'

describe "OYDID handling" do
  # basic functions - base58btc encoding
  Dir.glob(File.expand_path("../input/basic/*_b58_enc.doc", __FILE__)).each do |input|
    it "encodes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.multi_encode(data, {}).first).to eq expected
    end
  end
  # base16 encoding
  Dir.glob(File.expand_path("../input/basic/*_b16_enc.doc", __FILE__)).each do |input|
    it "encodes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.multi_encode(data, {encode: "base16"}).first).to eq expected
    end
  end
  # base32 encoding
  Dir.glob(File.expand_path("../input/basic/*_b32_enc.doc", __FILE__)).each do |input|
    it "encodes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.multi_encode(data, {encode: "base32"}).first).to eq expected
    end
  end
  # base64 encoding
  Dir.glob(File.expand_path("../input/basic/*_b64_enc.doc", __FILE__)).each do |input|
    it "encodes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.multi_encode(data, {encode: "base64"}).first).to eq expected
    end
  end
  # invalid encoding
  Dir.glob(File.expand_path("../input/basic/*_b17_enc.doc", __FILE__)).each do |input|
    it "encodes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.multi_encode(data, {encode: "base17"}).last).to eq expected
    end
  end
  # decoding
  Dir.glob(File.expand_path("../input/basic/*_dec.doc", __FILE__)).each do |input|
    it "decodes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.multi_decode(data).first.to_s).to eq expected
    end
  end
  # invalid decoding
  Dir.glob(File.expand_path("../input/basic/*_b17_edec.doc", __FILE__)).each do |input|
    it "decodes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.multi_decode(data).last.to_s).to eq expected
    end
  end
  # multi_hash: sha2-256, b58
  Dir.glob(File.expand_path("../input/basic/*_sha2-256_b58_hash.doc", __FILE__)).each do |input|
    it "hashes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.multi_hash(data, {}).first).to eq expected
    end
  end
  # multi_hash: sha2-512, b58
  Dir.glob(File.expand_path("../input/basic/*_sha2-512_b58_hash.doc", __FILE__)).each do |input|
    it "hashes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.multi_hash(data, {digest: "sha2-512"}).first).to eq expected
    end
  end
  # multi_hash: sha3-224, b64
  Dir.glob(File.expand_path("../input/basic/*_sha3-224_b64_hash.doc", __FILE__)).each do |input|
    it "hashes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.multi_hash(data, {digest: "sha3-224", encode: "base64"}).first).to eq expected
    end
  end
  # multi_hash: blake2b-16, b16
  Dir.glob(File.expand_path("../input/basic/*_blake2b-16_b16_hash.doc", __FILE__)).each do |input|
    it "hashes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.multi_hash(data, {digest: "blake2b-16", encode: "base16"}).first).to eq expected
    end
  end
  # multi_hash: blake2b-32, b32
  Dir.glob(File.expand_path("../input/basic/*_blake2b-32_b32_hash.doc", __FILE__)).each do |input|
    it "hashes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.multi_hash(data, {digest: "blake2b-32", encode: "base32"}).first).to eq expected
    end
  end
  # multi_hash: blake2b-64, b58
  Dir.glob(File.expand_path("../input/basic/*_blake2b-64_b58_hash.doc", __FILE__)).each do |input|
    it "hashes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.multi_hash(data, {digest: "blake2b-64"}).first).to eq expected
    end
  end

  # intermediate BLAKE2b digest sizes (17-23 bytes) ---------------------------
  # Needed so a did:oyd fits into the 50 character URL limit of the EU Digital
  # Product Passport registry: sha2-256 yields a 55 character identifier,
  # blake2b-16 is only 128 bit and therefore too weak for a 30 year lifetime.
  BLAKE2B_EXTRA_SIZES = (17..23).to_a

  # Backwards compatibility: recorded before the intermediate sizes were added.
  # multi_hash must stay byte-identical for every digest that existed before,
  # otherwise DIDs already in the wild stop resolving.
  legacy_hashes = JSON.parse(File.read(File.expand_path("../fixtures/multi_hash_legacy.json", __FILE__)))
  legacy_hashes.group_by { |e| [e["digest"], e["encode"]] }.each do |(digest, encode), entries|
    it "keeps multi_hash byte-identical for #{digest} in #{encode}" do
      entries.each do |entry|
        message = [entry["message"]].pack("H*")
        expect(Oydid.multi_hash(message, {digest: digest, encode: encode}).first).to eq entry["expected"]
      end
    end
    it "keeps get_digest working for #{digest} in #{encode}" do
      entries.each do |entry|
        expect(Oydid.get_digest(entry["expected"]).first).to eq entry["name"]
      end
    end
  end

  BLAKE2B_EXTRA_SIZES.each do |size|
    digest = "blake2b-#{size}"

    it "advertises #{digest} as supported" do
      expect(Oydid::SUPPORTED_DIGESTS).to include digest
    end

    it "round-trips #{digest} through multi_hash and get_digest" do
      hash = Oydid.multi_hash('{"a":1}', {digest: digest, encode: "base58btc"}).first
      expect(hash).not_to be_nil
      expect(Oydid.get_digest(hash).first).to eq digest
      # the raw digest really has the requested size
      decoded, _ = Oydid.multi_decode(hash)
      expect(decoded.bytesize).to eq size + 2
      expect(decoded[1].ord).to eq size
    end

    it "encodes #{digest} in every supported encoding" do
      Oydid::SUPPORTED_ENCODINGS.each do |encoding|
        hash = Oydid.multi_hash("payload", {digest: digest, encode: encoding}).first
        expect(hash).not_to be_nil
        expect(Oydid.get_digest(hash).first).to eq digest
      end
    end
  end

  # base58btc length varies with the leading byte, so pin the maximum over a
  # few hundred random inputs rather than a single sample
  {17 => 27, 18 => 28, 19 => 29, 20 => 31, 21 => 32, 22 => 34, 23 => 35}.each do |size, expected_length|
    it "produces a base58btc identifier of at most #{expected_length} characters for blake2b-#{size}" do
      lengths = 500.times.map do |i|
        Oydid.multi_hash(SecureRandom.hex(24) + i.to_s, {digest: "blake2b-#{size}", encode: "base58btc"}).first.length
      end
      expect(lengths.max).to eq expected_length
      expect("did:oyd:".length + lengths.max).to eq expected_length + 8
    end
  end

  it "assigns the acceptance size for the DPP use case" do
    identifier = Oydid.multi_hash(Oydid.canonical({"a" => 1}), {digest: "blake2b-18", encode: "base58btc"}).first
    expect(identifier.length).to eq 28
    expect(("did:oyd:" + identifier).length).to eq 36
  end

  it "assigns collision-free single byte codes to all supported digests" do
    codes = Oydid::SUPPORTED_DIGESTS.map do |digest|
      hash = Oydid.multi_hash("collision check", {digest: digest, encode: "base58btc"}).first
      Oydid.multi_decode(hash).first[0].ord
    end
    expect(codes.length).to eq Oydid::SUPPORTED_DIGESTS.length
    expect(codes.uniq.length).to eq codes.length
  end

  it "keeps the new codes out of the range used by the pre-existing digests" do
    # 0x02/0x04/0x08 are blake2b-16/-32/-64, 0x12-0x17 are the SHA digests
    expect(Oydid::BLAKE2B_EXTRA_CODES.values.sort).to eq (0x0B..0x11).to_a
    expect(Oydid::BLAKE2B_EXTRA_CODES.keys.sort).to eq BLAKE2B_EXTRA_SIZES
    expect(Oydid::BLAKE2B_EXTRA_CODES.values & [0x02, 0x04, 0x08, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]).to be_empty
  end

  it "keeps the defaults unchanged" do
    expect(Oydid::DEFAULT_DIGEST).to eq "sha2-256"
    expect(Oydid::LOG_HASH_OPTIONS).to eq({:digest => "sha2-256", :encode => "base58btc"})
  end

  BLAKE2B_EXTRA_SIZES.each do |size|
    it "creates and reads a DID with blake2b-#{size}" do
      Dir.mktmpdir do |dir|
        Dir.chdir(dir) do
          result, msg = Oydid.create({"hello" => "dpp"}, {
            digest: "blake2b-#{size}", encode: "base58btc",
            doc_location: "local", location: "local",
            return_secrets: true, key_type: "ed25519", silent: true})
          expect(msg).to eq ""
          expect(result).not_to be_nil
          did = result["did"]
          identifier = did.delete_prefix("did:oyd:").split(Oydid::LOCATION_PREFIX).first
          expect(Oydid.get_digest(identifier).first).to eq "blake2b-#{size}"

          read_result, read_msg = Oydid.read(did, {doc_location: "local", log_location: "local", silent: true})
          expect(read_msg).to eq ""
          expect(read_result).not_to be_nil
          expect(read_result["doc"]["doc"]).to eq({"hello" => "dpp"})
        end
      end
    end
  end

  it "does not shadow sha1, which shares code 0x11 with blake2b-23" do
    # 0x11 is unused among the digests oydid produces, but the multicodec
    # registry maps it to sha1. The length byte keeps the two apart: sha1 is
    # always 20 bytes, blake2b-23 always 23.
    sha1_multihash = Oydid.multi_encode([0x11, 20, Digest::SHA1.digest("test")].pack("CCa20"),
                                        {encode: "base58btc"}).first
    expect(Oydid.get_digest(sha1_multihash).first).to eq "sha1"
    expect(Oydid.get_digest(Oydid.multi_hash("test", {digest: "blake2b-23"}).first).first).to eq "blake2b-23"
  end

  it "still rejects an unsupported digest" do
    expect(Oydid.multi_hash("data", {digest: "blake2b-24"}).last).to eq "unsupported digest: 'blake2b-24'"
  end

  Dir.glob(File.expand_path("../input/basic/*.json", __FILE__)).each do |input|
    it "converts #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = JSON.parse(File.read(input))
      expect(Oydid.canonical(data)).to eq expected
    end
  end
  it "converts strings" do
    expected = "\"asdf\""
    data = "asdf"
    expect(Oydid.canonical(data)).to eq expected
  end

  # key management
  Dir.glob(File.expand_path("../input/basic/*_key.doc", __FILE__)).each do |input|
    it "generates #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      # signature is (input, method, options) - passing options as the 2nd
      # argument made this resolve the codec {} and always return nil
      expect(Oydid.generate_private_key(data, "ed25519-priv", {}).first).to eq expected
    end
  end
  it "handles unknown key codec" do
    expected = "unknown key codec"
    expect(Oydid.generate_private_key("", "asdf", {}).last).to eq expected
  end
  it "handles unsupported key codec" do
    expected = "unsupported key codec"
    expect(Oydid.generate_private_key("", "p256-pub", {}).last).to eq expected
  end
  it "handles random key generation" do
    expected_length = 48
    expect(Oydid.generate_private_key("", "ed25519-priv", {}).first.length).to eq expected_length
  end
  Dir.glob(File.expand_path("../input/basic/*_privkey.doc", __FILE__)).each do |input|
    it "public key from private key #{input.split('/').last}" do
      expected = JSON.parse(File.read(input.sub('input', 'output')))
      data = File.read(input)
      expect(Oydid.public_key(data, {})).to eq expected
    end
  end
  Dir.glob(File.expand_path("../input/basic/*_sign.doc", __FILE__)).each do |input|
    it "signing #{input.split('/').last}" do
      expected = JSON.parse(File.read(input.sub('input', 'output')))
      data = JSON.parse(File.read(input))
      expect(Oydid.sign(data["message"], data["key"], {})).to eq expected
    end
  end
  Dir.glob(File.expand_path("../input/basic/*_verify.doc", __FILE__)).each do |input|
    it "verifying #{input.split('/').last}" do
      expected = JSON.parse(File.read(input.sub('input', 'output')))
      data = JSON.parse(File.read(input))
      expect(Oydid.verify(data["message"], data["signature"], data["public_key"])).to eq expected
    end
  end
  Dir.glob(File.expand_path("../input/basic/*_readkey.doc", __FILE__)).each do |input|
    it "reading private key from file #{input.split('/').last}" do
      expected = JSON.parse(File.read(input.sub('input', 'output')))
      data = File.read(input)
      expect(Oydid.read_private_key(data, {})).to eq expected
    end
  end

  # P-256 predefined / deterministic key handling
  it "derives a deterministic p256 private key from a seed/password" do
    key1, _ = Oydid.generate_private_key("my-fixed-seed", "p256-priv", {key_type: "p256"})
    key2, _ = Oydid.generate_private_key("my-fixed-seed", "p256-priv", {key_type: "p256"})
    expect(key1).not_to be_nil
    expect(key1).to eq key2
    expect(Oydid.get_keytype(key1)).to eq "p256-priv"
  end
  it "derives different p256 keys for different seeds" do
    key1, _ = Oydid.generate_private_key("seed-a", "p256-priv", {})
    key2, _ = Oydid.generate_private_key("seed-b", "p256-priv", {})
    expect(key1).not_to eq key2
  end
  it "produces a usable p256 keypair from a derived key (sign/verify roundtrip)" do
    privkey, _ = Oydid.generate_private_key("roundtrip-seed", "p256-priv", {})
    pubkey, _  = Oydid.public_key(privkey, {})
    expect(pubkey).not_to be_nil
    message = "hello oydid"
    signature, _ = Oydid.sign(message, privkey, {})
    expect(signature).not_to be_nil
    expect(Oydid.verify(message, signature, pubkey).first).to eq true
  end
  it "preserves a predefined base64-encoded p256 private key" do
    ec = OpenSSL::PKey::EC.generate('prime256v1')
    b64 = Base64.encode64(ec.to_pem)
    encoded, _ = Oydid.generate_private_key(b64, "p256-priv", {})
    expect(encoded).not_to be_nil
    decoded = Oydid.decode_private_key(encoded).first
    expect(decoded.private_key.to_s(2)).to eq ec.private_key.to_s(2)
  end
  it "getPrivateKey honors key_type for password-derived keys" do
    p256_key, _ = Oydid.getPrivateKey(nil, "shared-pwd", nil, nil, {key_type: "p256"})
    ed_key, _   = Oydid.getPrivateKey(nil, "shared-pwd", nil, nil, {key_type: "ed25519"})
    expect(Oydid.get_keytype(p256_key)).to eq "p256-priv"
    expect(Oydid.get_keytype(ed_key)).to eq "ed25519-priv"
  end
  it "imports a hex-encoded p256 private key (matching the JWK conversion)" do
    hex = "96fe0f41947d645c7a1858c48c7a0560e7e5bd3d45125b57a611a3a9a103626b"
    jwk = {kty: "EC", crv: "P-256",
           d: "lv4PQZR9ZFx6GFjEjHoFYOflvT1FEltXphGjqaEDYms",
           x: "vK0MQ6yFnQVS2VtjkVYHP5wcT7GqlJDzY5qM8KKqrao",
           y: "R3AQWDZ-AAdwQ3sys1UwhIA5MX2WNnmSerQRKDKxg48"}
    from_hex, _ = Oydid.private_key_from_hex(hex, {key_type: "p256"})
    from_jwk, _ = Oydid.private_key_from_jwk(jwk.to_json, {})
    expect(from_hex).not_to be_nil
    expect(Oydid.get_keytype(from_hex)).to eq "p256-priv"
    expect(from_hex).to eq from_jwk
  end
  it "rejects malformed hex private keys" do
    expect(Oydid.private_key_from_hex("xyz", {key_type: "p256"}).first).to be_nil
    expect(Oydid.private_key_from_hex("96fe", {key_type: "p256"}).first).to be_nil
    expect(Oydid.private_key_from_hex("00" * 32, {key_type: "p256"}).first).to be_nil
  end
  it "round-trips a p256 private key hex -> mb -> hex" do
    hex = "96fe0f41947d645c7a1858c48c7a0560e7e5bd3d45125b57a611a3a9a103626b"
    mb, _  = Oydid.private_key_from_hex(hex, {key_type: "p256"})
    back, _ = Oydid.key_to_hex(mb, {})
    expect(back).to eq hex
  end
  it "decodes a p256 public key from mb to uncompressed hex" do
    privkey, _ = Oydid.private_key_from_hex(
      "96fe0f41947d645c7a1858c48c7a0560e7e5bd3d45125b57a611a3a9a103626b",
      {key_type: "p256"})
    pub_mb, _ = Oydid.public_key(privkey, {})
    pub_hex, _ = Oydid.key_to_hex(pub_mb, {})
    expect(pub_hex).to eq "04bcad0c43ac859d0552d95b639156073f9c1c4fb1aa9490f3639a8cf0a2aaadaa47701058367e000770437b32b35530848039317d963679927ab4112832b1838f"
  end
  it "rejects an invalid multibase key in key_to_hex" do
    expect(Oydid.key_to_hex("not-a-key", {}).first).to be_nil
  end

  # hex2mb: public keys (--public)
  it "encodes an ed25519 public key from hex identically to public_key()" do
    privkey, _ = Oydid.private_key_from_hex("aa" * 32, {key_type: "ed25519"})
    pub_mb, _  = Oydid.public_key(privkey, {})
    pub_hex, _ = Oydid.key_to_hex(pub_mb, {})
    from_hex, msg = Oydid.public_key_from_hex(pub_hex, {key_type: "ed25519"})
    expect(msg).to eq ""
    expect(from_hex).to eq pub_mb
    expect(Oydid.get_keytype(from_hex)).to eq "ed25519-pub"
  end
  it "encodes a p256 public key from hex identically to public_key()" do
    privkey, _ = Oydid.private_key_from_hex(
      "96fe0f41947d645c7a1858c48c7a0560e7e5bd3d45125b57a611a3a9a103626b",
      {key_type: "p256"})
    pub_mb, _  = Oydid.public_key(privkey, {})
    pub_hex, _ = Oydid.key_to_hex(pub_mb, {})
    from_hex, msg = Oydid.public_key_from_hex(pub_hex, {key_type: "p256"})
    expect(msg).to eq ""
    expect(from_hex).to eq pub_mb
    expect(Oydid.get_keytype(from_hex)).to eq "p256-pub"
  end
  it "round-trips a public key hex -> mb -> hex" do
    hex = "e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58"
    mb, _   = Oydid.public_key_from_hex(hex, {key_type: "ed25519"})
    back, _ = Oydid.key_to_hex(mb, {})
    expect(back).to eq hex
  end
  it "accepts a compressed p256 public key" do
    hex = "03bcad0c43ac859d0552d95b639156073f9c1c4fb1aa9490f3639a8cf0a2aaadaa"
    mb, msg = Oydid.public_key_from_hex(hex, {key_type: "p256"})
    expect(msg).to eq ""
    expect(Oydid.get_keytype(mb)).to eq "p256-pub"
  end
  it "rejects a p256 public key that is not a point on the curve" do
    mb, msg = Oydid.public_key_from_hex("04" + "11" * 64, {key_type: "p256"})
    expect(mb).to be_nil
    expect(msg).to match(/not a valid point/)
  end
  it "rejects malformed public key hex" do
    expect(Oydid.public_key_from_hex("xyz", {key_type: "ed25519"}).first).to be_nil
    expect(Oydid.public_key_from_hex("aa" * 31, {key_type: "ed25519"}).first).to be_nil
    expect(Oydid.public_key_from_hex("aa" * 32, {key_type: "p256"}).first).to be_nil
    expect(Oydid.public_key_from_hex("aa" * 32, {key_type: "secp256k1"}).first).to be_nil
  end
  it "defaults to ed25519 when no key type is given for a public key" do
    hex = "e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58"
    expect(Oydid.get_keytype(Oydid.public_key_from_hex(hex, {}).first)).to eq "ed25519-pub"
  end

  # hex2mb: raw data (--raw)
  it "encodes raw hex data to multibase without a multicodec prefix" do
    mb, msg = Oydid.hex_to_multibase("deadbeef", {})
    expect(msg).to eq ""
    expect(Oydid.multi_decode(mb).first.unpack1("H*")).to eq "deadbeef"
    # no multicodec prefix -> deliberately not readable back as a key
    expect(Oydid.key_to_hex(mb, {}).first).to be_nil
  end
  it "preserves leading zero bytes in raw hex data" do
    mb, _ = Oydid.hex_to_multibase("00deadbeef", {})
    expect(Oydid.multi_decode(mb).first.unpack1("H*")).to eq "00deadbeef"
  end
  it "accepts a 0x prefix and surrounding whitespace in raw hex data" do
    expect(Oydid.hex_to_multibase(" 0xdeadbeef\n", {}).first).to \
      eq Oydid.hex_to_multibase("deadbeef", {}).first
  end
  it "rejects all-zero raw hex data with a specific message" do
    mb, msg = Oydid.hex_to_multibase("00" * 4, {})
    expect(mb).to be_nil
    expect(msg).to match(/all-zero/)
  end
  it "rejects malformed raw hex data" do
    expect(Oydid.hex_to_multibase("xyz", {}).first).to be_nil
    expect(Oydid.hex_to_multibase("abc", {}).first).to be_nil
    expect(Oydid.hex_to_multibase("", {}).first).to be_nil
  end

  # storage functions
  it "should create 'filename' and put/read 'text'" do
    @buffer = StringIO.new()
    @filename = "filename"
    @content = "text"
    allow(File).to receive(:open).with(@filename,'w').and_yield( @buffer )
    Oydid.write_private_storage(@content, @filename)
    expect(@buffer.string).to eq(@content)
    allow(File).to receive(:open).with(@filename, 'r').and_yield( StringIO.new(@content) )
    expect(Oydid.read_private_storage(@filename)).to eq(@content)
  end

  # document functions
  Dir.glob(File.expand_path("../input/basic/*_get_location.doc", __FILE__)).each do |input|
    it "get location from #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.get_location(data)).to eq expected
    end
  end
  Dir.glob(File.expand_path("../input/basic/*_retrieve_document.doc", __FILE__)).each do |input|
    it "get location from #{input.split('/').last}" do
      expected = JSON.parse(File.read(input.sub('input', 'output')))
      data = JSON.parse(File.read(input))
      expect(Oydid.retrieve_document(data["doc_hash"], data["doc_file"], data["doc_location"], data["options"])).to eq expected
    end
  end

  # log functions
  Dir.glob(File.expand_path("../input/log/*_addhash.doc", __FILE__)).each do |input|
    it "adding hash value to log entry #{input.split('/').last}" do
      expected = JSON.parse(File.read(input.sub('input', 'output')))
      data = JSON.parse(File.read(input))
      expect(Oydid.add_hash(data)).to eq expected
    end
  end
  Dir.glob(File.expand_path("../input/log/*_match_log.doc", __FILE__)).each do |input|
    it "check log entry match #{input.split('/').last}" do
      expected = JSON.parse(File.read(input.sub('input', 'output')))
      data = JSON.parse(File.read(input))
      expect(Oydid.match_log_did?(data, data["didoc"])).to eq expected
    end
  end
  Dir.glob(File.expand_path("../input/log/*_retrieve_log.doc", __FILE__)).each do |input|
    it "retrieve log #{input.split('/').last}" do
      expected = JSON.parse(File.read(input.sub('input', 'output')))
      data = JSON.parse(File.read(input))
      expect(Oydid.retrieve_log(data["did_hash"], data["log_file"], data["log_location"], data["options"])).to eq expected
    end
  end
  Dir.glob(File.expand_path("../input/log/*_dag_did.doc", __FILE__)).each do |input|
    it "creates DAG from log #{input.split('/').last}" do
      expected = JSON.parse(File.read(input.sub('input', 'output')))
      data = JSON.parse(File.read(input))
      expect(Oydid.dag_did(data["log"], data["options"]).last(3)).to eq expected
    end
  end
  Dir.glob(File.expand_path("../input/log/*_dag2array.doc", __FILE__)).each do |input|
    it "process dag2array for #{input.split('/').last}" do
      expected = JSON.parse(File.read(input.sub('input', 'output')))
      data = JSON.parse(File.read(input))
      dag, create_index, terminate_index, msg = Oydid.dag_did(data["log"], data["options"])
      expect(Oydid.dag2array(dag, data["log"], create_index, [], data["options"])).to eq expected
    end
  end
  # Dir.glob(File.expand_path("../input/log/*_dag_update.doc", __FILE__)).each do |input|
  #   it "process DAG for #{input.split('/').last}" do
  #     expected = JSON.parse(File.read(input.sub('input', 'output')))
  #     data = JSON.parse(File.read(input))
  #     expect(Oydid.dag_update(data["currentDID"], data["options"])).to eq expected
  #   end
  # end

  # main functionds
  Dir.glob(File.expand_path("../input/main/*_read.doc", __FILE__)).each do |input|
    it "execute read for #{input.split('/').last}" do
      expected = JSON.parse(File.read(input.sub('input', 'output')))
      data = JSON.parse(File.read(input))
      expect(Oydid.read(data["did"], data["options"])).to eq expected
    end
  end

  # W3C conversion of verification relationships carried in the payload
  describe "verification relationships in the payload" do
    let(:did) { "did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh" }
    let(:keys) do
      "z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S:" \
      "z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK"
    end
    let(:attestation) do
      { "id" => "#key-attest",
        "type" => "Ed25519VerificationKey2020",
        "publicKeyMultibase" => "z6Mkg49NtQR2LyYRDCQFK4w1VVHqhypZSSRo7HsyuN7SV7v5" }
    end

    def convert(payload)
      Oydid.w3c({ "did" => did, "doc" => { "doc" => payload, "key" => keys } }, {})
    end

    it "prefixes the DID onto a key named by fragment" do
      wd = convert({ "authentication" => ["#key-doc"] })
      expect(wd["authentication"]).to eq ["#{did}#key-doc"]
    end

    it "prefixes the DID onto an embedded verification method" do
      wd = convert({ "assertionMethod" => [attestation] })
      expect(wd["assertionMethod"].first["id"]).to eq "#{did}#key-attest"
    end

    # a client cannot supply the controller: the DID is the hash of the
    # document that would contain it
    it "fills in the controller of an embedded verification method" do
      wd = convert({ "assertionMethod" => [attestation] })
      expect(wd["assertionMethod"].first["controller"]).to eq did
    end

    it "keeps a controller the payload already carries" do
      own = attestation.merge("controller" => "did:oyd:zSomeoneElse")
      wd = convert({ "assertionMethod" => [own] })
      expect(wd["assertionMethod"].first["controller"]).to eq "did:oyd:zSomeoneElse"
    end

    # regression: a payload carrying a service took a different branch and was
    # merged verbatim, leaving fragments unresolved
    it "handles relationships next to a service entry" do
      wd = convert({ "assertionMethod" => [attestation],
                     "service" => [{ "id" => "#payload", "type" => "Custom" }] })
      expect(wd["assertionMethod"].first["id"]).to eq "#{did}#key-attest"
      expect(wd["assertionMethod"].first["controller"]).to eq did
      expect(wd["service"]).to be_an(Array)
    end

    it "accepts a single embedded method that is not wrapped in an array" do
      wd = convert({ "assertionMethod" => attestation })
      expect(wd["assertionMethod"].first["id"]).to eq "#{did}#key-attest"
    end
  end

end
