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

  # regression: the payload of a DID Document is arbitrary JSON, not
  # necessarily an object. A revoked DID whose payload is an Array used to
  # raise NoMethodError in the alsoKnownAs lookup - the repository then
  # answered 500 with an empty body and the resolver reported "not found"
  # instead of "deactivated".
  describe "dag_update with a non-object DID Document payload" do
    def revoked_state(payload)
      { "did" => "did:oyd:zQmPyjnkL52gQxBBhPuCFkf167MzpCKquqbu5Qt5ia2JGTr",
        "doc" => { "doc" => payload, "key" => "", "log" => "" },
        "log" => [{ "ts" => 1647732475, "op" => 1, "doc" => "zQmcVLwEtzU8By7TTeRFGvVUKm7HhZS6GgRTDFt51QNnans",
                    "sig" => "", "previous" => [] }] }
    end

    it "does not raise for an Array payload" do
      expect {
        Oydid.dag_update(revoked_state([5]), { followAlsoKnownAs: true })
      }.not_to raise_error
    end

    it "does not raise for a scalar payload" do
      expect {
        Oydid.dag_update(revoked_state("plain"), { followAlsoKnownAs: true })
      }.not_to raise_error
    end

    it "accepts alsoKnownAs written as a set" do
      state = revoked_state({ "alsoKnownAs" => ["did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh"] })
      expect {
        Oydid.dag_update(state, { followAlsoKnownAs: true })
      }.not_to raise_error
    end
  end

  # regression: a log entry with a missing "previous" field (e.g. junk op=5
  # entries POSTed to the unauthenticated /log endpoint) made dag_did call
  # nil.each - the repository then answered 500 with an empty body for every
  # request to that DID. previous is optional; a missing one means no
  # back-reference, exactly like an empty array.
  describe "dag_did with a log entry missing 'previous'" do
    let(:log) do
      [ { "ts" => 0, "op" => 5, "doc" => "doc:123", "sig" => "z6M234" }, # no "previous"
        { "ts" => 1, "op" => 2, "doc" => "zQmSVzALxVDs2Tqf5gh9XDWSL4L57YLi8H1XpvpizQPd79c", "sig" => "z", "previous" => [] },
        { "ts" => 1, "op" => 0, "doc" => "zQmXRVzdjMnTz1WQVkVdJU1ZF9DPjcK5LM2GynpGzxbNAz6", "sig" => "z", "previous" => [] } ]
    end

    it "does not raise on a missing previous field" do
      expect { Oydid.dag_did(log, { silent: true }) }.not_to raise_error
    end

    it "still resolves the DAG and finds the single CREATE entry" do
      dag, create_index, _terminate_index, msg = Oydid.dag_did(log, { silent: true })
      expect(msg).to eq ""
      expect(dag).not_to be_nil
      expect(create_index).to eq 1
    end
  end

  # SECURITY regression (fail-closed on delegation): a DELEGATE entry (op=5) is
  # collected from the raw log with no authentication. Honouring it at resolution
  # let anyone able to write a log entry take over a revoked DID by injecting a
  # DELEGATE plus a self-signed UPDATE. Resolution must authorise an UPDATE only
  # by the superseded version's own document key - and must keep resolving a
  # legitimate owner-signed update.
  describe "DELEGATE keys are not honoured at resolution" do
    HOPTS = { digest: "sha2-256", encode: "base58btc" }
    class MemStore
      def initialize(h); @h = h; end
      def get(k); @h[k]; end
    end
    def h(e);   Oydid.multi_hash(Oydid.canonical(e.slice("ts","op","doc","sig","previous")), HOPTS).first; end
    def sub(e); Oydid.multi_hash(Oydid.canonical(e.slice("ts","op","doc","sig")), HOPTS).first; end

    # generate_base builds the CREATE/TERMINATE/REVOKE records and the keys
    # without the network round-trip that Oydid.create makes via w3c (which
    # WebMock blocks in the test env). doc_location "local" keeps the log
    # reference free of an @location suffix.
    def build_revoked_victim
      dd, dk, dl, = Oydid.generate_base({ "purpose" => "victim" }, nil, "create",
                                        { key_type: "ed25519", doc_location: "local" })
      create = dl[:l1]
      term1  = dl[:l2]
      revoke = dl[:r1].merge("previous" => [h(create), h(term1)])
      { vdid: dd[:did].delete_prefix("did:oyd:"), vdoc: dd[:didDocument], vpriv: dk[:privateKey],
        create: create, term1: term1, revoke: revoke }
    end

    def build_v2
      np    = { "service" => [{ "id" => "#x", "serviceEndpoint" => "https://new.example" }] }
      apriv = Oydid.generate_private_key("", "ed25519-priv", {}).first
      apub  = Oydid.public_key(apriv, {}).first
      arpub = Oydid.public_key(Oydid.generate_private_key("", "ed25519-priv", {}).first, {}).first
      nkey  = "#{apub}:#{arpub}"
      r2    = { "ts" => 3, "op" => 1, "sig" => "z",
                "doc" => Oydid.multi_hash(Oydid.canonical({ "doc" => np, "key" => nkey }.to_json), HOPTS).first }
      term2 = { "ts" => 3, "op" => 0, "doc" => sub(r2), "sig" => Oydid.sign(sub(r2), apriv, HOPTS).first, "previous" => [] }
      ndoc  = { "doc" => np, "key" => nkey, "log" => h(term2) }
      { np: np, apriv: apriv, apub: apub, term2: term2, ndoc: ndoc,
        ndid: Oydid.multi_hash(Oydid.canonical(ndoc.to_json), HOPTS).first }
    end

    def resolve(vic, v2, log)
      store = MemStore.new(vic[:vdid] => { "doc" => vic[:vdoc], "log" => log },
                           v2[:ndid]  => { "doc" => v2[:ndoc],  "log" => log })
      r, = Oydid.read("did:oyd:#{vic[:vdid]}",
                      { local_doc: vic[:vdoc], local_log: log, local_store: store, silent: true })
      [r["error"].to_i, r.dig("doc", "doc")]
    end

    it "rejects a takeover via an injected DELEGATE + self-signed UPDATE" do
      vic = build_revoked_victim; v2 = build_v2
      deleg = { "ts" => 2, "op" => 5, "doc" => "doc:#{v2[:apub]}", "sig" => "", "previous" => [h(vic[:term1])] }
      upd   = { "ts" => 3, "op" => 3, "doc" => v2[:ndid],
                "sig" => Oydid.sign(v2[:ndid], v2[:apriv], HOPTS).first, "previous" => [h(vic[:revoke])] }
      _err, doc = resolve(vic, v2, [vic[:create], vic[:term1], vic[:revoke], deleg, upd, v2[:term2]])
      expect(doc).not_to eq v2[:np]
    end

    it "still resolves a legitimate owner-signed UPDATE" do
      vic = build_revoked_victim; v2 = build_v2
      upd = { "ts" => 3, "op" => 3, "doc" => v2[:ndid],
              "sig" => Oydid.sign(v2[:ndid], vic[:vpriv], HOPTS).first, "previous" => [h(vic[:revoke])] }
      err, doc = resolve(vic, v2, [vic[:create], vic[:term1], vic[:revoke], upd, v2[:term2]])
      expect(err).to eq 0
      expect(doc).to eq v2[:np]
    end
  end

  # SECURITY regression: the append endpoint is unauthenticated, so a byte-identical
  # log entry can be replayed with no signing key. A duplicated CREATE trips dag_did's
  # "wrong number of CREATE entries" and a duplicated tangling TERMINATE its terminate
  # count, making the DID unresolvable. dedup_log collapses byte-identical replays
  # (keep-first) at ingestion; genuinely distinct fork entries survive and still fail
  # closed as ambiguous.
  describe "dedup_log collapses byte-identical replayed entries" do
    let(:create_e) { { "ts" => 1, "op" => 2, "doc" => "zCreate", "sig" => "z", "previous" => [] } }
    let(:term_e)   { { "ts" => 1, "op" => 0, "doc" => "zTerm",   "sig" => "z", "previous" => [] } }

    it "removes a byte-identical duplicate, keeping the first" do
      deduped = Oydid.dedup_log([create_e, term_e, create_e.dup])
      expect(deduped.length).to eq 2
      expect(deduped.count { |e| e["op"] == 2 }).to eq 1
    end

    it "lets a de-duplicated log resolve where the raw one fails" do
      logs = [create_e, term_e, create_e.dup]
      expect(Oydid.dag_did(logs, { silent: true }).last).to match(/wrong number of CREATE/)
      dag, create_index, _t, msg = Oydid.dag_did(Oydid.dedup_log(logs), { silent: true })
      expect(msg).to eq ""
      expect(dag).not_to be_nil
      expect(create_index).to eq 0
    end

    it "keeps genuinely distinct entries (a real fork is not collapsed)" do
      fork = create_e.merge("doc" => "zCreate2")
      expect(Oydid.dedup_log([create_e, fork, term_e]).length).to eq 3
    end
  end

  # a broken repository (5xx) has to stay distinguishable from a DID that is
  # not stored there - otherwise the caller reports "not found" and thereby
  # claims the identifier never existed
  describe "failure messages for non-200 responses" do
    it "marks a 5xx as an upstream error" do
      reply = double(code: 500, parsed_response: "")
      msg = Oydid.http_error_message(reply, "https://oydid.ownyourdata.eu/doc/zQmXY")
      expect(Oydid.upstream_error?(msg)).to be true
      expect(msg).to include("500")
    end

    it "passes the repository's own error through" do
      reply = double(code: 410, parsed_response: { "error" => "revoked" })
      msg = Oydid.http_error_message(reply, "https://oydid.ownyourdata.eu/doc/zQmXY")
      expect(msg).to eq "revoked"
      expect(Oydid.upstream_error?(msg)).to be false
    end

    it "does not mark a 4xx without an error field as upstream error" do
      reply = double(code: 404, parsed_response: nil)
      msg = Oydid.http_error_message(reply, "https://oydid.ownyourdata.eu/doc/zQmXY")
      expect(msg).to start_with("invalid response from")
      expect(Oydid.upstream_error?(msg)).to be false
    end
  end

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

  # Identifiers of the published versions of a DID. Every update mints a new
  # one, so a resolver has to be able to say which is current and which are
  # earlier - didDocumentMetadata canonicalId and equivalentId.
  describe "version_ids" do
    let(:first_did)  { "zQmSE1hzumtZ7AoK1qhHf4t5kiKsujMsJSHqoXtWrdd7K7W" }
    let(:second_did) { "zQmfEb3KgYZjZUPLTHPmFPdcV6peF5itB5NmJ9N6gaxxE8K" }

    it "reports a freshly created DID as canonical without equivalents" do
      canonical, equivalent = Oydid.version_ids(
        "did" => "did:oyd:" + first_did,
        "log" => [{ "op" => 2, "doc" => first_did },
                  { "op" => 0, "doc" => "terminate" }])
      expect(canonical).to eq "did:oyd:" + first_did
      expect(equivalent).to eq []
    end

    it "names the current version canonical and the previous one equivalent" do
      canonical, equivalent = Oydid.version_ids(
        "did" => "did:oyd:" + second_did,
        "log" => [{ "op" => 1, "doc" => "revoke" },
                  { "op" => 2, "doc" => first_did },
                  { "op" => 3, "doc" => second_did },
                  { "op" => 0, "doc" => "terminate" }])
      expect(canonical).to eq "did:oyd:" + second_did
      expect(equivalent).to eq ["did:oyd:" + first_did]
    end

    it "keeps every earlier version, oldest first" do
      canonical, equivalent = Oydid.version_ids(
        "did" => "did:oyd:zC",
        "log" => [{ "op" => 2, "doc" => "zA" },
                  { "op" => 3, "doc" => "zB" },
                  { "op" => 3, "doc" => "zC" }])
      expect(canonical).to eq "did:oyd:zC"
      expect(equivalent).to eq ["did:oyd:zA", "did:oyd:zB"]
    end

    it "adds the method prefix when the resolved DID carries none" do
      canonical, = Oydid.version_ids("did" => second_did, "log" => [])
      expect(canonical).to eq "did:oyd:" + second_did
    end

    # The identifier a relying party was handed is the one it asked for, which
    # after an update is an earlier version than the document being served. Every
    # other version is then equivalent to it - not just the current one. This is
    # the case the HTTP request specs could not reach before update_did existed.
    it "lists every other version when an earlier one was requested" do
      canonical, equivalent = Oydid.version_ids(
        "did" => "did:oyd:zC",
        "did_requested" => "did:oyd:zA",
        "log" => [{ "op" => 2, "doc" => "zA" },
                  { "op" => 3, "doc" => "zB" },
                  { "op" => 3, "doc" => "zC" }])
      expect(canonical).to eq "did:oyd:zC"
      expect(equivalent).to eq ["did:oyd:zB", "did:oyd:zC"]
    end

    it "lists the versions on both sides when a middle one was requested" do
      canonical, equivalent = Oydid.version_ids(
        "did" => "did:oyd:zC",
        "did_requested" => "did:oyd:zB",
        "log" => [{ "op" => 2, "doc" => "zA" },
                  { "op" => 3, "doc" => "zB" },
                  { "op" => 3, "doc" => "zC" }])
      expect(canonical).to eq "did:oyd:zC"
      expect(equivalent).to eq ["did:oyd:zA", "did:oyd:zC"]
    end

    # canonicalId and equivalentId state identity, and "@<location>" states where
    # a document is hosted. The same document can be mirrored at any number of
    # locations, so the set of location-bound variants is open and equivalentId
    # could not state it correctly - both are therefore location-free.
    it "strips the location suffix from canonicalId and equivalentId" do
      canonical, equivalent = Oydid.version_ids(
        "did" => "did:oyd:" + second_did + "@https://example.org",
        "did_requested" => "did:oyd:" + second_did,
        "log" => [{ "op" => 2, "doc" => first_did + "@https://example.org" },
                  { "op" => 3, "doc" => second_did + "@https://example.org" }])
      expect(canonical).to eq "did:oyd:" + second_did
      expect(equivalent).to eq ["did:oyd:" + first_did]
    end

    # A location-bound DID that was asked for stays the id of the document - DID
    # Core: "the value of the id property in the retrieved DID document must
    # always match the DID being resolved". Its location-free form is then a
    # genuinely different string for the same subject, so it belongs in
    # equivalentId alongside the earlier version.
    it "lists the location-free form of the current version when a location-bound DID was requested" do
      canonical, equivalent = Oydid.version_ids(
        "did" => "did:oyd:" + second_did + "@https://example.org",
        "did_requested" => "did:oyd:" + second_did + "@https://example.org",
        "log" => [{ "op" => 2, "doc" => first_did + "@https://example.org" },
                  { "op" => 3, "doc" => second_did + "@https://example.org" }])
      expect(canonical).to eq "did:oyd:" + second_did
      expect(equivalent).to eq ["did:oyd:" + first_did, "did:oyd:" + second_did]
    end

    # this used to list the DID as its own equivalent, in location-bound form,
    # and hand out that same string as canonicalId
    it "reports no equivalents for a never updated DID served from a location" do
      canonical, equivalent = Oydid.version_ids(
        "did" => "did:oyd:" + first_did + "@https://example.org",
        "did_requested" => "did:oyd:" + first_did,
        "log" => [{ "op" => 2, "doc" => first_did + "@https://example.org" },
                  { "op" => 0, "doc" => "terminate" }])
      expect(canonical).to eq "did:oyd:" + first_did
      expect(equivalent).to eq []
    end

    it "keeps the location suffix for the alsoKnownAs list" do
      canonical, equivalent = Oydid.version_ids(
        { "did" => "did:oyd:" + first_did + "@https://example.org",
          "did_requested" => "did:oyd:" + first_did,
          "log" => [{ "op" => 2, "doc" => first_did + "@https://example.org" }] },
        true)
      expect(canonical).to eq "did:oyd:" + first_did + "%40example.org"
      expect(equivalent).to eq ["did:oyd:" + first_did + "%40example.org"]
    end

    it "tolerates a missing log" do
      canonical, equivalent = Oydid.version_ids("did" => "did:oyd:" + second_did)
      expect(canonical).to eq "did:oyd:" + second_did
      expect(equivalent).to eq []
    end

    # w3c builds alsoKnownAs from the same list. The two used to be computed
    # separately in three places and drifted apart; this guards the merge.
    #
    # The canonical DID has to be one this suite stubs: w3c looks up delegation
    # keys for it, and WebMock::NetConnectNotAllowedError descends from Exception
    # rather than StandardError, so the inline `rescue []` around
    # getDelegatedPubKeysFromDID does not catch it. Only the canonical DID is
    # fetched - log entries are read, not resolved.
    it "agrees with the alsoKnownAs the DID document carries" do
      stubbed_did = "zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh"
      did_info = {
        "did" => "did:oyd:" + stubbed_did,
        "doc" => { "doc" => { "hello" => "world" },
                   "key" => "z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S:" \
                            "z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK" },
        "log" => [{ "op" => 2, "doc" => first_did },
                  { "op" => 3, "doc" => stubbed_did }]
      }
      wd = Oydid.w3c(Marshal.load(Marshal.dump(did_info)), {})
      expect(wd["alsoKnownAs"]).to eq ["did:oyd:" + first_did]
      expect(wd["alsoKnownAs"]).to eq Oydid.version_ids(did_info, true).last
    end

    # The two lists deliberately part ways on the location: identity statements
    # drop it, alsoKnownAs keeps it - otherwise the location would disappear from
    # the DID document altogether. Guards the live output for a never updated DID.
    it "keeps the location-bound variant in alsoKnownAs while canonicalId drops it" do
      stubbed_did = "zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh"
      did_info = {
        "did" => "did:oyd:" + stubbed_did + "@https://example.org",
        "did_requested" => "did:oyd:" + stubbed_did,
        "doc" => { "doc" => { "hello" => "world" },
                   "key" => "z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S:" \
                            "z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK" },
        "log" => [{ "op" => 2, "doc" => stubbed_did + "@https://example.org" }]
      }
      wd = Oydid.w3c(Marshal.load(Marshal.dump(did_info)), {})
      expect(wd["id"]).to eq "did:oyd:" + stubbed_did
      expect(wd["alsoKnownAs"]).to eq ["did:oyd:" + stubbed_did + "%40example.org"]
      canonical, equivalent = Oydid.version_ids(did_info)
      expect(canonical).to eq "did:oyd:" + stubbed_did
      expect(equivalent).to eq []
    end
  end

  # created / updated / versionId of the resolved version (DID Core 7.1.3).
  # Without `updated` a consumer cannot tell how old the document in its hands is.
  describe "version_metadata" do
    let(:first_did)  { "zQmSE1hzumtZ7AoK1qhHf4t5kiKsujMsJSHqoXtWrdd7K7W" }
    let(:second_did) { "zQmfEb3KgYZjZUPLTHPmFPdcV6peF5itB5NmJ9N6gaxxE8K" }

    # "The updated property is omitted if an Update operation has never been
    # performed on the DID document." - 7.1.3
    it "reports created and versionId, and omits updated, for a new DID" do
      meta = Oydid.version_metadata(
        "did" => "did:oyd:" + first_did + "@https://example.org",
        "log" => [{ "op" => 2, "ts" => 1641224940, "doc" => first_did + "@https://example.org" },
                  { "op" => 0, "ts" => 1641224940, "doc" => "terminate" }])
      expect(meta["created"]).to eq "2022-01-03T15:49:00Z"
      expect(meta["versionId"]).to eq first_did
      expect(meta).not_to have_key("updated")
    end

    it "reports the timestamp of the update that produced the resolved version" do
      meta = Oydid.version_metadata(
        "did" => "did:oyd:" + second_did,
        "log" => [{ "op" => 2, "ts" => 1641224940, "doc" => first_did },
                  { "op" => 3, "ts" => 1641225032, "doc" => second_did },
                  { "op" => 0, "ts" => 1641225032, "doc" => "terminate" }])
      expect(meta["created"]).to eq "2022-01-03T15:49:00Z"
      expect(meta["updated"]).to eq "2022-01-03T15:50:32Z"
      expect(meta["versionId"]).to eq second_did
    end

    # the entry is picked by the version it produced, not by its timestamp:
    # timestamps come from the client and two entries can share a second
    it "ignores updates that did not produce the resolved version" do
      meta = Oydid.version_metadata(
        "did" => "did:oyd:zB",
        "log" => [{ "op" => 2, "ts" => 1, "doc" => "zA" },
                  { "op" => 3, "ts" => 2, "doc" => "zB" },
                  { "op" => 3, "ts" => 3, "doc" => "zC" }])
      expect(meta["versionId"]).to eq "zB"
      expect(meta["updated"]).to eq "1970-01-01T00:00:02Z"
    end

    it "leaves out what the log cannot answer" do
      expect(Oydid.version_metadata("did" => "did:oyd:" + first_did))
        .to eq({ "versionId" => first_did })
      expect(Oydid.version_metadata("did" => "did:oyd:" + first_did,
                                    "log" => [{ "op" => 2, "doc" => first_did }]))
        .to eq({ "versionId" => first_did })
    end
  end

  # Which identifier a resolved DID document announces as its own. An update
  # mints a new did:oyd, but the identifier a relying party holds is the one it
  # asked for - that is the one the document has to carry.
  # The "key" field is positional: "<public document key>:<public revocation key>".
  # Reading it with .first/.last works only as long as it has exactly two slots -
  # the day a third one is added (e.g. a key agreement key), .last silently
  # returns the wrong key and the error only surfaces at revocation time.
  # Every read must therefore use an explicit index.
  describe "positional access to the key field" do
    repo_root = File.expand_path("../../..", __FILE__)
    sources = %w[
      ruby-gem/lib
      cli
      repository/app
      uni-registrar-driver-did-oyd/app
    ].map { |d| File.join(repo_root, d) }.select { |d| File.directory?(d) }

    ruby_files = sources.flat_map { |d| Dir.glob(File.join(d, "**", "*.rb")) }

    it "finds sources to scan" do
      skip "running outside the repository checkout" if ruby_files.empty?
      expect(ruby_files).not_to be_empty
    end

    it "never reads a split key field with .last" do
      skip "running outside the repository checkout" if ruby_files.empty?
      offenders = ruby_files.flat_map do |file|
        File.readlines(file).each_with_index.filter_map do |line, i|
          "#{file.sub(repo_root + "/", "")}:#{i + 1}" if line =~ /split\((["'])\:\1\)\.last/
        end
      end
      expect(offenders).to eq []
    end

    it "never reads a split key field with .first" do
      skip "running outside the repository checkout" if ruby_files.empty?
      offenders = ruby_files.flat_map do |file|
        File.readlines(file).each_with_index.filter_map do |line, i|
          next unless line =~ /split\((["'])\:\1\)\.first/
          # the DID identifier itself is also colon-separated and legitimately
          # read with .first - only the key field is at issue here
          "#{file.sub(repo_root + "/", "")}:#{i + 1}" if line.include?('"key"') || line.include?("'key'") || line =~ /_key(s)?\.split/
        end
      end
      expect(offenders).to eq []
    end
  end

  describe "document_id" do
    let(:first_did)  { "zQmSE1hzumtZ7AoK1qhHf4t5kiKsujMsJSHqoXtWrdd7K7W" }
    let(:second_did) { "zQmfEb3KgYZjZUPLTHPmFPdcV6peF5itB5NmJ9N6gaxxE8K" }
    # a DID this suite stubs - w3c looks up delegation keys for whatever it
    # emits as id, see the note on the alsoKnownAs example above
    let(:stubbed_did) { "zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh" }

    it "answers with the requested DID when the resolver kept it" do
      expect(Oydid.document_id("did" => "did:oyd:" + second_did,
                               "did_requested" => "did:oyd:" + first_did))
        .to eq "did:oyd:" + first_did
    end

    it "falls back to the resolved DID for a did_info built by hand" do
      expect(Oydid.document_id("did" => "did:oyd:" + second_did))
        .to eq "did:oyd:" + second_did
    end

    it "adds the method prefix and percent-encodes a location suffix" do
      expect(Oydid.document_id("did" => "", "did_requested" => first_did + "@https://example.org"))
        .to eq "did:oyd:" + first_did + "%40example.org"
    end

    # the point of the exercise: a DID printed on a data carrier keeps naming
    # itself after an update, while the current version stays readable
    it "keeps the requested DID as id and moves the current one to alsoKnownAs" do
      did_info = {
        "did" => "did:oyd:" + second_did,
        "did_requested" => "did:oyd:" + stubbed_did,
        "doc" => { "doc" => { "hello" => "world" },
                   "key" => "z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S:" \
                            "z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK" },
        "log" => [{ "op" => 2, "doc" => stubbed_did },
                  { "op" => 3, "doc" => second_did }]
      }
      wd = Oydid.w3c(Marshal.load(Marshal.dump(did_info)), {})
      expect(wd["id"]).to eq "did:oyd:" + stubbed_did
      expect(wd["alsoKnownAs"]).to eq ["did:oyd:" + second_did]
      # the entries of verificationMethod are built as hash literals with
      # "id": - Ruby makes that a symbol key, the surrounding keys are strings
      expect(wd["verificationMethod"].first[:id]).to start_with("did:oyd:" + stubbed_did + "#")
      expect(wd["verificationMethod"].first[:controller]).to eq "did:oyd:" + stubbed_did

      # canonicalId still names the version the log resolves to, and the
      # equivalent list is everything the document does not call itself
      canonical, equivalent = Oydid.version_ids(did_info)
      expect(canonical).to eq "did:oyd:" + second_did
      expect(equivalent).to eq ["did:oyd:" + second_did]
    end
  end


  describe "CMSM signature verification" do
    # An in-memory stand-in for the session store the repository provides, so
    # these examples run without a database and without the network.
    class MemoryCmsmStore
      def initialize; @data = {}; end
      def set(session, payload); @data[session] = payload; end
      def get(session); @data[session]; end
      def delete(session); @data.delete(session); end
    end

    let(:store) { MemoryCmsmStore.new }
    let(:priv)  { Oydid.generate_private_key("", "ed25519-priv", {}).first }
    let(:pub)   { Oydid.public_key(priv, {}).first }

    def cmsm_options(extra = {})
      { cmsm: true, key_type: "ed25519", cmsm_store: store,
        return_secrets: true, skip_publish: true }.merge(extra)
    end

    # phase 1: hand over the public key, receive session and value to sign
    def start_flow
      status, msg = Oydid.create({ "key" => pub }, cmsm_options)
      expect(msg).to eq("cmsm")
      status.transform_keys(&:to_s)
    end

    describe "cmsm_verify_signature" do
      it "accepts a signature made with the named key" do
        signature = Oydid.sign("hello", priv, {}).first
        expect(Oydid.cmsm_verify_signature("hello", signature, pub, "key-doc")).to be_nil
      end

      it "rejects a signature over a different value" do
        signature = Oydid.sign("hello", priv, {}).first
        msg = Oydid.cmsm_verify_signature("goodbye", signature, pub, "key-doc")
        expect(msg).to eq("CMSM signature for key-doc is invalid")
      end

      it "rejects a signature made with a different key" do
        other = Oydid.generate_private_key("", "ed25519-priv", {}).first
        signature = Oydid.sign("hello", other, {}).first
        expect(Oydid.cmsm_verify_signature("hello", signature, pub, "key-doc")).not_to be_nil
      end

      it "rejects nonsense instead of raising" do
        expect(Oydid.cmsm_verify_signature("hello", "not-a-signature", pub, "key-doc")).not_to be_nil
      end

      it "refuses to verify without a public key" do
        signature = Oydid.sign("hello", priv, {}).first
        msg = Oydid.cmsm_verify_signature("hello", signature, "", "key-doc")
        expect(msg).to include("no public key in session")
      end

      # the message is what the REST layers match on to answer 400 instead of 500
      it "phrases failures as client errors" do
        msg = Oydid.cmsm_verify_signature("hello", "zBogus", pub, "key-rev")
        expect(msg).to start_with("CMSM ")
      end
    end

    describe "a running flow" do
      it "advances when the signature is correct" do
        phase1 = start_flow
        signature = Oydid.sign(phase1["sign"], priv, {}).first

        status, msg = Oydid.create({}, cmsm_options(cmsm_session: phase1["session"], sig: signature))

        expect(msg).to eq("cmsm")
        expect(status.transform_keys(&:to_s)["session"]).to eq(phase1["session"])
      end

      # Before this check the flow took any signature, built the log entries from
      # it and answered 200. The DID did not resolve, but it had claimed the
      # public key - so anyone could burn a key they did not hold.
      it "refuses a signature the client cannot have made" do
        phase1 = start_flow
        forged = Oydid.sign(phase1["sign"],
                            Oydid.generate_private_key("", "ed25519-priv", {}).first, {}).first

        status, msg = Oydid.create({}, cmsm_options(cmsm_session: phase1["session"], sig: forged))

        expect(status).to be_nil
        expect(msg).to eq("CMSM signature for key-doc is invalid")
      end

      it "refuses a signature over a value from another flow" do
        phase1 = start_flow
        other  = start_flow
        signature = Oydid.sign(other["sign"], priv, {}).first

        status, msg = Oydid.create({}, cmsm_options(cmsm_session: phase1["session"], sig: signature))

        expect(status).to be_nil
        expect(msg).to start_with("CMSM ")
      end
    end
  end
  # These four defects together made the whole DIDComm branch unusable and, in
  # the HMAC case, forgeable. Nothing in the suite touched it before.
  describe "DIDComm signing" do
    let(:priv) { Oydid.generate_private_key("didcomm-spec-pwd", "ed25519-priv", {}).first }
    let(:pub)  { Oydid.public_key(priv, {}).first }

    # jwt < 3.2.0 verified an HS256 token against an empty key, so anybody could
    # forge one (CVE-2026-45363). The CLI reaches here with "" whenever
    # --hmac_secret is omitted, so the gem refuses the empty key itself.
    it "refuses to sign with an empty HMAC secret" do
      token, msg = Oydid.msg_sign({ "a" => 1 }, "")

      expect(token).to be_nil
      expect(msg).to eq("HMAC secret must not be empty")
    end

    it "refuses to verify a token forged with an empty HMAC key" do
      header  = Base64.urlsafe_encode64('{"alg":"HS256"}').delete("=")
      payload = Base64.urlsafe_encode64('{"sub":"attacker"}').delete("=")
      digest  = OpenSSL::HMAC.digest("SHA256", "", "#{header}.#{payload}")
      forged  = "#{header}.#{payload}.#{Base64.urlsafe_encode64(digest).delete('=')}"

      decoded, msg = Oydid.msg_verify_jws(forged, "")

      expect(decoded).to be_nil
      expect(msg).to eq("HMAC secret must not be empty")
    end

    it "still round-trips an HMAC signature with a real secret" do
      token, = Oydid.msg_sign({ "a" => 1 }, "s3cr3t")
      decoded, msg = Oydid.msg_verify_jws(token, "s3cr3t")

      expect(msg).to eq("")
      expect(decoded.first).to eq({ "a" => 1 })
    end

    # jwt-eddsa signs with Ed25519::SigningKey; handing it the RbNaCl key raised
    # JWT::EncodeError, so "oydid jws" could not produce a token at all.
    it "signs a DIDComm message with the Ed25519 document key" do
      token, msg = Oydid.dcsm({ "a" => 1 }, priv, { sign_did: "did:oyd:zSpec" })

      expect(msg).to eq("")
      _, _, digest = Oydid.multi_decode(pub).first.unpack("CCa*")
      decoded = JWT.decode(token, Ed25519::VerifyKey.new(digest), true,
                           { algorithms: Oydid::ED25519_ALGS })
      expect(decoded.first).to eq({ "a" => 1 })
      expect(decoded.last["kid"]).to eq("did:oyd:zSpec")
    end

    # w3c() lists "authentication" as a reference and uses symbol keys inside a
    # verification method - the old code indexed a String with "publicKeyMultibase".
    describe "authentication_key" do
      let(:didDocument) do
        { "authentication" => ["did:oyd:zSpec#key-doc"],
          "verificationMethod" => [
            { id: "did:oyd:zSpec#key-rev", publicKeyMultibase: "z6MkRev" },
            { id: "did:oyd:zSpec#key-doc", publicKeyMultibase: "z6MkDoc" }
          ] }
      end

      it "dereferences a referenced verification method" do
        key, msg = Oydid.authentication_key(didDocument)

        expect(key).to eq("z6MkDoc")
        expect(msg).to eq("")
      end

      it "accepts an embedded verification method" do
        key, = Oydid.authentication_key(
          { "authentication" => [{ "publicKeyMultibase" => "z6MkEmbedded" }] })

        expect(key).to eq("z6MkEmbedded")
      end

      # a DID created without --authentication has no such section; report it
      # instead of raising NoMethodError on nil
      it "reports a document without an authentication section" do
        key, msg = Oydid.authentication_key(didDocument.reject { |k, _| k == "authentication" })

        expect(key).to be_nil
        expect(msg).to eq("no authentication key in DID document")
      end
    end

    # dcsm_verify takes the public key from the token's own kid header, so a
    # green result on its own says nothing about *who* signed. --expect-did is
    # what turns it into an authorisation check.
    describe "expect_did" do
      let(:token) { Oydid.dcsm({ "a" => 1 }, priv, { sign_did: "did:oyd:zSigner" }).first }

      it "treats the two spellings of the location separator as one DID" do
        expect(Oydid.same_did?("did:oyd:zAbc%40example.com", "did:oyd:zAbc@example.com")).to be true
      end

      it "ignores a key fragment" do
        expect(Oydid.same_did?("did:oyd:zAbc#key-doc", "did:oyd:zAbc")).to be true
      end

      it "separates different DIDs" do
        expect(Oydid.same_did?("did:oyd:zAbc", "did:oyd:zDef")).to be false
      end

      # webmock lets no unstubbed request through, so this also shows that the
      # mismatch is caught before the DID is resolved
      it "refuses a token signed by another DID without resolving it" do
        payload, msg = Oydid.dcsm_verify(token, { expect_did: "did:oyd:zSomeoneElse" })

        expect(payload).to be_nil
        expect(msg).to eq("token was signed by did:oyd:zSigner, expected did:oyd:zSomeoneElse")
      end
    end
  end
end
