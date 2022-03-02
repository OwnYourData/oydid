require_relative 'spec_helper'

describe "OYDID handling" do
  # basic functions
  Dir.glob(File.expand_path("../input/basic/*_enc.doc", __FILE__)).each do |input|
    it "encodes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.encode(data)).to eq expected
    end
  end
  Dir.glob(File.expand_path("../input/basic/*_dec.doc", __FILE__)).each do |input|
    it "decodes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.decode(data)).to eq expected
    end
  end
  Dir.glob(File.expand_path("../input/basic/*_hash.doc", __FILE__)).each do |input|
    it "hashes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.hash(data)).to eq expected
    end
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
      expect(Oydid.generate_private_key(data).first).to eq expected
    end
  end
  it "handles unknown key codec" do
    expected = "unknown key codec"
    expect(Oydid.generate_private_key("", "asdf").last).to eq expected
  end
  it "handles unsupported key codec" do
    expected = "unsupported key codec"
    expect(Oydid.generate_private_key("", "p256-pub").last).to eq expected
  end
  it "handles random key generation" do
    expected_length = 48
    expect(Oydid.generate_private_key("").first.length).to eq expected_length
  end
  Dir.glob(File.expand_path("../input/basic/*_privkey.doc", __FILE__)).each do |input|
    it "public key from private key #{input.split('/').last}" do
      expected = JSON.parse(File.read(input.sub('input', 'output')))
      data = File.read(input)
      expect(Oydid.public_key(data)).to eq expected
    end
  end
  Dir.glob(File.expand_path("../input/basic/*_sign.doc", __FILE__)).each do |input|
    it "signing #{input.split('/').last}" do
      expected = JSON.parse(File.read(input.sub('input', 'output')))
      data = JSON.parse(File.read(input))
      expect(Oydid.sign(data["message"], data["key"])).to eq expected
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
      expect(Oydid.read_private_key(data)).to eq expected
    end
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
  Dir.glob(File.expand_path("../input/log/*_dag_update.doc", __FILE__)).each do |input|
    it "process DAG for #{input.split('/').last}" do
      expected = JSON.parse(File.read(input.sub('input', 'output')))
      data = JSON.parse(File.read(input))
      expect(Oydid.dag_update(data["currentDID"], data["options"])).to eq expected
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

end
