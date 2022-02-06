require_relative 'spec_helper'

describe "encoding and decoding" do
  Dir.glob(File.expand_path("../input/*_enc.doc", __FILE__)).each do |input|
    it "encodes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.encode(data)).to eq expected
    end
  end
  Dir.glob(File.expand_path("../input/*_dec.doc", __FILE__)).each do |input|
    it "decodes #{input.split('/').last}" do
      expected = File.read(input.sub('input', 'output'))
      data = File.read(input)
      expect(Oydid.decode(data)).to eq expected
    end
  end
end
