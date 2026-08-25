require 'rails_helper'
require 'rake'

# The backfill fills public_key for rows created before the column existed
# (November 2022). Pinned here: what it fills, what it leaves alone, that the
# collector key stays excluded, and that a second run finds nothing to do.
RSpec.describe 'oydid:backfill_public_keys' do

  def document(key)
    { "doc" => { "simple" => "example" },
      "key" => key,
      "log" => "zQmLogHash" }.to_json
  end

  def run_task(apply: false)
    Rake::Task['oydid:backfill_public_keys'].reenable
    previous = ENV['APPLY']
    ENV['APPLY'] = apply ? '1' : nil
    captured = StringIO.new
    original = $stdout
    $stdout = captured
    begin
      Rake::Task['oydid:backfill_public_keys'].invoke
    ensure
      $stdout = original
      ENV['APPLY'] = previous
    end
    captured.string
  end

  before(:all) do
    Rails.application.load_tasks unless Rake::Task.task_defined?('oydid:backfill_public_keys')
  end

  let!(:legacy) do
    Did.create!(did: "zQmLegacy", public_key: nil,
                doc: document("z6MkDocKeyLegacy:z6MkRevKeyLegacy"))
  end
  let!(:without_key) do
    Did.create!(did: "zQmWithoutKey", public_key: nil,
                doc: { "doc" => { "a" => 1 }, "log" => "zQmLogHash" }.to_json)
  end
  let!(:unparseable) do
    Did.create!(did: "zQmUnparseable", public_key: nil, doc: "not json")
  end
  let!(:already_set) do
    Did.create!(did: "zQmRecent", public_key: "z6MkDocKeyRecent",
                doc: document("z6MkDocKeyRecent:z6MkRevKeyRecent"))
  end

  it "reports the categories and changes nothing" do
    output = run_task

    expect(output).to include('MODUS: Bericht')
    expect(output).to match(/Zeilen ohne public_key: 3 von 4/)
    expect(output).to match(/key_gefunden\s+1/)
    expect(output).to match(/key_fehlt\s+1/)
    expect(output).to match(/doc_unlesbar\s+1/)

    expect(legacy.reload.public_key).to be_nil
  end

  it "writes only the document key with APPLY=1" do
    output = run_task(apply: true)

    expect(output).to include('MODUS: schreiben')
    expect(output).to match(/geaenderte Zeilen: 1/)

    expect(legacy.reload.public_key).to eq('z6MkDocKeyLegacy')
    expect(without_key.reload.public_key).to be_nil
    expect(unparseable.reload.public_key).to be_nil
    expect(already_set.reload.public_key).to eq('z6MkDocKeyRecent')
  end

  it "is repeatable - the second run finds nothing left" do
    run_task(apply: true)
    output = run_task(apply: true)

    expect(output).to match(/geaenderte Zeilen: 0/)
    expect(legacy.reload.public_key).to eq('z6MkDocKeyLegacy')
  end

  it "makes the DID resolvable through the public key shorthand" do
    expect(Did.find_by_public_key_active('z6MkDocKeyLegacy')).to be_nil
    run_task(apply: true)
    expect(Did.find_by_public_key_active('z6MkDocKeyLegacy')).to eq(legacy)
  end

  it "reports the multiple assignments the backfill would surface" do
    Did.create!(did: "zQmTwin", public_key: nil,
                doc: document("z6MkDocKeyRecent:z6MkRevKeyRecent"))

    output = run_task

    expect(output).to match(/Schluessel mit danach mehr als einer DID: 1/)
    expect(output).to include('z6MkDocKeyRecent')
  end

  # The collector key carries thousands of experiment DIDs. Filling it would
  # give the shorthand an arbitrary answer and widen the CREATE guardrail to a
  # population nobody has claimed.
  describe "excluded collector keys" do
    let(:skipped) { BACKFILL_SKIP_KEYS.first }
    let!(:collector) do
      Did.create!(did: "zQmCollector", public_key: nil,
                  doc: document("#{skipped}:z6MkRevKeyCollector"))
    end

    it "counts them separately and leaves the column empty" do
      output = run_task(apply: true)

      expect(output).to include("ausgenommener Sammel-Schluessel: #{skipped}")
      expect(output).to match(/ausgenommen\s+1/)
      expect(output).to match(/geaenderte Zeilen: 1/)

      expect(collector.reload.public_key).to be_nil
      expect(legacy.reload.public_key).to eq('z6MkDocKeyLegacy')
    end

    it "keeps the shorthand answering 404 for them" do
      run_task(apply: true)
      expect(Did.find_by_public_key_active(skipped)).to be_nil
    end
  end
end
