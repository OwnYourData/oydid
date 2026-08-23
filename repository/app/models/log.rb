# == Schema Information
#
# Table name: logs
#
#  id         :integer          not null, primary key
#  did        :string
#  item       :text
#  oyd_hash   :string
#  sub_hash   :string
#  ts         :integer
#  created_at :datetime         not null
#  updated_at :datetime         not null
#
# Indexes
#
#  index_logs_on_did       (did)
#  index_logs_on_oyd_hash  (oyd_hash) UNIQUE
#  index_logs_on_sub_hash  (sub_hash)
#
class Log < ApplicationRecord

    # Ein REVOKE-Eintrag (op:1) wird von zwei Seiten referenziert und hat
    # deshalb zwei Hashes (siehe ruby-gem/lib/oydid/log.rb):
    #
    #   entry-hash      ueber {ts,op,doc,sig,previous}  <- previous-Ketten
    #   sub-entry-hash  ueber {ts,op,doc,sig}           <- doc des TERMINATE
    #
    # Alle anderen Operationen haben nur die entry-hash; sub_hash bleibt nil.
    # Liefert [entry_hash, sub_hash].
    def self.hashes_for(item, options)
        entry = Oydid.multi_hash(
            Oydid.canonical(item.slice("ts", "op", "doc", "sig", "previous")), options).first
        return [entry, nil] if item["op"].to_i != 1
        sub = Oydid.multi_hash(
            Oydid.canonical(item.slice("ts", "op", "doc", "sig")), options).first
        [entry, sub]
    end

    # Sucht einen Eintrag ueber beide Hash-Spalten. Fuer Altbestaende, deren
    # oyd_hash nach heutigen Regeln nicht reproduzierbar ist, bleibt oyd_hash
    # der einzige Treffer - deshalb zuerst dort suchen.
    def self.find_by_any_hash(value)
        return nil if value.to_s == ""
        find_by(oyd_hash: value) || find_by(sub_hash: value)
    end

    # Ist dieser Record - unter welcher seiner beiden Hashes auch immer -
    # bereits gespeichert?
    def self.stored?(entry_hash, sub_hash = nil)
        candidates = [entry_hash, sub_hash].compact.reject(&:empty?)
        return false if candidates.empty?
        where(oyd_hash: candidates).exists? || where(sub_hash: candidates).exists?
    end
end
