# Ein REVOKE-Eintrag (op:1) hat zwei Hashes: die entry-hash ueber
# {ts,op,doc,sig,previous} und die sub-entry-hash ueber {ts,op,doc,sig}.
# Der TERMINATE-Eintrag referenziert die sub-entry-hash, previous-Ketten die
# entry-hash - eine Spalte kann nicht beide halten.
class AddSubHashToLogs < ActiveRecord::Migration[7.2]
    def change
        add_column :logs, :sub_hash, :string
        add_index  :logs, :sub_hash
    end
end
