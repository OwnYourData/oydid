class CreateLogs < ActiveRecord::Migration[5.2]
  def change
    create_table :logs do |t|
      t.text :item
      t.string :oyd_hash
      t.string :did
      t.integer :ts

      t.timestamps
    end
    add_index :logs, :oyd_hash, unique: true
    add_index :logs, :did
  end
end
