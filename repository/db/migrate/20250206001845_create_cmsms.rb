class CreateCmsms < ActiveRecord::Migration[7.2]
  def change
    create_table :cmsms do |t|
      t.string :pubkey
      t.text :payload

      t.timestamps
    end
    add_index :cmsms, :pubkey, unique: true
  end
end
