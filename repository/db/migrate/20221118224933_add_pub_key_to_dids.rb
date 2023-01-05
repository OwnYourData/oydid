class AddPubKeyToDids < ActiveRecord::Migration[5.2]
  def change
    add_column :dids, :public_key, :string
  end
end
