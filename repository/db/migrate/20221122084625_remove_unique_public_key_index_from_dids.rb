class RemoveUniquePublicKeyIndexFromDids < ActiveRecord::Migration[5.2]
  def change
  end
  remove_index :dids, :public_key
  add_index :dids, :public_key
end
