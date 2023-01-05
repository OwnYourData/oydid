class AddIdentifierIndexToCredentials < ActiveRecord::Migration[5.2]
  add_index :credentials, :identifier, unique: true
end
