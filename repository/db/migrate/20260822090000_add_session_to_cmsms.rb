# A CMSM flow is identified by a session handle, not by the public key: the same
# key may legitimately be reused across flows, and the unique index on pubkey
# made a second flow overwrite the first one.
class AddSessionToCmsms < ActiveRecord::Migration[7.2]
  def change
    add_column :cmsms, :session, :string

    remove_index :cmsms, :pubkey
    add_index    :cmsms, :pubkey
    add_index    :cmsms, :session, unique: true
  end
end
