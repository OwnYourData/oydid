class AddPublicKeyToOauthAccessToken < ActiveRecord::Migration[5.2]
  def change
    add_column :oauth_access_tokens, :public_key, :string
  end
end
