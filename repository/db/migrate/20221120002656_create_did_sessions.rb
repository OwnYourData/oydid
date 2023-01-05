class CreateDidSessions < ActiveRecord::Migration[5.2]
  def change
    create_table :did_sessions do |t|
      t.string :session
      t.integer :oauth_application_id
      t.string :challenge
      t.string :public_key

      t.timestamps
    end
  end
end
