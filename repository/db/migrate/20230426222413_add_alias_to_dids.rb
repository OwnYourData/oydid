class AddAliasToDids < ActiveRecord::Migration[5.2]
  def change
    add_column :dids, :alias, :string
  end
end
