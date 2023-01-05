# == Schema Information
#
# Table name: dids
#
#  id         :integer          not null, primary key
#  did        :string
#  doc        :text
#  public_key :string
#  created_at :datetime         not null
#  updated_at :datetime         not null
#
# Indexes
#
#  index_dids_on_did         (did) UNIQUE
#  index_dids_on_public_key  (public_key) UNIQUE
#
require 'rails_helper'

RSpec.describe Did, type: :model do
  pending "add some examples to (or delete) #{__FILE__}"
end
