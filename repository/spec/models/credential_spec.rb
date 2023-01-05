# == Schema Information
#
# Table name: credentials
#
#  id         :integer          not null, primary key
#  holder     :string
#  identifier :string
#  vc         :text
#  created_at :datetime         not null
#  updated_at :datetime         not null
#
# Indexes
#
#  index_credentials_on_identifier  (identifier) UNIQUE
#
require 'rails_helper'

RSpec.describe Credential, type: :model do
  pending "add some examples to (or delete) #{__FILE__}"
end
