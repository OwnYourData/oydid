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
class Credential < ApplicationRecord
end
