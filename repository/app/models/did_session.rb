# == Schema Information
#
# Table name: did_sessions
#
#  id                   :integer          not null, primary key
#  challenge            :string
#  public_key           :string
#  session              :string
#  created_at           :datetime         not null
#  updated_at           :datetime         not null
#  oauth_application_id :integer
#
class DidSession < ApplicationRecord
end
