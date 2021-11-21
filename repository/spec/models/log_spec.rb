# == Schema Information
#
# Table name: logs
#
#  id         :integer          not null, primary key
#  did        :string
#  item       :text
#  oyd_hash   :string
#  ts         :integer
#  created_at :datetime         not null
#  updated_at :datetime         not null
#
# Indexes
#
#  index_logs_on_did       (did)
#  index_logs_on_oyd_hash  (oyd_hash) UNIQUE
#
require 'rails_helper'

RSpec.describe Log, type: :model do
  pending "add some examples to (or delete) #{__FILE__}"
end
