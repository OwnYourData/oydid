# == Schema Information
#
# Table name: presentations
#
#  id         :integer          not null, primary key
#  holder     :string
#  identifier :string
#  vp         :text
#  created_at :datetime         not null
#  updated_at :datetime         not null
#
require 'rails_helper'

RSpec.describe Presentation, type: :model do
  pending "add some examples to (or delete) #{__FILE__}"
end
