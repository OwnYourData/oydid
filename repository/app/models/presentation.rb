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
class Presentation < ApplicationRecord
end
