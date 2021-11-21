# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# Note that this schema.rb definition is the authoritative source for your
# database schema. If you need to create the application database on another
# system, you should be using db:schema:load, not running all the migrations
# from scratch. The latter is a flawed and unsustainable approach (the more migrations
# you'll amass, the slower it'll run and the greater likelihood for issues).
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema.define(version: 2020_12_31_002222) do

  create_table "dids", force: :cascade do |t|
    t.string "did"
    t.text "doc"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["did"], name: "index_dids_on_did", unique: true
  end

  create_table "logs", force: :cascade do |t|
    t.text "item"
    t.string "oyd_hash"
    t.string "did"
    t.integer "ts"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["did"], name: "index_logs_on_did"
    t.index ["oyd_hash"], name: "index_logs_on_oyd_hash", unique: true
  end

end
