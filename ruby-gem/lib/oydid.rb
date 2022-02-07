# -*- encoding: utf-8 -*-
# frozen_string_literal: true
require 'multibases'

class Oydid
    def self.encode(message, method: "base58btc")
        Multibases.pack(method, message).to_s
    end

    def self.decode(message)
        Multibases.unpack(message).decode.to_s('ASCII-8BIT')
    end
end