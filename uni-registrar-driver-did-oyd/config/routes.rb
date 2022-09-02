Rails.application.routes.draw do
    match '1.0/create',     to: 'dids#create',     via: 'post'
    match '1.0/update',     to: 'dids#update',     via: 'post'
    match '1.0/deactivate', to: 'dids#deactivate', via: 'post'

    # administrative
    match '/version',   to: 'application#version', via: 'get'
    match ':not_found', to: 'application#missing', via: [:get, :post], :constraints => { :not_found => /.*/ }
end
