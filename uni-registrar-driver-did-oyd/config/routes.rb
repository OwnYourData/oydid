Rails.application.routes.draw do
    match '1.0/create',     to: 'dids#create',     via: 'post'
    match '1.0/update',     to: 'dids#update',     via: 'post'
    match '1.0/deactivate', to: 'dids#deactivate', via: 'post'

    match '1.0/version',    to: 'dids#version',    via: 'get'
    match ':not_found' => 'application#missing', :constraints => { :not_found => /.*/ }, via: [:get, :post]
end
