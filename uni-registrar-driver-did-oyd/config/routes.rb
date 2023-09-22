Rails.application.routes.draw do
    # Uniregistrar
    match '1.0/create',     to: 'dids#create',     via: 'post'
    match '1.0/update',     to: 'dids#update',     via: 'post'
    match '1.0/deactivate', to: 'dids#deactivate', via: 'post'

    # DID Provider
    match '1.0/createIdentifier',     to: 'providers#create',     via: 'post'
    match '1.0/updateIdentifier',     to: 'providers#update',     via: 'post'
    match '1.0/deactivateIdentifier', to: 'providers#deactivate', via: 'post'

    # administrative
    match '/version',   to: 'application#version', via: 'get'
    match ':not_found', to: 'application#missing', via: [:get, :post], :constraints => { :not_found => /.*/ }
end
