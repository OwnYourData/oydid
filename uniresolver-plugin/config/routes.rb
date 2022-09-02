Rails.application.routes.draw do
    match '1.0/identifiers/:did', to: 'dids#resolve', via: 'get', constraints: {did: /.*/}

    # administrative
    match '/version',   to: 'application#version', via: 'get'
    match ':not_found', to: 'application#missing', via: [:get, :post], :constraints => { :not_found => /.*/ }
end
