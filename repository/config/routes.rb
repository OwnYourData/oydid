Rails.application.routes.draw do
    mount Rswag::Ui::Engine => '/api-docs'
    mount Rswag::Api::Engine => '/api-docs'

    match 'doc/:did',     to: 'dids#show',   via: 'get', constraints: {did: /.*/}
    match 'doc_raw/:did', to: 'dids#raw',    via: 'get', constraints: {did: /.*/}
    match 'did/:did',     to: 'dids#show',   via: 'get', constraints: {did: /.*/}
    match 'did',          to: 'dids#create', via: 'post'
    match 'doc',          to: 'dids#create', via: 'post'
    match 'log/:id',      to: 'logs#show',   via: 'get', constraints: {id: /.*/}
    match 'log/:did',     to: 'logs#create', via: 'post', constraints: {did: /.*/}
    match 'doc/:did',     to: 'dids#delete', via: 'delete', constraints: {did: /.*/}

    # Uniresolver endpoint
    match '1.0/identifiers/:did', to: 'dids#resolve', via: 'get', constraints: {did: /.*/}

    # Uniregistrar endpoints
    match '1.0/create',     to: 'dids#uniregistrar_create',     via: 'post'
    match '1.0/update',     to: 'dids#uniregistrar_update',     via: 'post'
    match '1.0/deactivate', to: 'dids#uniregistrar_deactivate', via: 'post'

    # administrative
    root 'application#home'
    match '/',          to: 'application#home', via: 'get'
    match '/version',   to: 'application#version', via: 'get'
    match ':not_found', to: 'application#missing', via: [:get, :post], :constraints => { :not_found => /.*/ }
end
