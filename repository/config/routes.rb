Rails.application.routes.draw do
  use_doorkeeper
    mount Rswag::Ui::Engine => '/api-docs'
    mount Rswag::Api::Engine => '/api-docs'

    match 'doc/:did',             to: 'dids#show',              via: 'get', constraints: {did: /.*/}
    match 'doc_raw/:did',         to: 'dids#raw',               via: 'get', constraints: {did: /.*/}
    match 'did/:did',             to: 'dids#show',              via: 'get', constraints: {did: /.*/}
    match 'did',                  to: 'dids#create',            via: 'post'
    match 'doc',                  to: 'dids#create',            via: 'post'
    match 'log/:id/item',         to: 'logs#show_item',         via: 'get', constraints: {id: /.*/}
    match 'log/:id',              to: 'logs#show',              via: 'get', constraints: {id: /.*/}
    match 'log/:did',             to: 'logs#create',            via: 'post', constraints: {did: /.*/}
    match 'doc/:did',             to: 'dids#delete',            via: 'delete', constraints: {did: /.*/}

    # CMSM Support (Client-Managed-Secret-Mode)
    match 'cmsm/:id',             to: 'cmsm#show',              via: 'get', constraints: {id: /.*/}
    match 'cmsm',                 to: 'cmsm#create',            via: 'post'

    # VC & VP endpoints
    match 'credentials/:id',      to: 'credentials#show_vc',    via: 'get', constraints: {id: /.*/}
    match 'credentials',          to: 'credentials#publish_vc', via: 'post'
    match 'presentations/:id',    to: 'credentials#show_vp',    via: 'get', constraints: {id: /.*/}
    match 'presentations',        to: 'credentials#publish_vp', via: 'post'

    # Uniresolver endpoint
    match '1.0/identifiers/:did',    to: 'dids#resolve',        via: 'get', constraints: {did: /.*/}

    # Uniregistrar endpoints
    match '1.0/create',     to: 'dids#uniregistrar_create',     via: 'post'
    match '1.0/update',     to: 'dids#uniregistrar_update',     via: 'post'
    match '1.0/deactivate', to: 'dids#uniregistrar_deactivate', via: 'post'

    # OYDID Auth challenge
    match 'oydid/init',     to: 'dids#init',                    via: 'post'
    match 'oydid/token',    to: 'dids#token',                   via: 'post'

    # helper functions
    match 'helper/encrypt', to: 'dids#encrypt',                 via: 'post'
    match 'helper/decrypt', to: 'dids#decrypt',                 via: 'post'

    # did:web support
    match ':did/did.json',  to: 'dids#web', via: 'get'

    # administrative
    root 'application#home'
    match '/',          to: 'application#home',    via: 'get'
    match '/version',   to: 'application#version', via: 'get'
    match ':not_found', to: 'application#missing', via: [:get, :post], :constraints => { :not_found => /.*/ }
end
