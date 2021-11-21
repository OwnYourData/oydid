Rails.application.routes.draw do
    mount Rswag::Ui::Engine => '/api-docs'
    mount Rswag::Api::Engine => '/api-docs'

    match 'doc/:did', to: 'dids#show',   via: 'get', constraints: {did: /.*/}
    match 'did/:did', to: 'dids#show',   via: 'get', constraints: {did: /.*/}
    match 'did',      to: 'dids#create', via: 'post'
    match 'doc',      to: 'dids#create', via: 'post'
    match 'log/:id',  to: 'logs#show',   via: 'get', constraints: {id: /.*/}
    match 'log/:did', to: 'logs#create', via: 'post', constraints: {did: /.*/}
    match 'doc/:did', to: 'dids#delete', via: 'delete', constraints: {did: /.*/}

    match '1.0/identifiers/:did', to: 'dids#resolve', via: 'get', constraints: {did: /.*/}

    match ':not_found' => 'application#missing', :constraints => { :not_found => /.*/ }, via: [:get, :post]
end
