Rails.application.routes.draw do
    match '1.0/identifiers/:did', to: 'dids#resolve', via: 'get', constraints: {did: /.*/}

    match ':not_found' => 'application#missing', :constraints => { :not_found => /.*/ }, via: [:get, :post]
end
