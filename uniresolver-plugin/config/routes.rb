Rails.application.routes.draw do
    match '1.0/identifiers/:did',        to: 'dids#uniresolver_resolve',    via: 'get', constraints: {did: /.*/}
    match 'resolve/:did',                to: 'dids#resolve'            ,    via: 'get', constraints: {did: /.*/}
    match 'resolve_representation/:did', to: 'dids#resolve_representation', via: 'get', constraints: {did: /.*/}
    match 'dereference/:did',            to: 'dids#dereference',            via: 'get', constraints: {did: /.*/}

    # administrative
    match '/version',   to: 'application#version', via: 'get'
    match ':not_found', to: 'application#missing', via: [:get, :post], :constraints => { :not_found => /.*/ }
end
