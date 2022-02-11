Rails.application.routes.draw do
    match '1.0/create',     to: 'dids#creat', via: 'post'
    match '1.0/update',     to: 'dids#creat', via: 'post'
    match '1.0/deactivate', to: 'dids#creat', via: 'post'    

    match ':not_found' => 'application#missing', :constraints => { :not_found => /.*/ }, via: [:get, :post]
end
