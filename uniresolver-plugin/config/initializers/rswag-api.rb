Rswag::Api.configure do |c|

  # Folder holding the OpenAPI description served under /api-docs/v1/swagger.yml
  c.openapi_root = Rails.root.to_s + '/swagger'

end
