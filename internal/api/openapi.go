package api

import _ "embed"

// OpenAPISpec is served at /api/v1/openapi.yaml and used to generate the web UI's typed client.
//
//go:embed openapi.yaml
var OpenAPISpec []byte
