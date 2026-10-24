module github.com/eshu-hq/eshu-collector-kubernetes-live

go 1.26.5

require (
	github.com/eshu-hq/eshu-sdk/collector v0.1.0-rc.2
	github.com/eshu-hq/eshu-sdk/factschema v0.1.0-rc.2
	go.opentelemetry.io/otel v1.47.0
	go.opentelemetry.io/otel/trace v1.47.0
)

require github.com/cespare/xxhash/v2 v2.3.0 // indirect
