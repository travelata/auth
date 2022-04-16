module github.com/travelata/auth

go 1.15

require (
	github.com/go-redis/redis v6.15.9+incompatible
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang/protobuf v1.4.3
	github.com/olivere/elastic/v7 v7.0.22
	github.com/sethvargo/go-password v0.2.0 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/travelata/kit v0.0.0-local
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a
	google.golang.org/grpc v1.36.0
	google.golang.org/protobuf v1.25.0
)

replace github.com/travelata/proto => ../proto

replace github.com/travelata/kit => ../kit
