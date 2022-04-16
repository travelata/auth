-- +goose Up
CREATE ROLE auth LOGIN PASSWORD 'auth' NOINHERIT CREATEDB;
CREATE SCHEMA auth AUTHORIZATION auth;
GRANT USAGE ON SCHEMA auth TO PUBLIC;

-- +goose Down
DROP SCHEMA auth;
DROP ROLE auth;
