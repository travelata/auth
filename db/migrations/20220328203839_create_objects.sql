-- +goose Up
set schema 'auth';

create table samples
(
  id uuid primary key,
  name varchar not null,
  details jsonb,
  created_at timestamp not null,
  updated_at timestamp not null,
  deleted_at timestamp null
);

-- +goose Down
drop table samples;
