create table registrations (
  id text primary key,
  ido text not null,
  address text not null,
  tier int not null,
  xrune int not null,
  bonus int not null,
  iphash text not null,
  address_terra text not null,
  created_at timestamptz not null default now()
);

create table kyc (
  id text primary key,
  address text not null,
  session_id text not null,
  verified boolean not null default false,
  created_at timestamptz not null default now()
);

create table users (
  id text primary key,
  kyc_verified boolean not null default false,
  address_ethereum text not null,
  address_terra text not null,
  address_fantom text not null,
  address_polygon text not null,
  amount_ethereum int not null,
  amount_terra int not null,
  amount_fantom int not null,
  amount_polygon int not null,
  amount_tclp int not null,
  amount_forge int not null,
  iphash text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table users_addresses (
  id text primary key,
  user_id text not null,
  network text not null,
  address text not null,
  created_at timestamptz not null default now()
);

create table users_ips (
  id text primary key,
  user_id text not null,
  iphash text not null,
  created_at timestamptz not null default now()
);

create table users_registrations (
  id text primary key,
  ido text not null,
  user_id text not null,
  created_at timestamptz not null default now()
);
