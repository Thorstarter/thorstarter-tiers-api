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