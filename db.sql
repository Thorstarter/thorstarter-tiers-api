create table registrations (
  id text primary key,
  ido text not null,
  address text not null,
  tier int not null,
  xrune int not null,
  bonus int not null,
  iphash text not null,
  created_at timestamptz not null default now()
);
