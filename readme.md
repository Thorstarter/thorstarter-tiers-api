## Thorstarter Tiers API

Stores interest registrations for pending idos 

### Endpoints

`GET /stats?ido=mnet` Shows tiers registration statistics for an IDO

```
{
  "stats": [
    {
      "bonus": 1,
      "count": 1,
      "tier": 2
    },
    ...
  ]
}
```

`GET /user?address=0x...` Shows tiers registration history for an address

```
{
  "registrations": [
    {
      "created_at": "2021-11-22T10:17:44.432552-05:00",
      "ido": "mnet",
      "bonus": 1,
      "tier": 2
    },
    ...
  ]
}
```

`POST /register?ido=` Registers intent to participate in an IDO

```
{
    "address": "0x...",
    "tier": "1",
    "xrune": "2500",
    "bonus": "1",
}
```
