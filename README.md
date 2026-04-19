## Quick Start
Use the following command corresponding to your environment:
```shell
# dev
make dev
# prod
make prod
```

## Architect
- Postgres is the source of truth for reliable data storage
- KeyDB is a mapping of postgres state to reduce response time
- Selective Optimization:
  - Admin API: All management endpoints work in Strict Postgres mode for absolute consistency
  - Hot Path: The /me endpoint and token validation leverage the KeyDB mapping for high performance
- Data maps from postgres to keydb using the **Transactional Outbox** pattern through a trigger-table and a taskiq worker
- System monitors three state pointers:
  - $h$ (Head): The latest task ID in the Outbox table
  - $c$ (Cursor): Worker progress tracked in Postgres
  - $s$ (Sync): The actual synchronization ID stored within KeyDB
- **Fallback & Self-Healing:**
  1. Integrity Check: if $c \neq s \implies$ switch to **Strict Postgres** and reset all Outbox tasks from $s$ to $c$ to "pending" status for re-sync.
  2. Lag Check: if $(h - c) > k \implies$ switch to **Strict Postgres**
- Service is focused only on permission management and authorization through opaque with high-consistency guarantees
