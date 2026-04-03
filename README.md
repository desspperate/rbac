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
- Data maps from postgres to keydb using the **Transactional Outbox** pattern through a trigger-table and a taskiq worker
- System monitors three state pointers:
    - $h$ (Head): The latest task ID in the Outbox table
    - $c$ (Cursor): Worker progress tracked in Postgres
    - $s$ (Sync): The actual synchronization ID stored within KeyDB
- **Fallback & Self-Healing:**
    1. Lag Check: if $(h - c) > k \implies$ switch to **Strict Postgres**
    2. Integrity Check: if $c \neq s \implies$ switch to **Strict Postgres** and reset all Outbox tasks from $s$ to $c$ to "pending" status for re-sync.
- Service is focused only on permission management with high-consistency guarantees
