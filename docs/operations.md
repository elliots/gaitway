# Pilot operations

Gaitway's dashboard and raw-content API have no application authentication.
Expose ports 8080 and 8081 only to the intended private developer network. Do
not publish PostgreSQL, MinIO, or the OpenTelemetry Collector outside host or
service-network loopback.

## Deploy and inspect

Validate configuration before each rollout:

```bash
docker compose config --quiet
docker compose up --build -d
docker compose ps
curl -fsS http://127.0.0.1:8081/healthz
curl -fsS http://127.0.0.1:8081/readyz
```

The service stops accepting work and gets ten seconds to drain accepted HTTP
requests on SIGTERM. Request bodies, captured responses, SSE frames, plugin
deadlines, tool results, and database pools are bounded. Raw evidence is
archived before an allowed request can leave the gateway; archive failure is a
fail-closed `503`.

## Backup and restore

Back up PostgreSQL and the raw archive as one named recovery point. Stop
Gaitway first so the two copies share a clear cutoff.

Filesystem deployment:

```bash
docker compose stop gaitway
mkdir -p backups/recovery-YYYYMMDD
docker compose exec -T postgres pg_dump -U gaitway -Fc gaitway > backups/recovery-YYYYMMDD/postgres.dump
docker compose cp gaitway:/var/lib/gaitway backups/recovery-YYYYMMDD/gaitway-data
docker compose start gaitway
```

For S3, enable bucket versioning and use the object platform's immutable
snapshot/replication mechanism at the same cutoff instead of copying the
filesystem volume. Preserve `identity-hmac.key` and `gateway-tool-hmac.key`;
losing or replacing either breaks stable attribution and tool-principal
fingerprints.

Restore into an isolated environment first. Restore the archive and key files,
then recreate the database and run `pg_restore`. Start Gaitway only after both
halves are present. Sample several audit `content_ref` values, retrieve each
object through the dashboard API, and compare its SHA-256 to
`content_sha256`. Missing or mismatched objects block the recovery.

## Incidents

- **Archive unavailable:** requests fail closed. Restore disk/S3 reachability;
  do not bypass evidence capture.
- **PostgreSQL unavailable:** Compose restarts the process until metadata
  persistence is available. The JSONL fallback is selected only when
  `DATABASE_URL` is deliberately absent; it is not an automatic failover.
- **Plugin panic or timeout:** request plugins fail closed; central tool errors
  are classified and returned to Claude without an automatic side-effect retry.
- **Budget mismatch:** inspect request/response audit pairs. Reservations are
  reconciled to provider usage on the terminal response and released on an
  explicit failure.
- **Credential or content leak:** isolate both gateway ports, rotate the
  affected upstream/downstream credential, retain audit evidence, and replace
  HMAC keys only if they were exposed.
- **Disk pressure:** stop admission before the filesystem fills. Move complete
  recovery points or select S3; never delete individual objects without also
  applying the future retention workflow.

## Claude Code upgrades

Pin the supported Claude Code version for the pilot. Before admitting a new
version, run deterministic tests and `scripts/live-test.sh`, then manually
exercise an interactive session, resume, fork/rewind, compaction, a subagent,
parallel sessions, a usage acknowledgement, gateway-only HTTP, and a mixed
Bash/HTTP turn. A missing activation marker, malformed stream, repeated tool
effect, failed identity probe, credential canary, or missing archive object is
a release blocker.
