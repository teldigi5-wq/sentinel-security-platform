# Sensor-to-asset enrollment (v0.10)

Sentinel can restrict every enrolled signing identity to exactly one asset. Configure both maps privately, using matching sensor IDs:

```sh
SENTINEL_SENSOR_KEYS='{"lab-one":"<REPLACE_WITH_32+_CHAR_RANDOM_SECRET>"}'
SENTINEL_SENSOR_ASSETS='{"lab-one":"workstation-1"}'
```

When the explicit asset map is provided, **every** sensor key must have an assigned asset, and no extra IDs are allowed. A signed event or heartbeat claiming another asset receives HTTP 403 and does not update liveness, telemetry or replay state.

Without `SENTINEL_SENSOR_ASSETS`, existing local installations can use trust-on-first-contact. The first accepted contact permanently pins the sensor to its stated asset in the database. This is not administrative verification, and a stolen signing key may impersonate the device. The operator coverage API distinguishes explicit enrollment from first-contact pinning, reports expected assets, and keeps a never-seen sensor marked as never seen.

A deliberate asset reassignment requires a reviewed, offline maintenance procedure with inventory verification and credential rotation. Merely editing the environment map does **not** silently rebind an existing sensor row. There is no remote re-enrollment capability. For recovery use approved local database maintenance and validated backups.

This feature does not attest sensor software, detect compromised sensor keys, provide IPS, or guarantee complete log coverage. Do not automatically isolate systems based only on sensor connectivity.
