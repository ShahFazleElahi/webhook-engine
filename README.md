# Webhook Engine

HMAC-SHA256 webhook signing and verification primitives with freshness checks and optional single-process replay guard.

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white) ![License MIT](https://img.shields.io/badge/License-MIT-green)

## Quick start

Python 3.10+; standard library only. Clone or extract the repository, then run from its root.

```python
import secrets, time
from webhook import sign, verify, ReplayGuard

secret = secrets.token_bytes(32)  # store securely; share with receiver out of band
body = b'{"event":"invoice.created"}'
ts = int(time.time())
event_id = "evt_123"
sig = sign(secret, body, ts, event_id)
guard = ReplayGuard()
assert verify(secret, body, ts, event_id, sig)
assert guard.accept(event_id, ts)
```

Transport the timestamp, event ID and signature in your own documented headers. Verify against the exact raw request bytes before decoding JSON. Call replay guard only after verification.

## Scope and limitations

Custom signing format, not compatible by default with Stripe/GitHub/vendor webhook signatures. Does not deliver HTTP requests, retry or persist events. Replay guard is per process and fails closed at capacity; not suitable for distributed production without shared durable idempotency storage. Use one guard per sender scope and consistent tolerance; event processing and durable replay state should be coordinated transactionally. No secret rotation system. Use TLS and limit body size in your application.



## Development

```bash
python3 -m unittest discover -s tests -v
```



## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Please do not publish real credentials, customer data or sensitive reports in issues.

## License

MIT — see [LICENSE](LICENSE).
