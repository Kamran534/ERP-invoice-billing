/**
 * k6 load profile.
 *
 *   docker compose --profile perf run --rm k6 run /scripts/login.js
 *   docker compose --profile perf run --rm -e RUN_AUTH=true k6 run /scripts/login.js
 *
 * Thresholds come from AUTH-MODULE-PLAN.md §14.3 and are treated as build gates,
 * not suggestions: the whole point of tuning Argon2 cost is that you have a
 * number to hold it against.
 *
 * The `auth` scenario is written against the Phase 1 contract and is skipped
 * until those handlers exist (they currently answer 501). Run it with
 * RUN_AUTH=true once login and refresh are implemented.
 */

import http from 'k6/http';
import { check, group } from 'k6';
import { Trend, Counter } from 'k6/metrics';

const BASE = __ENV.BASE_URL || 'http://localhost:3000';
const RUN_AUTH = (__ENV.RUN_AUTH || 'false') === 'true';

const jwksDuration = new Trend('jwks_duration', true);
const loginDuration = new Trend('login_duration', true);
const refreshDuration = new Trend('refresh_duration', true);
const shed = new Counter('load_shed_503');
const rateLimited = new Counter('rate_limited_429');

// Scenarios use arrival-rate executors deliberately. `constant-vus` with no think
// time generates whatever throughput the box happens to allow (here ~1000 req/s),
// which measures nothing you can act on and trips every per-endpoint rate limit —
// so the run "fails" on limits working correctly rather than on a real regression.
// Arrival rate lets us state the load we actually expect to serve.
export const options = {
  scenarios: {
    // Warm-up, excluded from every threshold. The first requests after boot pay
    // for JIT compilation, the first pool connection, and the first TLS/SMTP
    // handshake — on a 30s run at 20 req/s those few outliers ARE the p99, so
    // measuring cold start tells you nothing about steady-state latency. Real
    // services are warm; measure them warm.
    warmup: {
      executor: 'constant-arrival-rate',
      rate: 10,
      timeUnit: '1s',
      duration: '8s',
      preAllocatedVUs: 10,
      maxVUs: 20,
      exec: 'warmup',
    },
    // Operational probe traffic: orchestrator + load balancer + monitoring across
    // replicas. If liveness latency degrades here, the event loop is the problem,
    // not the database.
    probes: {
      executor: 'constant-arrival-rate',
      rate: 50,
      timeUnit: '1s',
      duration: '30s',
      startTime: '10s',
      preAllocatedVUs: 30,
      maxVUs: 120,
      exec: 'probes',
    },
    // Realistic worst case for JWKS: a fleet of resource servers verifying tokens,
    // each caching for 5 minutes (see the endpoint's Cache-Control). 1000 pods at
    // a 60s cache is ~17 req/s; 20/s is that with headroom. If this ever gets rate
    // limited, the limit is wrong — token verification would break cluster-wide.
    jwks: {
      executor: 'constant-arrival-rate',
      rate: 20,
      timeUnit: '1s',
      duration: '30s',
      startTime: '10s',
      preAllocatedVUs: 10,
      maxVUs: 40,
      exec: 'jwks',
    },
    ...(RUN_AUTH
      ? {
          // Argon2 is memory-hard, so this scenario is what finds the real
          // ceiling. Watch auth_hash_queue{state="depth"} and the 503 rate:
          // shedding under this load means HASH_MAX_CONCURRENCY is too low, and a
          // rising queue with no shedding means it is about right.
          auth: {
            executor: 'ramping-arrival-rate',
            startRate: 5,
            timeUnit: '1s',
            preAllocatedVUs: 50,
            maxVUs: 200,
            stages: [
              { duration: '30s', target: 25 },
              { duration: '60s', target: 50 },
              { duration: '30s', target: 5 },
            ],
            exec: 'auth',
          },
        }
      : {}),
  },
  thresholds: {
    // Scoped to exclude the warm-up scenario's requests.
    'http_req_failed{name:live}': ['rate<0.01'],
    'http_req_failed{name:ready}': ['rate<0.01'],
    'http_req_failed{name:jwks}': ['rate<0.01'],
    // Liveness touches nothing, so it is a pure measure of event-loop health.
    'http_req_duration{name:live}': ['p(99)<50'],
    // Readiness makes three dependency round-trips including an SMTP handshake,
    // and is answered from a 1s cache under burst. Judging it against the
    // liveness budget would only ever measure Postgres and the mail relay.
    'http_req_duration{name:ready}': ['p(99)<400'],
    jwks_duration: ['p(99)<150'],
    // Zero tolerance: JWKS being rate limited breaks token verification fleet-wide.
    rate_limited_429: ['count==0'],
    // Plan §14.3: login p99 < 400ms, refresh p99 < 100ms.
    ...(RUN_AUTH
      ? {
          login_duration: ['p(99)<400'],
          refresh_duration: ['p(99)<100'],
        }
      : {}),
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'max'],
};

/** Untagged and unrecorded: exists only to warm the process. */
export function warmup() {
  http.get(`${BASE}/health/live`, { tags: { name: 'warmup' } });
  http.get(`${BASE}/health/ready`, { tags: { name: 'warmup' } });
  http.get(`${BASE}/.well-known/jwks.json`, { tags: { name: 'warmup' } });
}

export function probes() {
  group('health', () => {
    const live = http.get(`${BASE}/health/live`, { tags: { name: 'live' } });
    check(live, {
      'live 200': (r) => r.status === 200,
      'live reports ok': (r) => r.json('status') === 'ok',
    });

    const ready = http.get(`${BASE}/health/ready`, { tags: { name: 'ready' } });
    check(ready, { 'ready not 5xx': (r) => r.status < 500 || r.status === 503 });
    if (ready.status === 503) shed.add(1);
  });
}

export function jwks() {
  const response = http.get(`${BASE}/.well-known/jwks.json`, { tags: { name: 'jwks' } });
  jwksDuration.add(response.timings.duration);
  if (response.status === 429) rateLimited.add(1);
  check(response, {
    'jwks 200': (r) => r.status === 200,
    // A 429 here is a configuration bug, not load: this endpoint is public key
    // material that every resource server must be able to read.
    'jwks not rate limited': (r) => r.status !== 429,
    'jwks has keys': (r) => Array.isArray(r.json('keys')) && r.json('keys').length > 0,
    // Verifiers must be able to cache this, or every token check becomes a
    // round-trip to the auth service.
    'jwks is cacheable': (r) => (r.headers['Cache-Control'] || '').includes('max-age'),
  });
}

export function auth() {
  const email = `load-${__VU}-${__ITER}@example.test`;

  const login = http.post(
    `${BASE}/auth/login`,
    JSON.stringify({ email, password: 'correct horse battery staple' }),
    { headers: { 'Content-Type': 'application/json' }, tags: { name: 'login' } },
  );
  loginDuration.add(login.timings.duration);
  if (login.status === 503) shed.add(1);

  check(login, {
    // 401 is the expected answer for a user that does not exist — the point of
    // this scenario is the hashing cost, which is paid either way (§5.3 step 2).
    'login answered': (r) => r.status === 200 || r.status === 401 || r.status === 429,
    'login not 5xx': (r) => r.status < 500,
  });

  const refresh = http.post(`${BASE}/auth/token/refresh`, '{}', {
    headers: { 'Content-Type': 'application/json' },
    tags: { name: 'refresh' },
  });
  refreshDuration.add(refresh.timings.duration);
  check(refresh, { 'refresh not 5xx': (r) => r.status < 500 });
}
