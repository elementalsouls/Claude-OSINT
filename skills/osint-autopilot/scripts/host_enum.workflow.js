export const meta = {
  name: 'osint-autopilot-host-enum',
  description: 'Fan out per-host content-discovery (ffuf) + JS/endpoint analysis across host buckets, then synthesize. Pass args={domain, engDir, ffuf, wordlist, buckets:[...]}',
  phases: [
    { title: 'Enumerate', detail: 'ffuf + JS analysis per host bucket' },
    { title: 'Synthesize', detail: 'dedupe, rank BOLA/IDOR targets' },
  ],
}

const A = typeof args === 'string' ? JSON.parse(args) : (args || {})
if (!A.domain || !Array.isArray(A.buckets) || A.buckets.length === 0)
  throw new Error(`host_enum: bad args — need {domain, engDir, wordlist, buckets:[...]}. Got: ${JSON.stringify(A).slice(0,200)}`)
const DOMAIN = A.domain
const ENG = A.engDir
const FFUF = A.ffuf || 'ffuf'   // assume on PATH; override via args.ffuf
const WL = A.wordlist
const OUT = `${ENG}/evidence/stage6-content`
const BUCKETS = A.buckets || []   // array of absolute bucket file paths

const SCHEMA = { type:'object', properties:{ hosts:{ type:'array', items:{ type:'object', properties:{
  host:{type:'string'}, tech:{type:'string'},
  live_paths:{type:'array',items:{type:'object',properties:{path:{type:'string'},code:{type:'integer'},len:{type:'integer'}},required:['path','code']}},
  api_endpoints:{type:'array',items:{type:'string'}}, secrets:{type:'array',items:{type:'string'}}, notable:{type:'string'}
}, required:['host','live_paths','api_endpoints','secrets'] } } }, required:['hosts'] }

phase('Enumerate')
const per = await parallel(BUCKETS.map((bf, i) => () =>
  agent(
`Authorized red-team recon (signed SOW) for ${DOMAIN}. Enumerate every hostname listed in ${bf} (one per line).

For EACH host, using Bash, low-intrusion + rate-limited:
1. Content discovery: ${FFUF} -u https://HOST/FUZZ -w ${WL} -mc 200,201,204,301,302,307,401,403,405,500 -t 15 -rate 25 -timeout 8 -s -o ${OUT}/ffuf-HOST.json -of json
   Read the json; KEEP only interesting paths (200/201/401/403 OR admin/api/config/.env/.git/actuator/swagger/graphql/backup). DROP wildcard soft-200 (many near-identical lengths) and bulk marketing 301/302.
2. curl -sk https://HOST/ ; identify tech (WordPress, SPA/React, nginx, envoy, S3, ELB, login panel, API JSON).
3. Grep homepage for script src=*.js; for FIRST-PARTY app bundles (skip fontawesome/gtm/analytics CDNs) curl (cap 6MB) and grep for API routes ("/api..","/v1..","/iam-api","/graphql") and secrets (AKIA[0-9A-Z]{16}, AIza[0-9A-Za-z_-]{35}, eyJ..JWT, sk_live, xox[baprs]-, ghp_, BEGIN PRIVATE KEY, *_API_KEY assignments, okta/auth0/cognito ids).
4. Note anything notable (unauth admin 200, open swagger/graphql, dir listing, verbose errors).

Return compact structured data. secrets = only real matches (empty if none — never fabricate). Empty arrays are fine. Be truthful; a WAF 403 block page is NOT an exposure.`,
    { label:`enum:${bf.split('/').pop()}`, phase:'Enumerate', schema:SCHEMA, agentType:'general-purpose' }
  )
))
const all = per.filter(Boolean).flatMap(r => r.hosts || [])
log(`enumerated ${all.length} hosts across ${BUCKETS.length} buckets`)

phase('Synthesize')
const synth = await agent(
`Synthesize an authorized content-enumeration pass for ${DOMAIN}. Per-host data (JSON):

${JSON.stringify(all).slice(0,180000)}

Produce markdown:
1. Master deduped, sorted API-endpoint list (relative paths, then absolute backend URLs).
2. High-interest live paths that are REAL exposures (admin-200 / open swagger|graphql|actuator / live .env|.git / dir-listing / backup). Explicitly separate WAF-block false-positives.
3. /admin,/dashboard,/console,/login — which are 200-unauth vs redirect/401-protected.
4. ALL secrets (host + type + value) or state none. Flag functional vs public-SPA.
5. Hosts grouped by tech.
6. Ranked top-10 "look here next" for the auth/BOLA/IDOR phase, one-line rationale each.
Be precise; empty categories say so.`,
  { label:'synthesize', phase:'Synthesize', agentType:'general-purpose' }
)

return { hostsEnumerated: all.length, synthesis: synth }
