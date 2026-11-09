# ColdFusion 2023 Scheduled Tasks Fail Silently: A Complete Troubleshooting Runbook

> A scheduled task "runs," shows its output in the admin, sends no email, writes no output file, and logs **no error** you would notice. On ColdFusion (CF) 2023 this is almost never one bug - it is usually a **stack** of independent causes, and the newest security feature (the outbound-network policy) masks the rest. This runbook walks all of them, in the order you should check, with the log signatures for each.

Tested against ColdFusion 2023 on Windows, with scheduled tasks that call the server's **own** URL over the built-in server (Tomcat) on port 8455. Paths assume a default `D:\ColdFusion2023` install; adjust for `<cf_home>`.

Placeholders used throughout: `cfserver.example.com` = your server's fully qualified domain name (FQDN); `<server-ip>` = the server's own interface Internet Protocol (IP) address; `<app>` = your application webroot folder; `<output-folder>` = where tasks save output; `<cf-service-account>` = the account the CF service runs as.

---

## 0. Why this is so confusing

Two facts make CF2023 scheduler failures hard to diagnose:

1. **A blocked outbound request logs but does not throw.** The task appears to run; there is no exception on the page. You only see it if you read `scheduler.log` / `exception.log`.
2. **There are two Java Virtual Machines (JVMs).** The CF **application** layer may run on one Java (e.g. an external Java Development Kit (JDK) 17), while **Tomcat** - the built-in web server that executes the outbound call and serves 8455 - runs on the **bundled Java Runtime Environment (JRE)** (often an older Java, e.g. Java 9). The runtime that makes the CFHTTP call validates Transport Layer Security (TLS) against **its own** truststore, which is easy to get wrong.

Because of (1), the policy at the top of this list hides every cause below it. Fix them in order and re-test after each.

---

## 1. Outbound network security policy (CF2023 SSRF protection)  [most common, and it masks everything else]

**Symptom:** task runs, no output, no error on the page. `scheduler.log` / `exception.log`:
```
Task ... suspended: This scheduled task URL is not permitted by the outbound network security policy.
   To allow this connection, add it to outboundNetwork.allowList in security-settings.json
   or to this.security.outboundNetwork.allowList in Application.cfc.
```
or
```
Blocked outbound request: destination resolves to a private, loopback, link-local, CGNAT,
   or cloud-metadata address (or could not be resolved).
```

**Cause:** CF2023 added Server-Side Request Forgery (SSRF) protection that blocks outbound HyperText Transfer Protocol (HTTP) requests to private / loopback / link-local addresses by default. A scheduled task that calls the server's **own** URL is the classic trigger: the host resolves to the box's **own local interface IP**, which the policy treats as a self / link-local destination and blocks.

**Where:** `<cf_home>\cfusion\lib\security-settings.json`, key `outboundNetwork`.

**Fix:** a working config for a task that calls the server itself:
```json
"outboundNetwork": {
    "defaultAction": "allow",
    "allowList": [ "https://cfserver.example.com:8455" ],
    "denyList": [],
    "blockPrivateNetworks": false,
    "blockLinkLocal": false,
    "blockMetadataServices": true
}
```
- The **decisive** setting for a self-call to a local interface is **`blockLinkLocal: false`** (and/or `blockPrivateNetworks: false` if the target is on a private subnet).
- **Keep `blockMetadataServices: true`.** That still blocks `169.254.169.254` (the cloud-metadata endpoint) - the SSRF protection that matters most on any cloud host. You are permitting your own host, not disabling the feature.
- The `allowList` entry format is poorly documented. If a URL-form entry does not match, try the bare hostname and host:port forms as well. But note: with `defaultAction: allow` and the block flags relaxed, scheduled tasks to a self/local target are what `blockLinkLocal` governs - that is usually the real lever, not the allowList.

**Restart ColdFusion** (this file is read at startup). Re-test before moving on - this unmasks the rest.

---

## 2. Certificate trust in the runtime that makes the CFHTTP call

**Symptom:** `errorDetail` in the CFHTTP result contains `PKIX`, `unable to find valid certification path`, or `SSL handshake` - or the scheduled output shows `Connection Failure`. The page loads fine in a **browser** but the scheduler fails (browser uses the Operating System (OS) trust store; CFHTTP uses the JVM truststore).

**Cause and the common trap:** the cert the target presents must be in the cacerts of **the JVM that runs the CFHTTP call** - which is the **Tomcat / bundled JRE**, not necessarily the external JDK your apps run on. Importing into the wrong JVM's cacerts looks correct and still fails.

**Fix:**
1. Identify the runtime. A quick page that dumps `createObject("java","java.lang.System").getProperty("java.home")` shows the **application** JVM; but the outbound call may run on the bundled JRE at `<cf_home>\jre`. Import into **both** to be safe.
2. Import the target's leaf certificate (or its issuing Certificate Authority (CA) chain) into the bundled JRE store using **that JRE's** keytool:
```
"<cf_home>\jre\bin\keytool.exe" -importcert -noprompt -trustcacerts ^
   -alias cfserver-leaf -file cfserver.cer ^
   -keystore "<cf_home>\jre\lib\security\cacerts" -storepass changeit
```
3. Verify: `keytool -list -keystore "<cf_home>\jre\lib\security\cacerts" -storepass changeit | findstr /i cfserver`
4. **Restart ColdFusion** - the running JVM holds whatever truststore it loaded at startup.

Confirm trust independently of path issues by running a CFHTTP page that hits a known-good URL on the same host:port and dumping the full `cfhttp` result; an empty `errorDetail` with a real HTTP status code (even a 404) proves TLS/trust is fine.

---

## 3. The built-in server (Tomcat) cannot find your app path

**Symptom:** `coldfusion.runtime.TemplateNotFoundException: File not found: /<app>/...` even though the file exists on disk. Browser may 404 with a plain Tomcat page.

**Cause:** the CF **built-in server** (8455) serves only its own webroot `<cf_home>\cfusion\wwwroot`. Your application living under, say, `E:\websites\<app>` is **not** automatically served there - that mapping exists in your front web server (e.g. Internet Information Services (IIS)), not in Tomcat.

**Fix (any one):**

- A filesystem **junction/symlink** under wwwroot (simplest, and what many working servers use). Run in an **elevated** shell; the link path must not already exist. `/J` = directory junction, link path first, target second:
  - Command Prompt (`mklink` is a cmd built-in):
    ```
    mklink /J "<cf_home>\cfusion\wwwroot\<app>" "E:\websites\<app>"
    ```
  - PowerShell (`mklink` is not a cmdlet - wrap it in cmd):
    ```
    cmd /c mklink /J "<cf_home>\cfusion\wwwroot\<app>" "E:\websites\<app>"
    ```
  - PowerShell (native cmdlet):
    ```
    New-Item -ItemType Junction -Path "<cf_home>\cfusion\wwwroot\<app>" -Target "E:\websites\<app>"
    ```
- A `<Context path="/<app>" docBase="E:\websites\<app>"/>` under `<Host>` in `server.xml`.
- A context descriptor `<cf_home>\cfusion\runtime\conf\Catalina\localhost\<app>.xml`.

Compare a known-good server (e.g. staging) to see which mechanism it uses. Restart CF after.

---

## 4. The task URL itself: port doubling and special characters

Two URL mistakes that produce 404 / not-found even when everything else is right:

- **Doubled port.** In the task, the port can be supplied in the URL **or** in the task's `httpPort` field - not both. Setting both yields a malformed authority like `host:8455:8455`. Pick one: port in the URL with `httpPort` at its default, **or** host-only URL with `httpPort` set.
- **Special characters in the path.** If a folder or file name contains a character like `$`, URL-encode it (`$` -> `%24`). A literal `$` in the stored URL may not resolve the same way a browser handles it. Match a known-good server's exact encoding.

Export the task definitions (e.g. from CommandBox or `neo-cron.xml`) from a **working** server and diff the URL format against your broken one - that is the fastest way to spot both issues.

---

## 5. Output-file allowlist (pathfilter.json) and the slash-direction trap

**Symptom:** task runs and completes, but the "save output to a file" does not write; sometimes a log line `The specified path: ... is not allowed for scheduled tasks.`

**Cause:** CF2023 restricts where a scheduled task may write output via `<cf_home>\cfusion\lib\pathfilter.json`, key `schedulerexecutionpaths`. The output path must be allowlisted - **and the separator must match.**

**The trap:** the CF Admin scheduled-task **output path field wants Windows backslashes** (it errors on forward slashes), while Adobe's `pathfilter.json` examples use **forward slashes**. If CF compares the stored (backslash) path literally against a forward-slash allowlist entry, it will not match. Cover both:
```
"schedulerexecutionpaths": "E:/TaskOutput/scheduled_tasks/**;E:\\TaskOutput\\scheduled_tasks\\**;"
```
(`/**` allows the folder and subfolders; backslashes doubled because it is JavaScript Object Notation (JSON).)

Also confirm the CF **service account** (`<cf-service-account>`) has write permission to the output folder. Validate the file itself: no Byte Order Mark (BOM), no "smart quotes," valid JSON - a malformed `pathfilter.json` makes CF silently reject **all** paths. **Restart CF** after editing.

---

## 6. Connector reachable by name (for self-calls on a domain-joined host)

If the scheduler calls the server by name and the 8455 connector is bound to loopback (`address="127.0.0.1"`), a domain-joined Windows host answers its own name from its interface IPs and cannot reach a loopback-only connector by name. Bind the connector to an interface IP in `server.xml` (`address="<server-ip>"`) and let the host firewall / security group control exposure. Restart CF.

---

## Verification checklist

Work top to bottom; re-test after each since (1) masks the rest:

- [ ] `scheduler.log` shows no `not permitted by the outbound network security policy` after a restart.
- [ ] A CFHTTP test page to a real file on `https://cfserver.example.com:8455/...` returns `statusCode 200` with empty `errorDetail`.
- [ ] No `TemplateNotFoundException` for the app path (junction/context in place).
- [ ] Task URL has a single port and correct `%`-encoding.
- [ ] `pathfilter.json` allows the output folder (both separators), valid JSON, service account can write.
- [ ] Run Now a task -> the output file writes and ends with the task's success marker.

## The short version

1. CF2023's outbound SSRF policy (`security-settings.json`) blocks self-calls to a local/link-local address - set `blockLinkLocal: false`, keep `blockMetadataServices: true`. **This masks everything else.**
2. CFHTTP trust lives in the **Tomcat / bundled JRE** cacerts, not necessarily the app's JDK.
3. The built-in server needs a **junction/context** to serve your app webroot.
4. Task URL: **one** port, and URL-encode special characters (`$` -> `%24`).
5. `pathfilter.json` must allow the output folder - watch the **backslash vs forward-slash** mismatch.
6. **Every** one of these config files is read at startup - restart ColdFusion after each change, and remember: a blocked outbound call **logs, it does not throw**.

---

*Contributed from a production ColdFusion 2023 migration. Paths and ports reflect a default Windows install; adapt to your environment.*
