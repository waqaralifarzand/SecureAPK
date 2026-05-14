"""Catalog of vulnerability detection patterns for the source analyzer.

Each entry is regex-driven, severity-tagged, mapped to OWASP MTW10 (2024) +
CWE, and ships with a *complete* `remediation` dict (vulnerable_snippet,
fixed_snippet, explanation). Phase 8 (Educational Mode) reads the
remediation content directly — no entry may omit it. A test in
`tests/test_source_analyzer.py` enforces the contract.

Coverage required by ARCHITECTURE.md sec 9 + CLAUDE.md sec 6:
    - 30+ patterns total
    - exactly 9 categories
    - the 9 categories are the literal strings asserted at the bottom

Data only — no logic.
"""
from __future__ import annotations


# The 9 canonical categories. Kept as a tuple so the integrity assertion
# below can compare against it exactly.
CATEGORIES: tuple[str, ...] = (
    "Hardcoded Secrets",
    "Insecure Communication",
    "Weak Cryptography",
    "Insecure Data Storage",
    "Information Leakage",
    "WebView Security",
    "Code Execution",
    "IPC Security",
    "SSL/TLS Validation Bypass",
)


VULN_PATTERNS: list[dict] = [
    # ===================================================================
    # 1. Hardcoded Secrets
    # ===================================================================
    {
        "id": "HARDCODED_GOOGLE_API_KEY",
        "category": "Hardcoded Secrets",
        "severity": "HIGH",
        "regex": r"AIza[0-9A-Za-z\-_]{35}",
        "title": "Hardcoded Google API Key",
        "description": "A Google API key was embedded directly in source code. "
                       "Any user who unzips the APK can read it.",
        "owasp_id": "M1",
        "cwe_id": "CWE-798",
        "remediation": {
            "vulnerable_snippet": 'String apiKey = "AIzaSyB-1aBcDeFgHiJkLmNoPqRsTuVwXyZ0123";',
            "fixed_snippet": (
                "// Load from secure config / BuildConfig, never inline:\n"
                "String apiKey = BuildConfig.GOOGLE_API_KEY;\n"
                "// gradle: buildConfigField(\"String\", \"GOOGLE_API_KEY\","
                "\"\\\"${System.getenv(\\\"GOOGLE_API_KEY\\\")}\\\"\")"
            ),
            "explanation": (
                "API keys baked into source code are visible to anyone who "
                "decompiles the APK. They should be loaded from build "
                "configuration, the Android Keystore, or a server at runtime "
                "— never compiled into the binary."
            ),
        },
    },
    {
        "id": "HARDCODED_AWS_ACCESS_KEY",
        "category": "Hardcoded Secrets",
        "severity": "HIGH",
        "regex": r"AKIA[0-9A-Z]{16}",
        "title": "Hardcoded AWS Access Key ID",
        "description": "An AWS access key identifier was found in source code.",
        "owasp_id": "M1",
        "cwe_id": "CWE-798",
        "remediation": {
            "vulnerable_snippet": 'String awsKey = "AKIAIOSFODNN7EXAMPLE";',
            "fixed_snippet": (
                "// Use Cognito Identity Pools or STS for short-lived credentials.\n"
                "AWSCredentialsProvider provider = new CognitoCachingCredentialsProvider(\n"
                "    context, \"us-east-1:xxxx-xxxx\", Regions.US_EAST_1);"
            ),
            "explanation": (
                "Long-lived AWS access keys in mobile binaries grant attackers "
                "direct access to your cloud account. Use temporary, "
                "user-scoped credentials issued by Cognito or STS."
            ),
        },
    },
    {
        "id": "HARDCODED_FIREBASE_URL",
        "category": "Hardcoded Secrets",
        "severity": "MEDIUM",
        "regex": r"https?://[a-z0-9\-]+\.firebaseio\.com",
        "title": "Hardcoded Firebase Database URL",
        "description": "A Firebase Realtime Database URL is embedded. If the "
                       "database has permissive rules this is a data-leak risk.",
        "owasp_id": "M8",
        "cwe_id": "CWE-200",
        "remediation": {
            "vulnerable_snippet": 'String url = "https://myapp-prod.firebaseio.com";',
            "fixed_snippet": (
                "// Load from google-services.json + tighten Firebase security rules:\n"
                "FirebaseDatabase db = FirebaseDatabase.getInstance();"
            ),
            "explanation": (
                "Firebase URLs aren't strictly secret, but combined with "
                "permissive default security rules they often expose user "
                "data. Audit your rules and prefer authenticated access."
            ),
        },
    },
    {
        "id": "HARDCODED_GENERIC_PASSWORD",
        "category": "Hardcoded Secrets",
        "severity": "HIGH",
        "regex": r"(?i)(password|passwd|pwd)\s*=\s*\"[^\"\s]{4,}\"",
        "title": "Hardcoded Password Literal",
        "description": "A string literal that looks like a password was assigned to "
                       "a variable named password/passwd/pwd.",
        "owasp_id": "M1",
        "cwe_id": "CWE-259",
        "remediation": {
            "vulnerable_snippet": 'String password = "Admin@123";',
            "fixed_snippet": (
                "// Read from EncryptedSharedPreferences or Android Keystore:\n"
                "String password = encryptedPrefs.getString(\"db_password\", null);"
            ),
            "explanation": (
                "Hardcoded passwords are extracted in seconds with any APK "
                "unzip tool. Store secrets in EncryptedSharedPreferences, the "
                "Android Keystore, or fetch them from a server post-auth."
            ),
        },
    },
    {
        "id": "HARDCODED_JWT_TOKEN",
        "category": "Hardcoded Secrets",
        "severity": "HIGH",
        "regex": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "title": "Hardcoded JWT Token",
        "description": "A JSON Web Token appears to be embedded as a literal.",
        "owasp_id": "M1",
        "cwe_id": "CWE-798",
        "remediation": {
            "vulnerable_snippet": 'String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4eHgifQ.sig";',
            "fixed_snippet": (
                "// Acquire tokens at runtime via your auth endpoint and cache "
                "in encrypted storage:\n"
                "String token = authClient.signIn(user, pass).blockingGet();"
            ),
            "explanation": (
                "Embedded JWTs grant the bearer everything the token's scope "
                "allows. Acquire tokens at runtime and rotate them."
            ),
        },
    },

    # ===================================================================
    # 2. Insecure Communication
    # ===================================================================
    {
        "id": "HTTP_URL_LITERAL",
        "category": "Insecure Communication",
        "severity": "HIGH",
        "regex": r"\"http://[^\"\s]+\"",
        "title": "Cleartext HTTP URL Used",
        "description": "A literal http:// URL was found in source. Traffic to "
                       "this endpoint is transmitted unencrypted.",
        "owasp_id": "M5",
        "cwe_id": "CWE-319",
        "remediation": {
            "vulnerable_snippet": 'String api = "http://api.example.com/login";',
            "fixed_snippet": 'String api = "https://api.example.com/login";',
            "explanation": (
                "Cleartext HTTP exposes credentials, tokens, and personal data "
                "to anyone on the network path. Always use HTTPS and enforce "
                "it with a networkSecurityConfig."
            ),
        },
    },
    {
        "id": "ALLOW_ALL_HOSTNAME_VERIFIER",
        "category": "Insecure Communication",
        "severity": "HIGH",
        "regex": r"ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier",
        "title": "Hostname Verification Disabled",
        "description": "ALLOW_ALL_HOSTNAME_VERIFIER accepts any TLS hostname, "
                       "defeating server identity verification.",
        "owasp_id": "M5",
        "cwe_id": "CWE-297",
        "remediation": {
            "vulnerable_snippet": (
                "HttpsURLConnection.setDefaultHostnameVerifier(\n"
                "    SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);"
            ),
            "fixed_snippet": (
                "// Default verifier validates CN/SAN against the URL host.\n"
                "// Do not override it."
            ),
            "explanation": (
                "Disabling hostname verification means any valid TLS "
                "certificate — even one for an attacker's domain — will be "
                "accepted, enabling trivial MITM attacks."
            ),
        },
    },
    {
        "id": "WEBSOCKET_INSECURE_URL",
        "category": "Insecure Communication",
        "severity": "MEDIUM",
        "regex": r"\"ws://[^\"\s]+\"",
        "title": "Insecure WebSocket URL",
        "description": "A ws:// (unencrypted WebSocket) URL was found. Use wss://.",
        "owasp_id": "M5",
        "cwe_id": "CWE-319",
        "remediation": {
            "vulnerable_snippet": 'WebSocket ws = client.newWebSocket(new Request.Builder()\n    .url("ws://example.com/chat").build(), listener);',
            "fixed_snippet": 'WebSocket ws = client.newWebSocket(new Request.Builder()\n    .url("wss://example.com/chat").build(), listener);',
            "explanation": (
                "WebSocket traffic over ws:// is plaintext and trivially "
                "snoopable on a hostile network. Use wss:// (TLS-wrapped)."
            ),
        },
    },
    {
        "id": "FTP_URL_LITERAL",
        "category": "Insecure Communication",
        "severity": "MEDIUM",
        "regex": r"\"ftp://[^\"\s]+\"",
        "title": "Cleartext FTP URL Used",
        "description": "FTP transmits credentials and data in cleartext.",
        "owasp_id": "M5",
        "cwe_id": "CWE-319",
        "remediation": {
            "vulnerable_snippet": 'String dest = "ftp://files.example.com/upload";',
            "fixed_snippet": 'String dest = "sftp://files.example.com/upload";  // or https://...',
            "explanation": (
                "FTP has no transport encryption. Use SFTP, FTPS, or "
                "HTTPS uploads instead."
            ),
        },
    },

    # ===================================================================
    # 3. Weak Cryptography
    # ===================================================================
    {
        "id": "WEAK_HASH_MD5",
        "category": "Weak Cryptography",
        "severity": "HIGH",
        "regex": r"MessageDigest\.getInstance\(\s*\"MD5\"\s*\)",
        "title": "MD5 Hash Used",
        "description": "MD5 is cryptographically broken. Collisions are trivial "
                       "to generate; it must not be used for security purposes.",
        "owasp_id": "M10",
        "cwe_id": "CWE-327",
        "remediation": {
            "vulnerable_snippet": 'MessageDigest md = MessageDigest.getInstance("MD5");',
            "fixed_snippet": 'MessageDigest md = MessageDigest.getInstance("SHA-256");',
            "explanation": (
                "MD5 collisions can be computed in seconds on commodity "
                "hardware. Use SHA-256 (or SHA-3) for hashes, and bcrypt / "
                "Argon2 for passwords."
            ),
        },
    },
    {
        "id": "WEAK_HASH_SHA1",
        "category": "Weak Cryptography",
        "severity": "HIGH",
        "regex": r"MessageDigest\.getInstance\(\s*\"SHA-?1\"\s*\)",
        "title": "SHA-1 Hash Used",
        "description": "SHA-1 is no longer collision-resistant.",
        "owasp_id": "M10",
        "cwe_id": "CWE-327",
        "remediation": {
            "vulnerable_snippet": 'MessageDigest md = MessageDigest.getInstance("SHA-1");',
            "fixed_snippet": 'MessageDigest md = MessageDigest.getInstance("SHA-256");',
            "explanation": (
                "SHAttered demonstrated practical SHA-1 collisions in 2017. "
                "Migrate to SHA-256 or stronger."
            ),
        },
    },
    {
        "id": "DES_CIPHER",
        "category": "Weak Cryptography",
        "severity": "HIGH",
        "regex": r"Cipher\.getInstance\(\s*\"DES",
        "title": "DES Cipher Used",
        "description": "DES has a 56-bit effective key and is broken.",
        "owasp_id": "M10",
        "cwe_id": "CWE-327",
        "remediation": {
            "vulnerable_snippet": 'Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");',
            "fixed_snippet": 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");',
            "explanation": (
                "DES can be brute-forced in hours. Use AES-GCM with a "
                "256-bit key for authenticated encryption."
            ),
        },
    },
    {
        "id": "AES_ECB_MODE",
        "category": "Weak Cryptography",
        "severity": "HIGH",
        "regex": r"Cipher\.getInstance\(\s*\"AES/ECB",
        "title": "AES in ECB Mode",
        "description": "ECB mode reveals patterns in plaintext (same block -> "
                       "same ciphertext). Use an authenticated mode like GCM.",
        "owasp_id": "M10",
        "cwe_id": "CWE-327",
        "remediation": {
            "vulnerable_snippet": 'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");',
            "fixed_snippet": 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");',
            "explanation": (
                "ECB encrypts identical plaintext blocks to identical "
                "ciphertext, leaking structure (think the famous ECB-encrypted "
                "Tux). Use GCM or CBC with random IV + HMAC."
            ),
        },
    },
    {
        "id": "INSECURE_RANDOM",
        "category": "Weak Cryptography",
        "severity": "MEDIUM",
        "regex": r"\bnew\s+Random\s*\(",
        "title": "Insecure Random Used for Crypto Context",
        "description": "java.util.Random is not cryptographically secure. "
                       "Use SecureRandom for tokens, keys, nonces, IVs.",
        "owasp_id": "M10",
        "cwe_id": "CWE-338",
        "remediation": {
            "vulnerable_snippet": "byte[] iv = new byte[16];\nnew Random().nextBytes(iv);",
            "fixed_snippet": "byte[] iv = new byte[16];\nnew SecureRandom().nextBytes(iv);",
            "explanation": (
                "java.util.Random is a linear congruential generator — "
                "predictable from a few outputs. Use SecureRandom anywhere "
                "an attacker could observe or guess values."
            ),
        },
    },

    # ===================================================================
    # 4. Insecure Data Storage
    # ===================================================================
    {
        "id": "WORLD_READABLE_PREFS",
        "category": "Insecure Data Storage",
        "severity": "HIGH",
        "regex": r"MODE_WORLD_READABLE",
        "title": "World-Readable Storage Mode",
        "description": "MODE_WORLD_READABLE lets any app on the device read your "
                       "files. Deprecated since API 17.",
        "owasp_id": "M9",
        "cwe_id": "CWE-276",
        "remediation": {
            "vulnerable_snippet": 'SharedPreferences p = getSharedPreferences("u", MODE_WORLD_READABLE);',
            "fixed_snippet": (
                "SharedPreferences p = EncryptedSharedPreferences.create(\n"
                "    context, \"u\", masterKey,\n"
                "    PrefKeyEncryptionScheme.AES256_SIV,\n"
                "    PrefValueEncryptionScheme.AES256_GCM);"
            ),
            "explanation": (
                "Any installed app on the device could read these files. "
                "Use MODE_PRIVATE, and for sensitive values wrap in "
                "EncryptedSharedPreferences."
            ),
        },
    },
    {
        "id": "WORLD_WRITABLE_PREFS",
        "category": "Insecure Data Storage",
        "severity": "HIGH",
        "regex": r"MODE_WORLD_WRITEABLE",
        "title": "World-Writable Storage Mode",
        "description": "MODE_WORLD_WRITEABLE lets any app on the device modify "
                       "your files — catastrophic for integrity.",
        "owasp_id": "M9",
        "cwe_id": "CWE-732",
        "remediation": {
            "vulnerable_snippet": 'FileOutputStream f = openFileOutput("u.txt", MODE_WORLD_WRITEABLE);',
            "fixed_snippet": 'FileOutputStream f = openFileOutput("u.txt", MODE_PRIVATE);',
            "explanation": (
                "Allowing any app to write your files means a malicious app "
                "can replace credentials, configuration, or cached data."
            ),
        },
    },
    {
        "id": "EXTERNAL_STORAGE_WRITE",
        "category": "Insecure Data Storage",
        "severity": "MEDIUM",
        "regex": r"getExternalStorage(?:Directory|PublicDirectory)\s*\(",
        "title": "Data Written to External Storage",
        "description": "External storage is world-readable on legacy Android.",
        "owasp_id": "M9",
        "cwe_id": "CWE-200",
        "remediation": {
            "vulnerable_snippet": 'File f = new File(Environment.getExternalStorageDirectory(), "auth.json");',
            "fixed_snippet": 'File f = new File(context.getFilesDir(), "auth.json");',
            "explanation": (
                "External storage was historically world-readable. Use the "
                "app's internal storage (getFilesDir()) or scoped storage "
                "for sensitive data."
            ),
        },
    },
    {
        "id": "SQLITE_RAW_QUERY",
        "category": "Insecure Data Storage",
        "severity": "MEDIUM",
        "regex": r"rawQuery\s*\(\s*\".*\"\s*\+\s*",
        "title": "SQL Concatenation in rawQuery (Injection Risk)",
        "description": "Concatenating user input into rawQuery enables SQL injection.",
        "owasp_id": "M4",
        "cwe_id": "CWE-89",
        "remediation": {
            "vulnerable_snippet": 'db.rawQuery("SELECT * FROM u WHERE name=\'" + name + "\'", null);',
            "fixed_snippet": 'db.rawQuery("SELECT * FROM u WHERE name=?", new String[]{name});',
            "explanation": (
                "User-controlled values must be passed as parameters, not "
                "concatenated into SQL strings, to prevent SQL injection."
            ),
        },
    },

    # ===================================================================
    # 5. Information Leakage (logs)
    # ===================================================================
    {
        "id": "LOG_PASSWORD",
        "category": "Information Leakage",
        "severity": "HIGH",
        "regex": r"Log\.[a-z]\s*\([^)]*(?i:password|passwd|pwd|token|secret)",
        "title": "Sensitive Data Logged",
        "description": "Sensitive keyword is being passed to Android logcat.",
        "owasp_id": "M9",
        "cwe_id": "CWE-532",
        "remediation": {
            "vulnerable_snippet": 'Log.d("auth", "Logging in with password=" + password);',
            "fixed_snippet": 'Log.d("auth", "Login attempt for user " + user);  // never log secrets',
            "explanation": (
                "logcat is readable by other apps with READ_LOGS on older "
                "Android and by anyone with adb on debuggable builds. Never "
                "log credentials, tokens, or session keys."
            ),
        },
    },
    {
        "id": "LOG_PRINTSTACKTRACE",
        "category": "Information Leakage",
        "severity": "LOW",
        "regex": r"\.printStackTrace\s*\(\s*\)",
        "title": "printStackTrace() Used",
        "description": "Exception stack traces leaked to logcat reveal internal "
                       "class structure and may aid an attacker.",
        "owasp_id": "M9",
        "cwe_id": "CWE-209",
        "remediation": {
            "vulnerable_snippet": "} catch (IOException e) {\n    e.printStackTrace();\n}",
            "fixed_snippet": "} catch (IOException e) {\n    // Use a logging framework with build-flavour-aware filtering.\n    Log.w(TAG, \"network error\", e);\n}",
            "explanation": (
                "printStackTrace dumps to System.err which becomes logcat on "
                "Android. Use a controlled logger that can be silenced in "
                "release builds."
            ),
        },
    },
    {
        "id": "SYSTEM_OUT_PRINT",
        "category": "Information Leakage",
        "severity": "LOW",
        "regex": r"System\.(out|err)\.print(?:ln)?\s*\(",
        "title": "System.out / System.err Used",
        "description": "Output goes to logcat on Android and is often left in "
                       "release builds.",
        "owasp_id": "M9",
        "cwe_id": "CWE-532",
        "remediation": {
            "vulnerable_snippet": 'System.out.println("debug user=" + user);',
            "fixed_snippet": 'if (BuildConfig.DEBUG) Log.d(TAG, "user=" + user);',
            "explanation": (
                "System.out/err writes to logcat on Android. Gate diagnostic "
                "output behind BuildConfig.DEBUG so it ships disabled in "
                "release builds."
            ),
        },
    },

    # ===================================================================
    # 6. WebView Security
    # ===================================================================
    {
        "id": "WEBVIEW_JS_ENABLED",
        "category": "WebView Security",
        "severity": "MEDIUM",
        "regex": r"\.setJavaScriptEnabled\s*\(\s*true\s*\)",
        "title": "WebView JavaScript Enabled",
        "description": "JavaScript is enabled in a WebView. Combined with "
                       "loaded HTTP content this widens the XSS attack surface.",
        "owasp_id": "M4",
        "cwe_id": "CWE-79",
        "remediation": {
            "vulnerable_snippet": "webView.getSettings().setJavaScriptEnabled(true);",
            "fixed_snippet": (
                "// Only enable JS if absolutely required, and only load HTTPS content:\n"
                "webView.getSettings().setJavaScriptEnabled(needsJs);\n"
                "webView.getSettings().setMixedContentMode(\n"
                "    WebSettings.MIXED_CONTENT_NEVER_ALLOW);"
            ),
            "explanation": (
                "Enabling JS in a WebView that loads untrusted content lets "
                "an attacker run script with your app's WebView privileges. "
                "Disable it unless required, and lock down mixed content."
            ),
        },
    },
    {
        "id": "WEBVIEW_ADD_JS_INTERFACE",
        "category": "WebView Security",
        "severity": "HIGH",
        "regex": r"\.addJavascriptInterface\s*\(",
        "title": "WebView JavaScript-to-Java Bridge",
        "description": "addJavascriptInterface exposes a Java object to in-page "
                       "JavaScript — historically a remote-code-execution vector.",
        "owasp_id": "M4",
        "cwe_id": "CWE-749",
        "remediation": {
            "vulnerable_snippet": 'webView.addJavascriptInterface(new JsBridge(), "Android");',
            "fixed_snippet": (
                "// Prefer postMessage / @JavascriptInterface-annotated, minimum-surface objects.\n"
                "// And only register on trusted (your own) HTTPS origins."
            ),
            "explanation": (
                "Before API 17, addJavascriptInterface allowed full "
                "reflection from JS to Java — trivial RCE if the WebView "
                "loaded any attacker-influenced URL. Always pair with strict "
                "URL allowlisting and minimum-surface bridge methods."
            ),
        },
    },
    {
        "id": "WEBVIEW_FILE_ACCESS",
        "category": "WebView Security",
        "severity": "MEDIUM",
        "regex": r"\.setAllowFileAccess(?:FromFileURLs|FromFileURLs)?\s*\(\s*true\s*\)",
        "title": "WebView File Access Allowed",
        "description": "Allowing file:// access in a WebView lets remote pages "
                       "read local files via redirects.",
        "owasp_id": "M4",
        "cwe_id": "CWE-200",
        "remediation": {
            "vulnerable_snippet": "webView.getSettings().setAllowFileAccessFromFileURLs(true);",
            "fixed_snippet": "webView.getSettings().setAllowFileAccessFromFileURLs(false);",
            "explanation": (
                "Allowing file URLs to script other file URLs has been used "
                "to exfiltrate local SharedPreferences and database files."
            ),
        },
    },

    # ===================================================================
    # 7. Code Execution
    # ===================================================================
    {
        "id": "RUNTIME_EXEC",
        "category": "Code Execution",
        "severity": "HIGH",
        "regex": r"Runtime\.getRuntime\(\)\.exec\s*\(",
        "title": "Runtime.exec() Used",
        "description": "Runtime.exec() spawns shell processes. Concatenating "
                       "user input here is a classic command-injection vector.",
        "owasp_id": "M4",
        "cwe_id": "CWE-78",
        "remediation": {
            "vulnerable_snippet": 'Runtime.getRuntime().exec("ping " + userHost);',
            "fixed_snippet": (
                "// Use a typed library API for the operation, or "
                "ProcessBuilder with an explicit argv list:\n"
                "ProcessBuilder pb = new ProcessBuilder(\"ping\", userHost);\n"
                "// + validate userHost against an allowlist first."
            ),
            "explanation": (
                "exec(String) goes through /bin/sh, so any shell metacharacter "
                "in user input becomes an attacker-controlled command. Use "
                "ProcessBuilder with separate argv elements and validate input."
            ),
        },
    },
    {
        "id": "PROCESS_BUILDER",
        "category": "Code Execution",
        "severity": "MEDIUM",
        "regex": r"new\s+ProcessBuilder\s*\(",
        "title": "ProcessBuilder Spawned",
        "description": "Spawning external processes on Android is rarely needed. "
                       "Review whether user input ever reaches the argument list.",
        "owasp_id": "M4",
        "cwe_id": "CWE-78",
        "remediation": {
            "vulnerable_snippet": "ProcessBuilder pb = new ProcessBuilder(\"sh\", \"-c\", cmd);",
            "fixed_snippet": (
                "// Replace shell invocation with the appropriate Android API,\n"
                "// or use ProcessBuilder with a fixed argv and validated parameters."
            ),
            "explanation": (
                "Even ProcessBuilder can be abused when arguments contain "
                "user input — particularly when called with sh -c. Use "
                "first-class APIs instead."
            ),
        },
    },
    {
        "id": "REFLECTION_INVOKE",
        "category": "Code Execution",
        "severity": "LOW",
        "regex": r"Method\.invoke\s*\(",
        "title": "Reflection invoke() Used",
        "description": "Method.invoke() can call arbitrary methods. Review "
                       "whether the method name is influenced by untrusted input.",
        "owasp_id": "M4",
        "cwe_id": "CWE-470",
        "remediation": {
            "vulnerable_snippet": (
                "Class<?> c = Class.forName(userClass);\n"
                "c.getMethod(userMethod).invoke(c.newInstance());"
            ),
            "fixed_snippet": (
                "// Replace reflection with a typed dispatch table:\n"
                "Map<String, Runnable> handlers = Map.of(\"sync\", this::sync, \"clear\", this::clear);\n"
                "handlers.get(action).run();"
            ),
            "explanation": (
                "Reflection driven by user input is one of the easiest paths "
                "to arbitrary code execution. Use a fixed dispatch table."
            ),
        },
    },
    {
        "id": "DEX_CLASS_LOADER",
        "category": "Code Execution",
        "severity": "HIGH",
        "regex": r"new\s+DexClassLoader\s*\(",
        "title": "Dynamic Class Loading via DexClassLoader",
        "description": "Loading DEX files at runtime defeats static analysis and "
                       "code-signing guarantees.",
        "owasp_id": "M7",
        "cwe_id": "CWE-829",
        "remediation": {
            "vulnerable_snippet": 'new DexClassLoader(downloadedDex, optDir, null, parent);',
            "fixed_snippet": (
                "// Avoid loading code that wasn't part of the signed APK.\n"
                "// If unavoidable, verify a signature you control before loading."
            ),
            "explanation": (
                "Runtime DEX loading lets attackers (or a compromised CDN) "
                "swap in malicious code that bypasses Play Protect and your "
                "app signature."
            ),
        },
    },

    # ===================================================================
    # 8. IPC Security
    # ===================================================================
    {
        "id": "IMPLICIT_INTENT",
        "category": "IPC Security",
        "severity": "MEDIUM",
        "regex": r"new\s+Intent\s*\(\s*\"[^\"]+\"\s*\)",
        "title": "Implicit Intent Constructed",
        "description": "Implicit intents can be intercepted by any app declaring "
                       "a matching intent-filter.",
        "owasp_id": "M8",
        "cwe_id": "CWE-927",
        "remediation": {
            "vulnerable_snippet": 'Intent i = new Intent("com.example.ACTION_SEND_TOKEN");\nstartActivity(i);',
            "fixed_snippet": (
                "Intent i = new Intent(this, TargetActivity.class);  // explicit\n"
                "// or restrict with i.setPackage(\"com.example\")"
            ),
            "explanation": (
                "Other apps can register matching intent-filters and silently "
                "intercept your data. Use explicit intents (target class) or "
                "setPackage to bind the intent to a specific recipient."
            ),
        },
    },
    {
        "id": "BROADCAST_NO_PERM",
        "category": "IPC Security",
        "severity": "MEDIUM",
        "regex": r"sendBroadcast\s*\(\s*[a-zA-Z_]\w*\s*\)",
        "title": "Broadcast Without Permission",
        "description": "sendBroadcast() without a receiverPermission can be "
                       "received by any app.",
        "owasp_id": "M8",
        "cwe_id": "CWE-925",
        "remediation": {
            "vulnerable_snippet": "sendBroadcast(intent);",
            "fixed_snippet": (
                "// Use LocalBroadcastManager or restrict with a permission:\n"
                "sendBroadcast(intent, \"com.example.permission.RECEIVE_INTERNAL\");"
            ),
            "explanation": (
                "Unrestricted broadcasts can leak data to any app on the "
                "device. Use LocalBroadcastManager for in-app messaging or "
                "guard with a signature-level permission."
            ),
        },
    },
    {
        "id": "EXPORTED_CONTENT_PROVIDER",
        "category": "IPC Security",
        "severity": "MEDIUM",
        "regex": r"grantUriPermission\s*\(",
        "title": "URI Permission Granted via IPC",
        "description": "grantUriPermission widens content-provider access. "
                       "Verify the target package is trusted.",
        "owasp_id": "M8",
        "cwe_id": "CWE-926",
        "remediation": {
            "vulnerable_snippet": "grantUriPermission(targetPkg, uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);",
            "fixed_snippet": (
                "// Prefer FLAG_GRANT_READ_URI_PERMISSION on the Intent and revoke after use:\n"
                "intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);"
            ),
            "explanation": (
                "Persistent grants survive process restarts. Prefer per-Intent "
                "flag-based grants that scope access to a single recipient."
            ),
        },
    },

    # ===================================================================
    # 9. SSL/TLS Validation Bypass
    # ===================================================================
    {
        "id": "TRUSTALL_X509_TRUSTMANAGER",
        "category": "SSL/TLS Validation Bypass",
        "severity": "HIGH",
        "regex": r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}",
        "title": "Empty X509TrustManager.checkServerTrusted",
        "description": "An empty checkServerTrusted accepts ALL certificates — "
                       "complete TLS validation bypass.",
        "owasp_id": "M5",
        "cwe_id": "CWE-295",
        "remediation": {
            "vulnerable_snippet": (
                "public void checkServerTrusted(X509Certificate[] chain, String authType) {\n"
                "    // accept everything\n"
                "}"
            ),
            "fixed_snippet": (
                "// Remove the override entirely; let the default TrustManager validate.\n"
                "// Or use network_security_config.xml for pinning."
            ),
            "explanation": (
                "A trust manager that silently accepts every certificate "
                "makes you trivially MITM-able with any self-signed cert. "
                "Use Android's default trust store or certificate pinning."
            ),
        },
    },
    {
        "id": "BLIND_HOSTNAME_VERIFIER",
        "category": "SSL/TLS Validation Bypass",
        "severity": "HIGH",
        "regex": r"verify\s*\(\s*String\s+\w+\s*,\s*SSLSession\s+\w+\s*\)\s*\{\s*return\s+true\s*;",
        "title": "HostnameVerifier Always Returns true",
        "description": "A HostnameVerifier that returns true accepts any "
                       "certificate hostname.",
        "owasp_id": "M5",
        "cwe_id": "CWE-297",
        "remediation": {
            "vulnerable_snippet": (
                "new HostnameVerifier() {\n"
                "    public boolean verify(String h, SSLSession s) { return true; }\n"
                "}"
            ),
            "fixed_snippet": (
                "HostnameVerifier v = HttpsURLConnection.getDefaultHostnameVerifier();"
            ),
            "explanation": (
                "Always-true hostname verifiers were the cause of many famous "
                "Android banking-app MITM CVEs. Trust the platform default."
            ),
        },
    },
    {
        "id": "SSL_ERROR_PROCEED",
        "category": "SSL/TLS Validation Bypass",
        "severity": "HIGH",
        "regex": r"handler\.proceed\s*\(\s*\)",
        "title": "WebView SSL Error Ignored (handler.proceed())",
        "description": "onReceivedSslError calling handler.proceed() ignores all "
                       "TLS errors in the WebView.",
        "owasp_id": "M5",
        "cwe_id": "CWE-295",
        "remediation": {
            "vulnerable_snippet": (
                "public void onReceivedSslError(WebView w, SslErrorHandler h, SslError e) {\n"
                "    h.proceed();\n"
                "}"
            ),
            "fixed_snippet": (
                "public void onReceivedSslError(WebView w, SslErrorHandler h, SslError e) {\n"
                "    h.cancel();  // do not proceed past TLS errors\n"
                "}"
            ),
            "explanation": (
                "Calling proceed() ignores invalid, expired or attacker-issued "
                "certificates and is a 1-click MITM. Always cancel SSL errors "
                "in production code paths."
            ),
        },
    },
]


# --------------------------------------------------------------------------
# Integrity guarantees enforced at import time.
# These checks catch silent drift before the chapter claims do.
# --------------------------------------------------------------------------

# 1) at least 30 patterns (CLAUDE.md sec 6 rule 7)
assert len(VULN_PATTERNS) >= 30, (
    f"VULN_PATTERNS must contain at least 30 entries, found {len(VULN_PATTERNS)}"
)

# 2) exactly the 9 canonical categories — no typos, no extras
_present_categories = {p["category"] for p in VULN_PATTERNS}
assert _present_categories == set(CATEGORIES), (
    f"Pattern categories drift: "
    f"missing={set(CATEGORIES) - _present_categories}, "
    f"unexpected={_present_categories - set(CATEGORIES)}"
)

# 3) every pattern carries a complete remediation dict (Phase 8 contract)
for _p in VULN_PATTERNS:
    _r = _p.get("remediation")
    assert isinstance(_r, dict), f"{_p['id']} missing remediation dict"
    for _k in ("vulnerable_snippet", "fixed_snippet", "explanation"):
        assert _k in _r and _r[_k], f"{_p['id']} remediation.{_k} empty/missing"

# 4) pattern ids are unique
_ids = [p["id"] for p in VULN_PATTERNS]
assert len(_ids) == len(set(_ids)), "Duplicate pattern ids in VULN_PATTERNS"
