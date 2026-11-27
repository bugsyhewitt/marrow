# marrow

Prototype pollution payload generator and static JavaScript vulnerability scanner.

Part of the [necromancer](https://github.com/bugsyhewitt/necromancer) offensive-security suite.

## Install

```bash
pip install marrow
```

Or from source:

```bash
pip install -e ".[dev]"
```

## Usage

### Generate payloads

```bash
# List all prototype pollution payload variants
marrow generate

# Custom probe key/value
marrow generate --key xtest --value 42

# Include server-side Node.js payloads
marrow generate --server-side

# JSON output
marrow generate --json
```

### Scan JS source for vulnerable patterns

```bash
# Scan a local JS file
marrow scan-js target.js

# JSON output
marrow scan-js target.js --json
```

### Probe a live URL

```bash
# GET probe with all payload variants
marrow probe --url http://target.example.com/api

# POST probe
marrow probe --url http://target.example.com/api --method POST

# Include server-side payloads, JSON output
marrow probe --url http://target.example.com/api --server-side --json
```

## What it detects

**Payload generation** covers 10 techniques:

| Technique | Example |
|-----------|---------|
| proto-bracket | `__proto__[polluted]=1` |
| constructor-chain | `constructor[prototype][polluted]=1` |
| constructor-dot | `constructor.prototype[polluted]=1` |
| url-encoded | `%5F%5Fproto%5F%5F[polluted]=1` |
| nested | `__proto__[polluted][subkey]=1` |
| crlf-bypass | CRLF-injected param name |
| json-proto | `{"__proto__": {"polluted": "1"}}` |
| json-constructor | `{"constructor": {"prototype": {"polluted": "1"}}}` |
| merge-target | `a[__proto__][polluted]=1` |
| get-param | `?__proto__[polluted]=1` |

**Static JS analysis** finds:

- Recursive merge/extend functions with for-in loops (high confidence)
- Lodash `_.merge()` / `lodash.merge()` calls (medium confidence)
- `Object.assign()` with external inputs (low confidence)
- Object spread merges `{...a, ...b}` (medium confidence)
- `jQuery.extend(true, ...)` deep merges (high confidence)
- for-in enumeration without `hasOwnProperty` guard (medium confidence)
- `_.defaults()` / `_.defaultsDeep()` calls (medium confidence)

## v0.1 limitations

- Static JS analysis uses regex patterns, not an AST — false positives are possible.
- HTTP probing checks only whether the probe key appears in the response body; full server-side pollution verification requires a more complex test harness.
- No headless browser; dynamic client-side pollution is out of scope for v0.1.

## License

MIT
