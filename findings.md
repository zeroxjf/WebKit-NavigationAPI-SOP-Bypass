# CVE-2026-20643 — Navigation API SOP Bypass (iOS 26.3.1 vulnerable build)

## Summary
- **Issue class:** Cross-origin policy bypass in WebKit Navigation API interception gate.
- **Effect:** `NavigateEvent.canIntercept` may be `true` for cross-origin navigations that should be non-interceptable.
- **Observed vulnerable target:** iOS `26.3.1` restore build `23D8133` (`iPhone18,2`) WebCore from dyld shared cache.

## Root Cause
The URL rewrite/interception eligibility logic (in `documentCanHaveURLRewritten`, inlined into Navigation flow) accepts HTTP-family targets too broadly:

```cpp
if (!isSameSite && !isSameOrigin)
    return false;
if (targetURL.protocolIsInHTTPFamily())
    return true; // missing strict component equality checks
```

This allows same-site-but-cross-origin cases (notably cross-port) to pass the gate.

### Expected behavior (spec-aligned)
Interception should be denied if document URL and target URL differ in any of:
- scheme
- username
- password
- host
- port

## Reverse Engineering Evidence

### Vulnerable path
- `WebCore::Navigation::innerDispatchNavigateEvent(...)`
  - Address: `0x1a1303304`
  - Binary: WebCore (from `23D8133` dyld cache)

Inside that function, the gate sequence uses:
- Same-site / same-origin checks
- HTTP family allow branch
- File/fragment special cases

Stubs resolved from callsites in this block:
- `0x1A4186DC0` -> `WTF::URL::protocolIs(...)_stub`
- `0x1A41842F0` -> `WTF::isEqualIgnoringQueryAndFragments(...)_stub`
- `0x1A41842E0` -> `WTF::equalIgnoringFragmentIdentifier(...)_stub`

### `canIntercept` wiring
- Getter:
  - `WebCore::jsNavigateEvent_canIntercept`
  - Address: `0x19f84ab84`
  - Returns boolean from `*(event + 160)`.
- Constructor path:
  - `WebCore::NavigateEvent::NavigateEvent(...)`
  - Address: `0x1a12fa834`
  - Initializes `event+160..163` from init flags.
- Source of init flag:
  - `innerDispatchNavigateEvent` computes rewrite/interception eligibility and stores into NavigateEvent init before dispatch.

## Trigger Conditions

### Reliable test case
- Current page: `http://127.0.0.1:8000/`
- Target URL: `http://127.0.0.1:8800/`
- Same-site: yes (`127.0.0.1`)
- Same-origin: no (different port)

### Expected outputs
- **Vulnerable:** `navigate` event reports `canIntercept === true` for cross-port target.
- **Patched:** `navigate` event reports `canIntercept === false`.

## Practical Impact
- Navigation integrity break across origins in Navigation API path.
- Attacker can intercept/suppress navigations that should cross an origin boundary.
- Enables strong URL/context confusion and phishing workflow abuse in redirect-heavy flows.
- High relevance to localhost multi-port environments (`:3000` -> `:3001`) where origin separation is port-based.

## Limits of This Primitive Alone
- By itself, this does **not** automatically grant arbitrary cross-origin response body read.
- It is still a meaningful SOP boundary violation because interception authorization itself is wrong.

## Correlation to Upstream Fix
WebKit mainline fix adds strict equality checks for scheme/user/password/host/port before allowing URL rewriting/interception in this path, matching this root-cause analysis.

