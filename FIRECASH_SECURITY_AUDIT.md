# Firecash/ZKas Security Audit Report
## Comprehensive Vulnerability Analysis with Causes, Effects, and Code-Level Solutions

*Generated: September 6, 2026*
*Project Vision: ZKas — A shielded cryptocurrency protocol built on Kaspa, providing privacy through zk-SNARKs (Orchard protocol), enabling trustless cross-chain bridges, mining pools, and merchant payment gateways.*

---

## Executive Summary

This audit analyzed **12 repositories** under `github.com/firecash`, encompassing the ZKas shielded cryptocurrency ecosystem. The audit identified **critical security vulnerabilities** across multiple layers — from client-side XSS to fundamental protocol design issues — each requiring specific code-level remediation aligned with the project's whitepaper vision of privacy, decentralization, and trustless operation.

Each vulnerability entry includes:
- **Cause**: Root cause or contributing factors
- **Effect**: Potential impact if exploited
- **Solution**: Code-level fix aligned with project vision
- **Severity**: Critical / High / Medium classification

---

## 1. zkas-explorer (React Block Explorer) - CRITICAL

### 1.1 Vulnerability: XSS via Unescaped API Data

**Location**: `app/PageTable.tsx:41`, `app/KasLink.tsx:56-68`

**Cause**:
- Table cell values rendered directly without HTML sanitization: `{cell}`
- Address names from API (`addressNames[to]`) displayed in tooltips without escaping
- No Content Security Policy (CSP) to restrict executable content
- Reliance on API data being trusted/clean — violates the project's trustless design principle

**Effect**:
- **Remote Code Execution (RCE)**: A malicious transaction with `signature_script: "<script>alert('XSS')</script>"` executes in user browser
- **Credential Theft**: Keylogging, session hijacking, or wallet address harvesting
- **Phishing**: Fake transaction data displayed to redirect users
- **Data Exfiltration**: Sensitive blockchain data sent to external servers

**Severity**: CRITICAL — Active XSS in public-facing block explorer affecting all users

**Solution**:
```tsx
// PageTable.tsx - Line 41
// Replace: {cell}
// With: Sanitized rendering
import DOMPurify from 'dompurify';

<td dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(String(cell)) }} />

// KasLink.tsx - Lines 56-68
// Replace: {addressNames[to]}
// With: Sanitized display
<span>{DOMPurify.sanitize(String(addressNames[to]))}</span>

// Add CSP header in server configuration (nginx/proxy)
// Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https:; frame-src 'none';
```

**Alignment with Whitepaper Vision**: The project's trustless design principle requires that no untrusted data enters the browser without sanitization. The block explorer is the primary interface for users to verify transactions — if compromised, the entire trust model collapses.

---

### 1.2 Vulnerability: CORS Misconfiguration

**Location**: `app/api/kaspa-api-client.ts:4`

**Cause**:
- `Access-Control-Allow-Origin: *"` explicitly set in fetch headers
- Reduces server-side control over origin access
- Intended for development but present in production build
- Violates the project's security architecture documented in `ARCHITECTURE.md`

**Effect**:
- Unauthorized origins can access API responses
- Potential data leakage to malicious websites
- Bypasses intended same-origin policy
- Enables cross-origin data exfiltration of blockchain data

**Severity**: HIGH — Enables cross-origin data access

**Solution**:
```typescript
// kaspa-api-client.ts - Line 4
// Remove Access-Control-Allow-Origin from client-side headers
// Let the server handle CORS properly

const DEFAULT_HEADERS = {
  "Cache-Control": "no-cache",
  "Accept": "application/json",
};

// Server-side nginx configuration:
# Add to nginx config for API server
add_header 'Access-Control-Allow-Origin' 'https://explorer.zkas.info' always;
add_header 'Access-Control-Allow-Methods' 'GET, OPTIONS' always;
add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type' always;
add_header 'Access-Control-Max-Age' 86400 always;

# Remove the client-side header entirely
```

**Alignment with Whitepaper Vision**: The project's architecture documentation specifies a clear separation between client and server responsibilities. CORS is a server-side concern and should be handled at the API layer, not the client.

---

## 2. zkas-wallet (TypeScript Wallet) - HIGH

### 2.1 Vulnerability: Plaintext localStorage Exposure

**Location**: `src/deviceSeed.ts:33-38`, `src/accounts.ts:73`, `src/applock.ts:83-92`

**Cause**:
- `setDeviceSeed()` falls back to plaintext localStorage when seal fails (line 33-38)
- `setMasterMnemonic()` writes to localStorage unencrypted when lock disabled (line 73)
- `plaintextSeeds()` reads all seed keys from localStorage when unlocked (line 83-92)
- Status cache reads from localStorage without integrity checks (api.ts:358-371)
- Defense-in-depth prioritizes convenience over secure storage
- Contradicts the whitepaper's privacy and self-custody principles

**Effect**:
- **Immediate fund theft**: XSS or malware on user's machine reads seed phrases from localStorage
- **Session takeover**: Authentication tokens accessible via JavaScript
- **Mass compromise**: Single XSS incident exposes all wallet data
- **No user awareness**: Seeds stored without explicit user consent for plaintext storage
- **Loss of self-custody**: Core whitepaper promise of non-custodial wallet is undermined

**Severity**: HIGH — Direct path to private key compromise

**Solution**:
```typescript
// deviceSeed.ts - Replace fallback-to-plaintext with secure fallback
// Lines 33-38: Replace with:

async function setDeviceSeed(seed: string, token: string): Promise<void> {
  try {
    // Attempt encryption first (existing seal logic)
    const encrypted = await seal(seed, token);
    await localStorage.setItem(`device_seed_${token}`, encrypted);
  } catch (error) {
    // NEW: Fall back to encrypted storage with a secondary key
    // instead of plaintext. If encryption fails entirely, 
    // store nothing and prompt user.
    const secondaryKey = await deriveBackupKey(devicePassphrase);
    const encrypted = await encrypt(seed, secondaryKey);
    await localStorage.setItem(`device_seed_backup_${token}`, encrypted);
    // Log security warning but never store plaintext
    console.warn('Primary encryption failed; using secondary encryption.');
  }
}

// accounts.ts - Line 73: Replace plaintext write
// Replace:
// localStorage.setItem(`device_mnemonic_${token}`, mnemonic);
// With:
const encryptedMnemonic = await encryptWithDeviceLock(mnemonic, appLockKey);
await localStorage.setItem(`device_mnemonic_${token}`, encryptedMnemonic);

// applock.ts - Line 83-92: Add integrity check
// Replace plaintextSeeds() reading from localStorage:
async function plaintextSeeds(): Promise<SeedData[]> {
  const seeds = [];
  for (const key of seedKeys) {
    const encrypted = await localStorage.getItem(key);
    // NEW: Verify integrity before decryption
    if (!encrypted || !isEncrypted(encrypted)) {
      throw new SecurityError(`Invalid or plaintext seed found for ${key}`);
    }
    const decrypted = await decryptWithAppLock(encrypted);
    seeds.push(decrypted);
  }
  return seeds;
}

// Add encryption wrapper utility
// src/crypto/storageEncryption.ts
import { encrypt, decrypt } from './encryption';

export async function secureLocalStorageSet(key: string, value: string): Promise<void> {
  const encrypted = await encrypt(value, await getStorageEncryptionKey());
  await localStorage.setItem(key, encrypted);
}

export async function secureLocalStorageGet(key: string): Promise<string> {
  const encrypted = await localStorage.getItem(key);
  if (!encrypted || !isEncrypted(encrypted)) {
    throw new SecurityError('Plaintext data found in secure storage');
  }
  return await decrypt(encrypted, await getStorageEncryptionKey());
}
```

**Alignment with Whitepaper Vision**: The whitepaper explicitly states that users maintain full self-custody of their funds. Plaintext seed storage in localStorage directly violates this principle — if a third party accesses the device, the user loses control of their assets. All sensitive data must be encrypted at rest before storage.

---

### 2.2 Vulnerability: No HTTP-only Token Flags

**Cause**:
- Tokens stored in localStorage without `HttpOnly` flag
- CSP includes `unsafe-eval` for convenience
- No separation between device-lock encryption and token storage

**Effect**:
- **XSS-driven token theft**: JavaScript can read all localStorage values
- **Cross-site request forgery**: Tokens sent to malicious sites
- **Persistent access**: Tokens remain accessible even after session expiry

**Severity**: HIGH — Enables token theft via XSS

**Solution**:
```typescript
// api.ts - Replace localStorage token storage with HttpOnly cookie handling
// Replace localStorage.setItem('wallet_token', token):

// Use a secure cookie via the Tauri backend (since this is a Tauri app)
// src-tauri/src/api.rs or equivalent:

// In Tauri backend command:
#[tauri::command]
async fn set_wallet_token(token: &str) -> Result<(), String> {
    // Set HttpOnly, Secure, SameSite=Strict cookie
    // This is only accessible from the backend, not JavaScript
    let cookie = format!(
        "wallet_token={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600",
        token
    );
    // Use tauri's cookie mechanism
    tauri::api::process::Command::new("set-cookie")
        .arg(&cookie)
        .execute();
    Ok(())
}

// In frontend, call backend instead of localStorage:
// Replace: localStorage.setItem('wallet_token', token)
// With: await invoke('set_wallet_token', { token })

// Also fix CSP by removing unsafe-eval:
// Replace CSP with:
// Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https:; frame-src 'none';
// Note: 'wasm-unsafe-eval' is specific to WASM and more restrictive than 'unsafe-eval'
```

**Alignment with Whitepaper Vision**: The whitepaper emphasizes robust security architecture with defense-in-depth. HttpOnly cookies are a fundamental security control that prevents JavaScript access to authentication tokens, directly supporting the project's security-first approach.

---

## 3. zkas-pool (Rust Pool) - HIGH

### 3.1 Vulnerability: Silent Fund Redirection

**Location**: `bridge/src/default_client.rs` `clean_wallet()` function

**Cause**:
- `handle_authorize()` accepts any bech32-valid Kaspa address without additional verification
- `clean_wallet()` coerces bare payloads into `kaspa:` prefixed addresses
- If validation fails, silently falls back to `pool_fallback_address()` without alerting miner
- Miners unaware their rewards are being redirected
- Violates the project's trustless and transparent mining principles

**Effect**:
- **Unauthorized reward diversion**: Miner's KAS rewards redirected to pool operator
- **Loss of miner trust**: Miners lose confidence in pool integrity
- **Financial loss**: Ongoing diversion without miner knowledge
- **Difficulty detecting**: Silent fallback makes detection extremely difficult
- **Reputation damage**: Pool operator loses credibility in the community

**Severity**: HIGH — Direct financial impact on miners

**Solution**:
```rust
// default_client.rs - Replace clean_wallet() function
// Lines 497-508: Replace silent fallback with explicit error and warning

fn clean_wallet(input: &str) -> Result<String, WalletError> {
    // Try to parse the address
    match WalletAddress::new(input) {
        Ok(addr) => {
            // Validate the address belongs to the miner
            // NEW: Check if address is the authorized address
            if !is_authorized_address(&addr) {
                return Err(WalletError::UnauthorizedAddress {
                    submitted: addr.to_string(),
                    authorized: get_authorized_address(),
                });
            }
            Ok(addr.to_string())
        }
        Err(e) => {
            // NEW: Throw explicit error instead of silent fallback
            // Log the attempt for security monitoring
            log::warn!("Wallet address validation failed for miner: {}", input);
            // Emit event for pool monitoring
            emit_event(PoolEvent::WalletValidationFailed {
                miner_id: get_miner_id(),
                submitted_address: input.to_string(),
                error: e.to_string(),
            });
            // Return error to miner - they must fix their address
            Err(WalletError::InvalidAddress {
                reason: format!("Address validation failed: {}", e),
                suggestion: "Please verify your Kaspa address is correct".to_string(),
            })
        }
    }
}

// handle_authorize() - Add miner notification
// Lines 257-268: Replace silent fallback with explicit error
// Replace:
// if let Err(e) = validate_address(address) {
//     // silently use fallback
// }
// With:
if let Err(e) = validate_address(address) {
    // Notify miner of the problem
    send_notification_to_miner(
        miner_session_id,
        NotificationType::AddressError {
            message: format!("Your submitted address failed validation: {}", e),
            action_required: "Update your wallet address in your mining software",
        }
    );
    return Err(PoolError::AddressValidationFailed(e));
}

// Add address validation helper
fn is_authorized_address(addr: &WalletAddress) -> bool {
    // Compare against the address registered during authorization
    get_registered_miner_address() == Some(addr.to_string())
}
```

**Alignment with Whitepaper Vision**: The whitepaper emphasizes transparent and fair mining operations. Silent fund redirection directly contradicts the project's commitment to honest payouts. Every miner must be explicitly notified of any address issues and given the opportunity to correct them.

---

### 3.2 Vulnerability: No API Authentication

**Location**: `api/src/lib.rs` - public API endpoints

**Cause**:
- API designed to be "embedded behind a reverse proxy" per documentation
- No API keys, tokens, or authentication mechanisms implemented
- Health endpoints (`/health`, `/ready`, `/started`) openly accessible
- Per-IP rate limiting via `tower_governor` but no identity-based auth

**Effect**:
- **Unauthorized API access**: Anyone can query pool statistics, submit shares
- **Data scraping**: Full pool data accessible without restrictions
- **Denial of service**: Unlimited API calls from anyone
- **Mining manipulation**: Potential to interfere with pool operations
- **Information leakage**: Pool composition, payout patterns exposed

**Severity**: HIGH — Exposes full pool control surface

**Solution**:
```rust
// api/src/lib.rs - Add API key authentication middleware
// Add a new middleware for API key validation

use tower_http::auth::{AsyncAuthorizeRequest, AuthorizationLayer};
use std::sync::Arc;

// NEW: API Key authentication layer
struct ApiKeyAuthorizer {
    valid_keys: Arc<HashSet<String>>,
}

impl<S> AsyncAuthorizeRequest<S> for ApiKeyAuthorizer {
    type Response = S;
    type Error = StatusCode;
    type Future = future::Ready<Result<S, StatusCode>>;

    fn authorize(&self, req: Request<S>) -> Self::Future {
        let key = req.headers()
            .get("X-API-Key")
            .and_then(|v| v.to_str().ok())
            .filter(|k| self.valid_keys.contains(*k));
        
        match key {
            Some(_) => future::ok(req),
            None => future::err(StatusCode::UNAUTHORIZED),
        }
    }
}

// Configure API with authentication
// In the API setup:
pub fn create_pool_api(config: &PoolConfig) -> Router {
    // Load valid API keys from secure storage
    let api_keys = load_api_keys(&config).expect("Failed to load API keys");
    
    let app = Router::new()
        // Apply API key authentication to all endpoints except health
        .layer(
            AuthorizationLayer::custom(ApiKeyAuthorizer {
                valid_keys: Arc::new(api_keys),
            })
        )
        .layer(
            // Health endpoints remain public
            Tower(layer::builder().path_prefix("/health").layer(identity::layer()))
        )
        .layer(
            // Add rate limiting per authenticated user
            Tower::new(GovernorConfig::new()
                .key_extractor(|req| {
                    req.headers()
                        .get("X-API-Key")
                        .and_then(|v| v.to_str().ok())
                        .map(|k| k.to_string())
                        .unwrap_or_else(|| req.extensions().get::<ClientIp>().map(|ip| ip.to_string()).unwrap_or_default())
                })
                .rate(100)
                .burst(200)
            )
        );
    
    // Add CORS properly
    let cors = CorsLayer::new()
        .allow_origin(config.api_cors_allow_origin.as_str())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([HeaderName::AUTHORIZATION, HeaderName::CONTENT_TYPE, HeaderName::X_API_KEY]);
    
    app.layer(cors)
}

// Add API key management endpoint (admin only)
#[post("/api/admin/keys/generate")]
async fn generate_api_key(
    State(config): State<AppConfig>,
    Authorization(header: Authorization<BearerToken>) = require(),
) -> Result<ApiKeyResponse, StatusCode> {
    // Only allow admin users to generate keys
    if !is_admin(&header.token()) {
        return Err(StatusCode::FORBIDDEN);
    }
    let key = generate_secure_key();
    store_api_key(&key, &config).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(ApiKeyResponse { key, created_at: Utc::now() })
}
```

**Alignment with Whitepaper Vision**: The whitepaper's architecture design specifies that the pool operates as a transparent, auditable service. API authentication ensures that only authorized parties can access pool data or submit shares, maintaining the integrity of the mining operation.

---

## 4. vprogs-zkas (Rust Bridge Protocol) - HIGH

### 4.1 Vulnerability: Dev vs Production Settlement Gap

**Location**: `zk/backend/settlement.rs` dev vs production modes

**Cause**:
- Dev script has weaker deposit binding than production mode
- `settlement.rs:333-350` - dev mode lacks journal for deposit binding
- Production code has stronger deposit binding than dev mode
- Gap not documented, leading to potential misconfiguration
- Contradicts the whitepaper's trustless bridge design

**Effect**:
- **Settlement bypass**: Dev mode could allow fraudulent settlements
- **Inconsistent security**: Same code has different security levels based on mode
- **Production risk**: Accidental use of dev mode in production
- **Audit complexity**: Hard to verify which mode is active
- **Trustless guarantee broken**: Bridge security depends on mode configuration

**Severity**: HIGH — Inconsistent security guarantees

**Solution**:
```rust
// settlement.rs - Add explicit mode enforcement and logging
// Add at the top of settlement configuration:

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementMode {
    Development,
    Production,
}

impl SettlementMode {
    pub fn from_env() -> Result<SettlementMode, ConfigError> {
        let mode = std::env::var("ZKAS_SETTLEMENT_MODE")
            .unwrap_or_else(|_| "production".to_string());
        
        match mode.as_str() {
            "development" => Ok(SettlementMode::Development),
            "production" => Ok(SettlementMode::Production),
            _ => Err(ConfigError::InvalidMode(mode)),
        }
    }
    
    // NEW: Enforce that production mode requires explicit confirmation
    pub fn require_production_confirmation(&self) -> Result<(), ConfigError> {
        match self {
            SettlementMode::Production => {
                // Require an explicit environment variable to confirm production use
                let confirmed = std::env::var("ZKAS_PRODUCTION_CONFIRMED")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                if !confirmed {
                    Err(ConfigError::ProductionNotConfirmed(
                        "Set ZKAS_PRODUCTION_CONFIRMED=true to use production mode".to_string()
                    ))
                } else {
                    Ok(())
                }
            }
            SettlementMode::Development => Ok(()),
        }
    }
    
    // NEW: Log the current mode prominently at startup
    pub fn log_mode(&self) {
        match self {
            SettlementMode::Development => {
                log::warn!("⚠️  SETTLEMENT MODE: DEVELOPMENT - Weaker security guarantees");
                log::warn!("⚠️  Do NOT use this mode with real funds");
            }
            SettlementMode::Production => {
                log::info!("✓ SETTLEMENT MODE: PRODUCTION - Full security guarantees");
            }
        }
    }
}

// Add to the settlement initialization:
pub fn initialize_settlement(config: &SettlementConfig) -> Result<SettlementEngine, ConfigError> {
    let mode = SettlementMode::from_env()?;
    mode.require_production_confirmation()?;
    mode.log_mode();
    
    // NEW: Ensure dev mode cannot access production-grade deposit binding
    // If dev mode is active, explicitly document the weaker guarantees
    if mode == SettlementMode::Development {
        log::warn!("Dev mode: Deposit binding uses dev script without journal");
        log::warn!("This provides weaker guarantees than production mode");
        // Ensure the dev mode explicitly sets deposit binding to dev level
        config.deposit_binding_level = DepositBinding::Dev;
    }
    
    Ok(SettlementEngine::new(config))
}
```

**Alignment with Whitepaper Vision**: The whitepaper's trustless bridge design requires consistent security guarantees regardless of environment. The dev/production gap means the bridge operates with different security assumptions in different modes, violating the trustless principle. Explicit mode enforcement and confirmation prevent accidental use of weaker security in production.

---

### 4.2 Vulnerability: Compute Budget Oversizing Risk

**Location**: `settlement.rs:212-228`

**Cause**:
- `covenant_compute_budget` uses `checked_covering_script_units`
- Oversized budget → transaction rejected by node (DoS vector)
- 25M unit term for R0Succinct precompile cost not properly validated
- Compute budget miscalculation can halt settlement process

**Effect**:
- **Denial of Service**: Legitimate settlements blocked by budget miscalculation
- **Miner griefing**: Malicious actors trigger budget errors to stop settlements
- **L2 stall**: Entire settlement pipeline grinds to halt
- **Economic loss**: Delayed settlements affect all participants

**Severity**: HIGH — Can halt entire L2 settlement pipeline

**Solution**:
```rust
// settlement.rs - Lines 212-228: Add budget validation and bounds checking

pub fn calculate_covenant_compute_budget(lane_id: LaneId, batch_size: usize) -> Result<u64, BudgetError> {
    // NEW: Validate and cap the compute budget
    let requested_budget = checked_covering_script_units(lane_id, batch_size)?;
    
    // Define safe bounds
    const MIN_BUDGET: u64 = 1_000_000;   // 1M units minimum
    const MAX_BUDGET: u64 = 50_000_000;  // 50M units maximum (safety cap)
    const RISCO_PRECOMPUTE_COST: u64 = 25_000_000; // Known R0Succinct cost
    
    // Validate budget is within safe range
    if requested_budget > MAX_BUDGET {
        // Cap at maximum safe value instead of rejecting
        log::warn!("Compute budget {} exceeds maximum {}, capping", requested_budget, MAX_BUDGET);
        return Ok(MAX_BUDGET);
    }
    
    if requested_budget < MIN_BUDGET {
        return Err(BudgetError::BelowMinimum {
            requested: requested_budget,
            minimum: MIN_BUDGET,
        });
    }
    
    // Validate the R0Succinct precompile cost term is reasonable
    let r0_cost = calculate_risc0_succinct_cost(batch_size)?;
    if r0_cost > RISCO_PRECOMPUTE_COST * 2 {
        return Err(BudgetError::Risc0CostExceeded {
            cost: r0_cost,
            expected_max: RISCO_PRECOMPUTE_COST * 2,
        });
    }
    
    // NEW: Add a safety margin (e.g., 10% buffer)
    let safety_margin = requested_budget / 10;
    let total_budget = requested_budget + safety_margin;
    
    // Final validation: ensure total budget doesn't exceed mass limit
    if total_budget > MAX_MASS_LIMIT {
        return Err(BudgetError::ExceedsMassLimit {
            budget: total_budget,
            mass_limit: MAX_MASS_LIMIT,
        });
    }
    
    Ok(total_budget)
}

// Add monitoring for budget usage
pub fn monitor_budget_usage(current: u64, limit: u64) -> BudgetHealth {
    let ratio = current as f64 / limit as f64;
    if ratio > 0.9 {
        log::warn!("⚠️  Compute budget usage at {:.1}% of limit", ratio * 100.0);
        BudgetHealth::Critical
    } else if ratio > 0.7 {
        log::warn!("Compute budget usage at {:.1}% of limit", ratio * 100.0);
        BudgetHealth::Warning
    } else {
        BudgetHealth::Healthy
    }
}
```

**Alignment with Whitepaper Vision**: The whitepaper specifies a trustless and reliable settlement mechanism. Budget miscalculations that halt settlement directly violate the reliability guarantees of the bridge protocol. Proper bounds checking and monitoring ensure the settlement pipeline remains operational.

---

## 5. zkas-signer (WASM Key Derivation) - MEDIUM

### 5.1 Vulnerability: No Seed Zeroization in WASM

**Location**: `src/lib.rs` - main WASM library, no `zeroize` usage

**Cause**:
- Sensitive data (32-byte seeds, 43-byte address raw bytes, 96-byte FVK) persist in WASM memory
- No explicit memory zeroization after use
- Mobile wrapper (`mobile/src/lib.rs`) uses `zeroize::Zeroizing` but browser/WASM port lacks it
- JavaScript glue passes strings via `passStringToWasm0()` but doesn't guarantee clearing
- Violates the whitepaper's secure key management principles

**Effect**:
- **Memory forensics**: Compromised browser can extract seeds from WASM memory
- **Persistent secrets**: Seeds remain accessible until garbage collected (potentially indefinitely)
- **Cross-session leakage**: Previous Wallet instances' seeds recoverable
- **Malware target**: Information-stealing malware focuses on browser WASM memory

**Severity**: MEDIUM — Requires browser compromise for exploitation

**Solution**:
```rust
// src/lib.rs - Add zeroize to all sensitive data structures
// Add to Cargo.toml dependencies:
// zeroize = { version = "1.5", features = ["zeroize_derive"] }

use zeroize::Zeroize;

// NEW: Wrap sensitive data in Zeroizing types
#[derive(Clone)]
pub struct SecureWallet {
    pub seed_hex: String,
    pub address: String,
    pub fvk: String,
    // Wrap sensitive fields in Zeroizing
    pub _secret_seed: Zeroizing<Vec<u8>>, // Zeroized on drop
}

impl Drop for SecureWallet {
    fn drop(&mut self) {
        // Zeroize all sensitive memory on drop
        self._secret_seed.zeroize();
        // Zeroize the hex string too
        self.seed_hex.zeroize();
        log::info!("SecureWallet dropped - sensitive memory zeroized");
    }
}

// In the Wallet struct, add zeroization:
pub struct Wallet {
    pub seed_hex: Zeroizing<String>,  // Changed from String
    pub address_bytes: Zeroizing<Vec<u8>>, // Changed from Vec<u8>
    pub fvk_bytes: Zeroizing<Vec<u8>>, // Changed from Vec<u8>
    // Other non-sensitive fields remain unchanged
}

impl Wallet {
    pub fn new(seed: &[u8]) -> Result<Self, WalletError> {
        // Store seed in Zeroizing wrapper
        let seed_hex = Zeroizing::new(hex::encode(seed));
        let address_bytes = Zeroizing::new(address_from_seed(seed)?);
        let fvk_bytes = Zeroizing::new(fvk_from_seed(seed)?);
        
        Ok(Wallet {
            seed_hex,
            address_bytes,
            fvk_bytes,
            // ... other fields
        })
    }
    
    // Explicit zeroize method for when wallet is no longer needed
    pub fn zeroize(&mut self) {
        self.seed_hex.zeroize();
        self.address_bytes.zeroize();
        self.fvk_bytes.zeroize();
    }
}

// Add explicit zeroization to WASM glue code
// pkg-new/firecash_signer.js (or equivalent):
// Ensure that after each Wallet operation, memory is cleared:
// 
// export class Wallet {
//     async destroy() {
//         // Call Rust zeroize function
//         await wasm.zeroize_wallet(this.ptr);
//     }
// }

// Add a zeroize_wasm_memory function in Rust:
#[wasm_bindgen]
pub fn zeroize_wasm_memory(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // Use volatile_zero_memory or explicit zeroization
    unsafe {
        std::ptr::write_bytes(ptr, 0, len);
    }
}
```

**Alignment with Whitepaper Vision**: The whitepaper emphasizes secure key management as a fundamental pillar of the privacy protocol. Without zeroization, sensitive key material persists in browser memory, directly contradicting the project's security-first design.

---

### 5.2 Vulnerability: Public `seed_hex` Exposure

**Location**: `src/lib.rs:35` - `Wallet.seed_hex` public field

**Cause**:
- `seed_hex` exposed publicly on `Wallet` struct for API accessibility
- Intentional for public API but creates surface for misuse
- No access controls on WASM memory fields

**Effect**:
- **Accidental exposure**: Developers retain Wallet instances with seed_hex accessible
- **JS debugging**: `window.__wbg_wallet_*()` can inspect seed_hex
- **Extension vulnerabilities**: Browser extensions access WASM heap
- **Backup mishaps**: Seed accidentally logged or transmitted

**Severity**: MEDIUM — Requires developer misuse for exploitation

**Solution**:
```rust
// src/lib.rs - Make seed_hex private and provide controlled access
// Replace: pub seed_hex: String
// With: private field + accessor method

pub struct Wallet {
    seed_hex: Zeroizing<String>,  // Now private
    address: Zeroizing<String>,
    fvk: Zeroizing<String>,
}

impl Wallet {
    // NEW: Only expose hash of seed for verification, not the seed itself
    pub fn seed_hash(&self) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(self.seed_hex.as_bytes());
        hex::encode(hasher.finalize())
    }
    
    // NEW: Require authentication for seed access
    pub fn get_seed_hex(&self, auth_token: &str) -> Result<String, WalletError> {
        if !verify_access_token(auth_token) {
            return Err(WalletError::UnauthorizedAccess);
        }
        // Log access attempt
        log::warn!("Seed accessed - this should only happen with explicit user consent");
        Ok(self.seed_hex.clone())
    }
    
    // NEW: Temporary seed display with explicit user confirmation
    pub fn reveal_seed(&mut self, confirmation: &str) -> Result<(), WalletError> {
        if confirmation != "I confirm I want to reveal my seed" {
            return Err(WalletError::RevealNotConfirmed);
        }
        log::warn!("Seed revealed - user confirmed");
        Ok(())
    }
}
```

**Alignment with Whitepaper Vision**: The whitepaper's security model relies on seed phrase confidentiality. Exposing the seed through a public field contradicts the privacy guarantees of the protocol. Controlled, authenticated access with explicit user confirmation ensures seeds are only revealed when the user explicitly intends to.

---

### 5.3 Vulnerability: JSON Deserialization Without Validation

**Location**: `verify_and_sign_payment()` at `src/lib.rs:346-465`

**Cause**:
- Server-supplied JSON (`Disc`, `AlphaReq` structs) parsed without strict field validation
- Fields like `out_rseed` and `rcv` no length/format validation
- Malicious JSON could trigger panics or out-of-bounds access

**Effect**:
- **Panic-based information leak**: `expect()` calls expose internal state via error handler
- **Out-of-bounds memory access**: Malformed JSON triggers panic with state exposure
- **Forced signing**: Server could craft payload to bypass verification
- **Denial of service**: Panics crash WASM module, disrupting wallet functionality

**Severity**: MEDIUM-HIGH — Combined with other vulnerabilities enables advanced attacks

**Solution**:
```rust
// src/lib.rs - Add strict JSON validation in verify_and_sign_payment

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PaymentValidationError {
    #[error("Invalid recipient address format")]
    InvalidRecipient,
    #[error("Amount exceeds maximum limit")]
    AmountExceeded,
    #[error("Fee exceeds maximum limit")]
    FeeExceeded,
    #[error("Invalid disclosure format")]
    InvalidDisclosure,
    #[error("JSON field too large: {0}")]
    FieldTooLarge(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
}

// NEW: Strict validation function for all server-supplied JSON
fn validate_payment_request(payload: &Value) -> Result<(), PaymentValidationError> {
    // Validate all fields exist and have correct types
    let recipient = payload.get("to")
        .ok_or(PaymentValidationError::MissingField("to".to_string()))?
        .as_str()
        .ok_or(PaymentValidationError::InvalidRecipient)?;
    
    // Validate address format (must be zkas: prefix)
    if !recipient.starts_with("zkas:") && !recipient.starts_with("zkastest:") {
        return Err(PaymentValidationError::InvalidRecipient);
    }
    
    // Validate amount is positive and within reasonable bounds
    let amount = payload.get("amountSompi")
        .and_then(|v| v.as_i64())
        .ok_or(PaymentValidationError::MissingField("amountSompi".to_string()))?;
    if amount <= 0 || amount > MAX_SOMPI {
        return Err(PaymentValidationError::AmountExceeded);
    }
    
    // Validate fee bounds
    if let Some(fee) = payload.get("feeSompi").and_then(|v| v.as_i64()) {
        if fee < 0 || fee > MAX_FEE {
            return Err(PaymentValidationError::FeeExceeded);
        }
    }
    
    // Validate disclosure fields are within size limits
    let disclosure = payload.get("disclosure");
    if let Some(disc) = disclosure {
        let disc_str = disc.to_string();
        if disc_str.len() > MAX_DISCLOSURE_SIZE {
            return Err(PaymentValidationError::FieldTooLarge("disclosure".to_string()));
        }
        // Validate disclosure structure
        validate_disclosure_structure(disc)?;
    }
    
    // Validate out_rseed is within bounds
    if let Some(out_rseed) = payload.get("out_rseed") {
        let rseed_str = out_rseed.to_string();
        if rseed_str.len() > MAX_RSEED_SIZE {
            return Err(PaymentValidationError::FieldTooLarge("out_rseed".to_string()));
        }
    }
    
    // Validate rcv field
    if let Some(rcv) = payload.get("rcv") {
        if rcv.to_string().len() > MAX_RCV_SIZE {
            return Err(PaymentValidationError::FieldTooLarge("rcv".to_string()));
        }
    }
    
    Ok(())
}

// In verify_and_sign_payment(), call validation before processing:
pub fn verify_and_sign_payment(
    payload_json: &str,
    seed_hex: &str,
    network: &str,
    max_fee_sompi: u64,
) -> Result<PaymentSignature, WalletError> {
    // NEW: Parse and validate JSON before processing
    let payload: Value = serde_json::from_str(payload_json)
        .map_err(|_| WalletError::InvalidJson)?;
    
    validate_payment_request(&payload)?;
    
    // ... rest of the verification logic with validated inputs ...
    
    // Replace panic-prone expect() calls with proper error handling:
    let fvk_bytes = blob.get(..FVK_LEN)
        .ok_or(WalletError::InvalidBlobLength {
            expected: FVK_LEN,
            got: blob.len(),
        })?;
    let sig_bytes = blob.get(FVK_LEN..)
        .ok_or(WalletError::InvalidBlobLength {
            expected: SIG_LEN,
            got: blob.len(),
        })?;
    
    Ok(PaymentSignature::new(fvk_bytes, sig_bytes))
}
```

**Alignment with Whitepaper Vision**: The whitepaper's anti-blind-signing design requires that the wallet never signs anything without explicit verification. Malformed JSON that bypasses validation could cause the wallet to sign unintended transactions, directly violating the trustless principle of the payment gateway.

---

## 6. zkas-pool-merged (AuxPoW Merged Mining) - MEDIUM

### 6.1 Vulnerability: `MergedPending::insert_with_payee()` Unconditional Flag

**Location**: `bridge/src/merged.rs`

**Cause**:
- `insert_with_payee()` sets payee flag unconditionally on re-insert
- Could mask stale state from earlier templates
- FIFO map with cap of 4096 entries may have edge cases

**Effect**:
- **Stale state masking**: Old payee information overwrites current state
- **Fee attribution errors**: Pool vs miner fee tracking becomes inaccurate
- **Merged mining bugs**: Incorrect H_fc → ZKas block mappings
- **Miner non-payment**: Miners don't receive proper ZKAS rewards

**Severity**: MEDIUM — Affects reward distribution accuracy

**Solution**:
```rust
// merged.rs - Replace insert_with_payee() with conditional update

pub struct MergedPending {
    entries: HashMap<Hash, MergedEntry>,
    order: VecDeque<Hash>,
    cap: usize,
}

// NEW: Replace unconditional flag setting with conditional update
pub fn insert_with_payee(&mut self, h_fc: Hash, entry: MergedEntry) -> bool {
    if let Some(existing) = self.entries.get_mut(&h_fc) {
        // NEW: Only update payee flag if the new entry is newer
        // Compare generation numbers or timestamps instead of unconditional overwrite
        if entry.generation > existing.generation {
            existing.payee = entry.payee;
            existing.generation = entry.generation;
            // Log the update for audit trail
            log::info!("Updated payee for H_fc {}: {} -> {}", h_fc, existing.payee, entry.payee);
        }
        // If new entry is not newer, keep existing state
        return true;
    }
    
    // NEW entry - insert normally
    if self.entries.len() >= self.cap {
        if let Some(oldest) = self.order.pop_front() {
            self.entries.remove(&oldest);
        }
    }
    self.order.push_back(h_fc.clone());
    self.entries.insert(h_fc, entry)
}

// Add validation to prevent stale state
pub fn validate_entry(&self, entry: &MergedEntry) -> Result<(), MergeError> {
    // Verify H_fc matches the block hash commitment
    if !self.is_valid_h_fc(&entry.h_fc) {
        return Err(MergeError::InvalidHfc);
    }
    // Verify fee lane attribution is correct
    if !self.is_valid_fee_lane(&entry.fee_lane) {
        return Err(MergeError::InvalidFeeLane);
    }
    Ok(())
}
```

**Alignment with Whitepaper Vision**: The whitepaper's mining pool design specifies fair and transparent reward distribution. Stale payee information directly affects miner compensation and undermines trust in the pool's fairness.

---

### 6.2 Vulnerability: Pool Redactor Script

**Location**: `pool-redactor.py` (37KB script)

**Cause**:
- Script handles sensitive data redaction for pool logs
- 37KB size warrants review for proper data handling
- May have edge cases in redaction patterns

**Effect**:
- **Sensitive data leakage**: Improper redaction leaves secrets in logs
- **Privacy violations**: Miner addresses, payment details exposed in logs
- **Compliance failures**: Potential GDPR/data protection violations
- **Attack reconnaissance**: Attackers gather intelligence from redacted logs

**Severity**: MEDIUM — Log mishandling with privacy implications

**Solution**:
```python
# pool-redactor.py - Replace with comprehensive redaction rules

import re
import hashlib
from enum import Enum

class RedactionLevel(Enum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    STRICT = "strict"

# NEW: Comprehensive redaction configuration
REDACTION_RULES = {
    # Addresses: Hash all but last 4 characters
    "address": {
        "pattern": r'\b(kaspa|zkas|zkastest):[a-zA-Z0-9]{20,}\b',
        "replacement": lambda m: m.group(0)[:12] + '***REDACTED***',
        "level": RedactionLevel.STRICT
    },
    # Wallet identifiers: Full hash
    "wallet_id": {
        "pattern": r'wallet_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
        "replacement": lambda m: hashlib.sha256(m.group(0).encode()).hexdigest()[:16],
        "level": RedactionLevel.STANDARD
    },
    # API keys/tokens: Full redaction
    "api_key": {
        "pattern": r'(api_key|token|secret)\s*[=:]\s*["\']?[a-zA-Z0-9_\-]{16,}',
        "replacement": r'\1 = "***REDACTED***"',
        "level": RedactionLevel.STRICT
    },
    # Amounts: Keep visible for auditing
    "amount": {
        "pattern": r'amount\s*[=:]\s*(\d+\.?\d*)',
        "replacement": r'amount = \1',  # Keep amounts visible
        "level": RedactionLevel.MINIMAL
    },
    # IP addresses: Hash for analytics
    "ip_address": {
        "pattern": r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
        "replacement": lambda m: hashlib.sha256(m.group(0).encode()).hexdigest()[:8],
        "level": RedactionLevel.STANDARD
    },
}

def redact_line(line: str, level: RedactionLevel = RedactionLevel.STANDARD) -> str:
    """Apply redaction rules based on severity level"""
    result = line
    for rule_name, rule in REDACTION_RULES.items():
        if rule["level"].value >= level.value:
            result = rule["pattern"].sub(rule["replacement"], result)
    return result

def audit_redaction(original: str, redacted: str) -> dict:
    """Log what was redacted for compliance"""
    findings = []
    for rule_name, rule in REDACTION_RULES.items():
        matches = rule["pattern"].findall(original)
        if matches:
            findings.append({
                "field": rule_name,
                "count": len(matches),
                "redaction_level": rule["level"].value
            })
    return {
        "original_hash": hashlib.sha256(original.encode()).hexdigest(),
        "redacted_hash": hashlib.sha256(redacted.encode()).hexdigest(),
        "findings": findings,
        "timestamp": datetime.utcnow().isoformat()
    }
```

**Alignment with Whitepaper Vision**: The whitepaper's transparent operations model requires auditability while protecting user privacy. Proper redaction ensures compliance with data protection regulations while maintaining the ability to audit pool operations.

---

## 7. zkas-sdk (TypeScript SDK) - MEDIUM

### 7.1 Vulnerability: No HTTPS Enforcement

**Location**: `client.ts` - `#baseUrl` user-configurable without validation

**Cause**:
- Base URL configurable by user/client
- Only trailing-slash removal validation (line 57)
- No protocol validation or HTTPS enforcement
- Architecture doc acknowledges "hosted hybrid" trade-off but doesn't enforce

**Effect**:
- **Man-in-the-middle**: Unencrypted connections expose FVK, wallet tokens
- **FVK interception**: Full viewing key transmitted in plaintext
- **Token theft**: Authentication credentials intercepted
- **SSRF**: `baseUrl` used directly in template literals without protocol validation

**Severity**: MEDIUM — Requires network-level attack

**Solution**:
```typescript
// client.ts - Add HTTPS enforcement and URL validation

class ZKasClient {
  #baseUrl: string;
  
  constructor(config: ZKasClientConfig) {
    // NEW: Validate URL protocol
    this.#baseUrl = this.#validateBaseUrl(config.baseUrl);
  }
  
  // NEW: Strict URL validation
  #validateBaseUrl(url: string): string {
    // Remove trailing slash
    const cleaned = url.replace(/^https?:\/\//, '').replace(/\/$/, '');
    
    // NEW: Enforce HTTPS protocol
    const baseUrl = `https://${cleaned}`;
    
    // Validate the URL is properly formed
    try {
      const parsed = new URL(baseUrl);
      if (parsed.protocol !== 'https:') {
        throw new Error('HTTPS protocol required');
      }
      // Block localhost/internal addresses (SSRF prevention)
      if (['localhost', '127.0.0.1', '0.0.0.0', '::1'].includes(parsed.hostname)) {
        throw new Error('Localhost URLs are not allowed');
      }
      // Validate hostname format
      if (!/^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(parsed.hostname)) {
        throw new Error('Invalid hostname format');
      }
    } catch (e) {
      throw new ZKasError(`Invalid base URL: ${baseUrl}. ${e.message}`);
    }
    
    return baseUrl;
  }
  
  // NEW: Add certificate pinning (optional but recommended)
  async #fetchWithPinning(url: string, options: RequestInit): Promise<Response> {
    // Use globalThis.fetch with additional security headers
    const response = await globalThis.fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Accept': 'application/json',
        'X-Client-Version': SDK_VERSION,
      },
    });
    
    // NEW: Verify response content type
    const contentType = response.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      throw new ZKasError('Invalid response content type');
    }
    
    return response;
  }
}

// Add to package.json dependencies:
// "tls": "latest"  // Use Node.js TLS module for additional verification
```

**Alignment with Whitepaper Vision**: The whitepaper's privacy guarantees require that all communication between the wallet and daemon is encrypted. Unencrypted HTTP connections expose the full viewing key and wallet data, directly violating the privacy model.

---

### 7.2 Vulnerability: FVK Transmitted to Daemon

**Location**: `client.ts:113` - `fullViewingKeyHex()` sent to `/api/wallet/prepare`

**Cause**:
- SDK's "hosted hybrid" trust mode as primary path
- FVK transmitted to service for transaction preparation
- Architecture explicitly acknowledges: "service can observe the wallet and may censor preparation"
- Trade-off documented but not mitigated with alternatives

**Effect**:
- **Wallet surveillance**: Service observes all wallet activity
- **Censorship**: Service can block transaction preparation
- **Privacy violation**: Full viewing key exposed to intermediate service
- **No user control**: Cannot opt-out without switching trust modes

**Severity**: MEDIUM — Trust model limitation

**Solution**:
```typescript
// client.ts - Add alternative trust modes with privacy enhancements

enum TrustMode {
  HostedHybrid = 'hosted_hybrid',    // Current default
  LocalOnly = 'local_only',           // NEW: Fully local signing
  PrivacyProxy = 'privacy_proxy',     // NEW: Encrypted proxy mode
}

class ZKasClient {
  #trustMode: TrustMode;
  
  // NEW: Allow users to configure their trust model
  constructor(config: ZKasClientConfig & { trustMode?: TrustMode }) {
    this.#trustMode = config.trustMode ?? TrustMode.HostedHybrid;
  }
  
  // NEW: Local-only mode - FVK never leaves the client
  async preparePaymentLocal(paymentRequest: PaymentRequest): Promise<PreparedPaymentEnvelope> {
    if (this.#trustMode !== TrustMode.LocalOnly) {
      throw new ZKasError('Local-only mode required for this operation');
    }
    
    // Full wallet preparation happens locally
    // FVK is never transmitted to any external service
    const proof = await this.#generateProofLocally(paymentRequest);
    const envelope = await this.#constructEnvelopeLocally(proof);
    
    return envelope;
  }
  
  // NEW: Privacy proxy mode - Encrypted FVK transmission
  async preparePaymentPrivacyProxy(paymentRequest: PaymentRequest): Promise<PreparedPaymentEnvelope> {
    if (this.#trustMode !== TrustMode.PrivacyProxy) {
      throw new ZKasError('Privacy proxy mode required for this operation');
    }
    
    // NEW: Encrypt FVK before transmission
    const encryptedFvk = await this.#encryptFvkForService();
    const response = await this.#request('/api/wallet/prepare', {
      ...paymentRequest,
      fvk_hex: encryptedFvk,  // Encrypted, not plaintext
    });
    
    return response;
  }
  
  // NEW: Add opt-out mechanism from hosted hybrid mode
  async switchToLocalMode(): Promise<void> {
    log.warn('Switching to local-only mode - FVK will no longer be transmitted');
    this.#trustMode = TrustMode.LocalOnly;
    // Clear any cached FVK from memory
    await this.clearFvkCache();
  }
  
  // NEW: Add user notification when FVK is transmitted
  private async #request(path: string, body: any): Promise<any> {
    if (this.#trustMode === TrustMode.HostedHybrid && path.includes('/wallet/')) {
      log.warn('FVK will be transmitted to daemon in hosted hybrid mode');
      // NEW: Prompt user confirmation
      if (!await this.confirmPrivacyTradeOff()) {
        throw new ZKasError('User declined FVK transmission');
      }
    }
    return this.#requestInternal(path, body);
  }
}
```

**Alignment with Whitepaper Vision**: The whitepaper's privacy model specifies that users can choose their trust model. By default, the SDK uses "hosted hybrid" mode which exposes the FVK to the service. Providing local-only and privacy proxy alternatives gives users control over their privacy, directly supporting the whitepaper's privacy guarantees.

---

## 8. zkas-website (Static HTML) - MEDIUM

### 8.1 Vulnerability: Missing Content Security Policy

**Location**: All HTML files - no CSP header or meta tag

**Cause**:
- Static HTML site, CSP would need web server configuration
- No `<meta http-equiv="Content-Security-Policy">` directive
- No `X-Content-Security-Policy` header
- Site serves over HTTPS but has no content restriction

**Effect**:
- **Unrestricted XSS**: Any XSS vector executes freely without CSP restrictions
- **Arbitrary code execution**: Third-party scripts can run with full browser permissions
- **Data exfiltration**: No mitigations against information leakage
- **Clickjacking**: No `X-Frame-Options` to prevent framing attacks

**Severity**: MEDIUM — Lowers bar for XSS exploitation

**Solution**:
```html
<!-- index.html - Add CSP meta tag to ALL HTML files -->
<!-- Add in <head> section of every HTML file -->

<meta http-equiv="Content-Security-Policy" content="
  default-src 'self';
  script-src 'self';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self' data:;
  connect-src 'self' https:;
  frame-src 'none';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests;
">

<meta http-equiv="X-Content-Security-Policy" content="
  default-src 'self';
  script-src 'self';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self' data:;
  frame-src 'none';
  object-src 'none';
">

<!-- Add X-Frame-Options -->
<meta http-equiv="X-Frame-Options" content="DENY">

<!-- Add Referrer-Policy -->
<meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">

<!-- Add Permissions-Policy -->
<meta http-equiv="Permissions-Policy" content="
  camera=(),
  microphone=(),
  geolocation=(),
  payment=()
">
```

**Alignment with Whitepaper Vision**: The whitepaper emphasizes security as a foundational principle. CSP headers protect against XSS injection attacks that could compromise the entire website. These headers are essential for maintaining the trust the project places in its web presence.

---

### 8.2 Vulnerability: Missing X-Frame-Options

**Location**: All HTML files

**Cause**:
- No `X-Frame-Options: DENY` or `SAMEORIGIN` header
- Site vulnerable to clickjacking attacks
- Standard security header omitted from static site

**Effect**:
- **Clickjacking**: Users tricked into clicking invisible elements
- **UI redress**: Malicious overlays capture user interactions
- **Session hijacking**: Hidden buttons trigger unwanted actions
- **Combined with XSS**: Amplifies attack chain

**Severity**: MEDIUM — Enables clickjacking attack surface

**Solution**:
```html
<!-- Add to ALL HTML files in <head> -->
<meta http-equiv="X-Frame-Options" content="DENY">
<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none';">
```

**Server-side nginx configuration** (if available):
```nginx
add_header X-Frame-Options "DENY" always;
add_header X-Content-Security-Policy "frame-ancestors 'none'" always;
```

**Alignment with Whitepaper Vision**: The whitepaper's security-first approach requires protection against all common web attacks, including clickjacking. The X-Frame-Options header prevents malicious sites from embedding the website in invisible frames.

---

### 8.3 Vulnerability: External API Without CORS/SRI Checks

**Location**: `reserves.html` - `fetch('https://mining-pool.zkas.info/api/otc/reserves')`

**Cause**:
- API call over HTTPS but no CORS or SRI (Subresource Integrity) checks
- Response injected directly into DOM via `innerHTML`
- If API compromised, arbitrary HTML injection possible

**Effect**:
- **API compromise XSS**: If `mining-pool.zkas.info` hacked, response executes in browser
- **Data tampering**: Reserve information modified without user knowledge
- **Trust erosion**: Users see fake reserve data
- **Combined with missing CSP**: No mitigations available

**Severity**: MEDIUM — Depends on external service security

**Solution**:
```html
<!-- reserves.html - Replace fetch with validated request -->
<script>
// NEW: Validate API response before displaying
async function fetchReserves() {
  const response = await fetch('https://mining-pool.zkas.info/api/otc/reserves', {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
    // NEW: Add cache busting to prevent stale data
    cache: 'no-cache',
  });
  
  if (!response.ok) {
    console.error('Failed to fetch reserves:', response.status);
    return;
  }
  
  const data = await response.json();
  
  // NEW: Validate response structure before displaying
  if (!isValidReservesData(data)) {
    console.error('Invalid reserves data received');
    displayError('Failed to load reserve data');
    return;
  }
  
  // NEW: Use textContent instead of innerHTML to prevent XSS
  const container = document.getElementById('reserves-container');
  // Use safe DOM manipulation instead of innerHTML
  container.textContent = formatReserves(data);
  // Or use DOM API:
  // const el = document.createElement('div');
  // el.textContent = data.value; // Safe - no HTML rendering
}

// NEW: Validate reserves data structure
function isValidReservesData(data) {
  if (!data || typeof data !== 'object') return false;
  if (typeof data.asOf !== 'string') return false;
  if (typeof data.totalReserves !== 'number') return false;
  if (data.totalReserves < 0) return false;
  // Add more validation rules
  return true;
}

// NEW: Safe formatting function
function formatReserves(data) {
  // Use textContent instead of innerHTML
  return `${new Date(data.asOf).toLocaleString()} · Total Reserves: ${data.totalReserves}`;
}
</script>
```

**Alignment with Whitepaper Vision**: The whitepaper's transparent operations model requires accurate data display. Compromised external APIs that display fake reserve data undermine user trust. Proper data validation ensures users see accurate information.

---

## 9. zkas-paper-wallet (HTML WASM Generator) - GOOD

### Assessment: No Critical Vulnerabilities Found

**Positive Factors**:
- **WASM integrity**: sha256 hash `ea0ec55a2cef0bb7f3cd6ce80b0e5c218693e0e97be49c80a73587b1eefcd409` (594044 bytes) documented in README for manual verification
- **Entropy source**: `crypto.getRandomValues()` - browser's cryptographically secure PRNG
- **Private key generation**: `new_wallet()` generates 32-byte seed; retries if invalid Orchard key (negligible probability)
- **HTML/JS security**: Zero network requests; no external dependencies; `autocomplete="off"` on seed input
- **Address display**: Address/view key safe to share; seed blurred until "Reveal"; print intentionally reveals
- **QR code generation**: Inlined MIT-licensed qrcode library; pure JS; no network calls
- **Offline enforcement**: Warning banner; documented air-gapped workflow; Network tab verification recommended

**Additional Recommendations**:
```html
<!-- Add to index.html for enhanced security -->
<!-- Subresource integrity for WASM loading -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'none'; frame-src 'none';">
<!-- Add X-Frame-Options -->
<meta http-equiv="X-Frame-Options" content="DENY">
<!-- Add integrity verification -->
<script>
// Verify WASM integrity hash matches documented hash
const EXPECTED_WASM_HASH = 'ea0ec55a2cef0bb7f3cd6ce80b0e5c218693e0e97be49c80a73587b1eefcd409';
// Add runtime verification
if (typeof crypto !== 'undefined' && crypto.subtle) {
  // Verify WASM blob integrity before instantiation
}
</script>
```

**Severity**: GOOD — Well-audited offline client-side generator

---

## 10. zkas-rusty (Rust Core) - Needs Review

**Status**: Core Rust implementation would require detailed cryptographic review
- **Current analysis**: Insufficient depth for complete assessment
- **Likely areas**: Cryptographic curve operations, ZKP verification, consensus rules
- **Recommendation**: Full formal verification of core cryptographic primitives

**Additional Audit Recommendations**:
```rust
// zkas-rusty/Cargo.toml - Add security dependencies
// Add to dependencies:
// ring = "0.17"  # For validated cryptographic operations
// subtle = "2.5" # For constant-time operations
// zeroize = "1.5" # For memory zeroization

// Audit checklist for zkas-rusty:
// 1. Verify all cryptographic operations use constant-time implementations
// 2. Check for proper zeroization of sensitive intermediate values
// 3. Verify Orchard protocol implementation matches zcash reference
// 4. Audit ZKP verification circuit for soundness
// 5. Review consensus rules for edge cases
// 6. Validate all input parsing for boundary conditions
// 7. Check for integer overflow/underflow in all arithmetic operations
// 8. Review error handling for information leakage
```

---

## Cross-Repository Security Patterns

### Summary of Root Causes and Effects

| Pattern | Root Cause | Effect | Affected Repos | Solution |
|---------|-----------|--------|----------------|----------|
| **Fallback to insecure default** | Convenience over security design | Silent fund redirection, data exposure | zkas-wallet, zkas-pool | Throw explicit errors instead of silent fallbacks |
| **No authentication** | Assumed trusted environment | Unauthorized access, data leakage | zkas-pool API, zkas-sdk | Add API key authentication middleware |
| **XSS from API data** | Trusting remote sources | Remote code execution | zkas-explorer | Implement DOMPurify sanitization |
| **Missing security headers** | Static site simplicity | Clickjacking, unrestricted XSS | zkas-website | Add CSP, X-Frame-Options headers |
| **Plaintext sensitive data** | No zeroization/encryption | Memory forensics, key theft | zkas-signer, zkas-wallet | Implement zeroize library, encrypt at rest |
| **Incomplete validation** | Performance/usability trade-offs | Boundary conditions, edge case exploits | zkas-signer, zkas-sdk, vprogs-zkas | Add strict input validation with bounds checking |
| **Trust model limitations** | Architecture trade-offs | Wallet surveillance, privacy violation | zkas-sdk, zkas-signer | Provide local-only and privacy proxy alternatives |

---

## Complete Remediation Roadmap

### Phase 1: Immediate (Critical/HIGH) - Week 1
| Priority | Repository | Action | File/Location |
|----------|-----------|--------|---------------|
| 1 | zkas-explorer | Implement DOMPurify sanitization | `app/PageTable.tsx`, `app/KasLink.tsx` |
| 2 | zkas-wallet | Encrypt sensitive data in localStorage | `src/deviceSeed.ts`, `src/accounts.ts`, `src/applock.ts` |
| 3 | zkas-pool | Add API authentication + fix silent fallback | `api/src/lib.rs`, `bridge/src/default_client.rs` |
| 4 | zkas-signer | Implement zeroize for WASM memory | `src/lib.rs` |
| 5 | zkas-pool-merged | Fix insert_with_payee unconditional flag | `bridge/src/merged.rs` |

### Phase 2: High Priority - Week 2-3
| Priority | Repository | Action |
|----------|-----------|--------|
| 1 | vprogs-zkas | Document dev/production gap, add budget validation |
| 2 | zkas-sdk | Enforce HTTPS, add trust mode alternatives |
| 3 | zkas-website | Add CSP, X-Frame-Options, sanitize external API |
| 4 | zkas-signer | Add JSON field validation in verify_and_sign_payment |

### Phase 3: Medium Priority - Week 4
| Priority | Repository | Action |
|----------|-----------|--------|
| 1 | zkas-pool-merged | Review pool-redactor.py |
| 2 | solo-dual-mode | Minor merged mining refinements |
| 3 | zkas-rusty | Schedule formal cryptographic verification |
| 4 | zkas-paper-wallet | Add runtime WASM integrity verification |

---

## Security Architecture Alignment Summary

The project's whitepaper and architecture documentation emphasize the following security principles:

1. **Trustless Operation**: No single party should be able to compromise user funds — addressed by fixing silent fallback mechanisms
2. **Privacy by Default**: Users should have full control over their data exposure — addressed by adding local-only modes and zeroization
3. **Transparency**: All operations should be auditable — addressed by proper logging and audit trails
4. **Defense in Depth**: Multiple layers of security controls — addressed by adding CSP, authentication, and encryption layers
5. **Secure by Design**: Security considerations from the start — addressed by adding validation to all input paths

Each solution provided in this report aligns with the project's whitepaper vision of building a secure, private, and trustworthy shielded cryptocurrency ecosystem on Kaspa.

---

*Audit Scope: 12 repositories under github.com/firecash*  
*Analysis Method: Code review of source files, Cargo.toml, package.json, and key configuration files*  
*Audit Date: September 6, 2026*  
*Report Updated: September 6, 2026*  
*All solutions aligned with project whitepaper vision and README documentation*
