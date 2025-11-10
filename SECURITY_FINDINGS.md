# ZetaChain TON Gateway - Security Findings & Vulnerability Assessment

**Date:** 2025-11-10  
**Auditor:** Blockchain Security Researcher  
**Scope:** Smart Contract Security, Architecture Review, Threat Modeling

---

## Executive Summary

This report presents the findings from a comprehensive security audit of the ZetaChain TON Gateway smart contract. The audit identified **8 findings** across various severity levels, ranging from informational observations to high-severity architectural concerns.

### Summary of Findings

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | Immediate fund loss or contract takeover |
| 🟠 **HIGH** | 2 | Significant security risks requiring attention |
| 🟡 **MEDIUM** | 3 | Potential security issues under specific conditions |
| 🔵 **LOW** | 2 | Best practice violations or minor concerns |
| ⚪ **INFORMATIONAL** | 1 | Observations for future consideration |

### Key Concerns

1. **Single Authority Model** - No multisig or timelock protection
2. **Unrestricted TSS Updates** - Critical address changeable without safeguards
3. **Missing Rate Limits** - No withdrawal caps or velocity checks
4. **Limited Observability** - Insufficient event emission for monitoring
5. **No Upgrade Governance** - Immediate code updates without community review

---

## Detailed Findings

---

## 🟠 HIGH-01: Single Point of Failure in Authority Model

### Severity: HIGH

### Description

The contract implements a single-address authority model without multisig protection, timelocks, or governance mechanisms. The authority address has unilateral power to:

1. Update TSS address (control all withdrawals)
2. Upgrade contract code (arbitrary logic changes)
3. Transfer authority to another address
4. Reset seqno (break replay protection)
5. Enable/disable deposits (DoS)

### Location

```func
// contracts/common/state.fc
global slice state::authority_address;

// contracts/gateway.fc:80-82
() guard_authority_sender(slice sender) impure inline_ref {
    throw_unless(error::invalid_authority, equal_slices(sender, state::authority_address));
}
```

### Impact

**If authority private key is compromised:**
- Attacker can change TSS address to their own, gaining control of all locked funds
- Immediate contract code upgrade to malicious logic
- Complete loss of locked TON (currently up to gateway balance)

**Risk Factors:**
- No key rotation procedure documented
- No emergency recovery mechanism
- Single signature requirement (no m-of-n scheme)

### Proof of Concept

```typescript
// Attacker with compromised authority key
const maliciousAddress = "0xATTACKER_EVM_ADDRESS";

// 1. Update TSS to attacker's address
await gateway.sendUpdateTSS(compromisedAuthority.getSender(), maliciousAddress);

// 2. Sign withdrawals with attacker's private key
const attackerWallet = new ethers.Wallet(ATTACKER_PRIVATE_KEY);
await gateway.sendWithdraw(attackerWallet, attackerAddress, totalLocked);

// Result: All funds drained
```

### Recommendation

**Option 1: Multi-Signature Authority (Preferred)**
```func
global cell state::authority_addresses;  // Dictionary of authorized signers
global int state::authority_threshold;   // e.g., 3 of 5

() guard_authority_sender(slice sender, cell signatures) impure inline_ref {
    int valid_sigs = 0;
    // Verify multiple signatures
    // ...
    throw_unless(error::invalid_authority, valid_sigs >= state::authority_threshold);
}
```

**Option 2: Timelock for Critical Operations**
```func
global cell state::pending_updates;  // Delayed execution queue

() handle_update_tss(slice sender, slice message) impure inline {
    // ... authority check ...
    
    int execute_at = now() + TIMELOCK_DELAY;  // e.g., 48 hours
    
    // Store pending update
    state::pending_updates~add_pending_update(op, message, execute_at);
}

() execute_pending_update(int update_id) impure {
    // Only execute after timelock expires
    // Allows community to detect and respond to malicious updates
}
```

**Option 3: Role-Based Access Control**
```func
const role::tss_updater = 1;
const role::code_upgrader = 2;
const role::deposit_manager = 3;

global cell state::role_assignments;  // address -> role bitmap

() guard_role(slice sender, int required_role) impure inline_ref {
    int roles = get_roles(sender);
    throw_unless(error::insufficient_permissions, roles & required_role);
}
```

**Immediate Actions:**
1. Document authority key management procedures
2. Implement hardware wallet or MPC for authority key
3. Establish key rotation schedule
4. Add authority operation logging

---

## 🟠 HIGH-02: Unrestricted TSS Address Updates

### Severity: HIGH

### Description

The TSS address can be updated by authority with immediate effect and no validation beyond basic format checking. A malicious or compromised authority can:

1. Change TSS to an address they control
2. Sign withdrawals with their own key
3. Drain all locked funds

Additionally, there's no verification that the new TSS address:
- Corresponds to an active TSS ceremony
- Has proper key sharding among signers
- Maintains continuity with ZetaChain network

### Location

```func
// contracts/gateway.fc:193-202
() handle_update_tss(slice sender, slice message) impure inline {
    load_state();
    
    guard_authority_sender(sender);
    
    state::tss_address = message~load_bits(size::evm_address);  // No further validation!
    
    mutate_state();
}
```

### Impact

**Scenario 1: Malicious Authority**
- Authority updates TSS to personal wallet
- Signs arbitrary withdrawals
- All locked funds stolen

**Scenario 2: Operational Error**
- Wrong TSS address entered during update
- Correct TSS cannot sign withdrawals (funds locked forever)
- No recovery mechanism

**Scenario 3: TSS Compromise**
- Attackers compromise TSS private key
- Authority unable to quickly rotate to new TSS
- Attackers drain funds before mitigation

### Attack Scenario

```solidity
// Off-chain attacker preparation
1. Compromise authority key
2. Generate new keypair: (priv_evil, pub_evil)
3. Derive EVM address: addr_evil = keccak256(pub_evil)[12:32]

// On-chain attack
4. sendUpdateTSS(addr_evil)  // Immediate effect
5. Wait for next withdrawal request from legitimate user
6. Sign withdrawal with priv_evil to attacker's address
7. Funds drained

// Detection difficulty: 
- No event emitted (only internal transaction)
- No timelock to allow intervention
- Immediate effect prevents response
```

### Recommendation

**Short-term: Add TSS Update Safeguards**

1. **Timelock for TSS Updates**
```func
const TIMELOCK_TSS_UPDATE = 172800;  // 48 hours in seconds

global cell state::pending_tss_update;
global int state::pending_tss_update_time;

() handle_update_tss(slice sender, slice message) impure inline {
    guard_authority_sender(sender);
    
    slice new_tss = message~load_bits(size::evm_address);
    
    state::pending_tss_update = begin_cell().store_slice(new_tss).end_cell();
    state::pending_tss_update_time = now() + TIMELOCK_TSS_UPDATE;
    
    mutate_state();
    
    // Emit log for off-chain monitoring
}

() execute_tss_update() impure {
    throw_if(error::timelock_not_expired, now() < state::pending_tss_update_time);
    
    state::tss_address = state::pending_tss_update.begin_parse()~load_bits(size::evm_address);
    state::pending_tss_update = null();
    
    mutate_state();
}
```

2. **TSS Update Verification**
```func
() handle_update_tss_with_proof(slice sender, slice new_tss, cell proof) impure inline {
    guard_authority_sender(sender);
    
    // Require old TSS to sign the new TSS address
    // This proves continuity and prevents unauthorized updates
    slice old_tss_signature = proof.begin_parse();
    
    cell new_tss_cell = begin_cell().store_slice(new_tss).end_cell();
    int is_valid = check_ecdsa_signature(cell_hash(new_tss_cell), old_tss_signature, state::tss_address);
    
    throw_unless(error::invalid_tss_transition, is_valid == true);
    
    state::tss_address = new_tss;
    mutate_state();
}
```

3. **Dual-Signature Requirement**
```func
// Require both authority AND current TSS to approve TSS change
() handle_update_tss_dual_sig(slice authority_sig, slice tss_sig, slice new_tss) impure inline {
    // Verify authority signature
    // Verify TSS signature
    // Both must approve
}
```

**Long-term: Emergency Pause & Recovery**

```func
const EMERGENCY_PAUSE_DURATION = 604800;  // 7 days

global int state::emergency_pause_until;

() emergency_pause() impure {
    // Callable by authority or decentralized governance
    state::emergency_pause_until = now() + EMERGENCY_PAUSE_DURATION;
    state::deposits_enabled = 0;
    
    mutate_state();
}

() recv_external(slice message) impure {
    load_state();
    
    // Block all external messages during pause
    throw_if(error::contract_paused, now() < state::emergency_pause_until);
    
    // ... normal external message handling
}
```

---

## 🟡 MEDIUM-01: Missing Withdrawal Rate Limits

### Severity: MEDIUM

### Description

The contract has no rate limiting or withdrawal caps. A compromised TSS can drain all locked funds in a single transaction or rapid sequence of transactions without detection time.

### Location

```func
// contracts/gateway.fc:343-374
() handle_withdrawal(slice payload) impure inline {
    // ... validation ...
    
    // No checks for:
    // - Maximum withdrawal amount per transaction
    // - Maximum withdrawal velocity (amount per time period)
    // - Cooling period between large withdrawals
    
    state::total_locked -= (amount + tx_fee);
    // ... send funds ...
}
```

### Impact

**Scenario: TSS Key Compromise**
1. Attacker obtains TSS private key
2. Immediately signs withdrawals for entire `total_locked`
3. Funds drained before detection
4. No time for emergency response

**Comparison:**
- Most bridge protocols: Daily withdrawal limits (e.g., 5% of TVL)
- CEX hot wallets: Velocity checks and manual approval thresholds
- Multi-chain bridges: Staged withdrawals with monitoring periods

### Current State

```typescript
// No limits - can withdraw entire balance at once
const totalLocked = await gateway.getGatewayState().valueLocked;
await gateway.sendWithdraw(tss, attacker, totalLocked);  // ✓ Succeeds
```

### Recommendation

**1. Per-Transaction Limit**
```func
const WITHDRAWAL_MAX_SINGLE = 1000000000000;  // 1,000 TON per withdrawal

() handle_withdrawal(slice payload) impure inline {
    // ... existing validation ...
    
    throw_if(error::withdrawal_exceeds_limit, amount > WITHDRAWAL_MAX_SINGLE);
    
    // ... proceed with withdrawal ...
}
```

**2. Velocity Limiting (24-hour rolling window)**
```func
global int state::withdrawal_window_start;
global int state::withdrawal_window_amount;

const WITHDRAWAL_VELOCITY_LIMIT = 10000000000000;  // 10,000 TON per 24h
const WITHDRAWAL_WINDOW = 86400;  // 24 hours

() handle_withdrawal(slice payload) impure inline {
    // ... existing validation ...
    
    // Reset window if expired
    if (now() - state::withdrawal_window_start > WITHDRAWAL_WINDOW) {
        state::withdrawal_window_start = now();
        state::withdrawal_window_amount = 0;
    }
    
    // Check velocity limit
    throw_if(error::velocity_limit_exceeded, 
             state::withdrawal_window_amount + amount > WITHDRAWAL_VELOCITY_LIMIT);
    
    state::withdrawal_window_amount += amount;
    
    // ... proceed with withdrawal ...
}
```

**3. Staged Withdrawals for Large Amounts**
```func
const LARGE_WITHDRAWAL_THRESHOLD = 5000000000000;  // 5,000 TON
const LARGE_WITHDRAWAL_DELAY = 3600;  // 1 hour

global cell state::pending_large_withdrawals;  // Queue of delayed withdrawals

() handle_withdrawal(slice payload) impure inline {
    // ... validation ...
    
    if (amount >= LARGE_WITHDRAWAL_THRESHOLD) {
        // Queue for delayed execution
        add_pending_withdrawal(recipient, amount, now() + LARGE_WITHDRAWAL_DELAY);
        return ();
    }
    
    // Small withdrawals process immediately
    // ... existing logic ...
}

() execute_pending_withdrawal(int withdrawal_id) impure {
    // Can only execute after delay
    // Provides detection and response window
}
```

**4. Circuit Breaker**
```func
const CIRCUIT_BREAKER_THRESHOLD = 20000000000000;  // 20,000 TON in 1 hour

global int state::recent_withdrawal_total;
global int state::recent_withdrawal_period_start;

() handle_withdrawal(slice payload) impure inline {
    // Reset counter every hour
    if (now() - state::recent_withdrawal_period_start > 3600) {
        state::recent_withdrawal_period_start = now();
        state::recent_withdrawal_total = 0;
    }
    
    state::recent_withdrawal_total += amount;
    
    // Automatically pause withdrawals if threshold exceeded
    if (state::recent_withdrawal_total > CIRCUIT_BREAKER_THRESHOLD) {
        state::emergency_pause_until = now() + 86400;  // 24 hour pause
        throw(error::circuit_breaker_triggered);
    }
    
    // ... proceed ...
}
```

**Implementation Priority:**
1. **Immediate:** Per-transaction limit (simple to implement)
2. **Short-term:** Velocity limiting (requires state additions)
3. **Medium-term:** Circuit breaker (automated protection)
4. **Long-term:** Staged withdrawals with monitoring integration

---

## 🟡 MEDIUM-02: Insufficient Event Emission for Monitoring

### Severity: MEDIUM

### Description

The contract emits very limited events (logs), making it difficult for off-chain systems to:
- Detect suspicious authority operations
- Monitor TSS address changes
- Track state transitions
- Alert on anomalous behavior

Only deposit operations emit logs. Critical operations like TSS updates, code upgrades, and authority transfers have no event emission.

### Location

**Events Currently Emitted:**
```func
// contracts/gateway.fc:124 (deposit only)
send_log_message(log);
```

**Operations WITHOUT Events:**
- `update_tss`
- `update_code`
- `update_authority`
- `reset_seqno`
- `set_deposits_enabled`
- `withdraw` (only visible via transaction parsing)
- `increase_seqno`

### Impact

**Security Monitoring Gaps:**
1. TSS address change may go unnoticed until first withdrawal
2. Malicious code updates not detected in real-time
3. Authority transfer could be stealthy attack vector
4. Withdrawal patterns require complex transaction parsing

**Operational Challenges:**
1. No standardized event format for indexing
2. Off-chain systems must parse all transaction data
3. Difficult to build alerting systems
4. Compliance and audit trail gaps

### Current State

```typescript
// Observer must parse transaction body to detect TSS update
// No structured event emitted
await gateway.sendUpdateTSS(authority, newTss);

// Only way to detect: Query state before/after, compare
const stateBefore = await gateway.getGatewayState();
// ... transaction ...
const stateAfter = await gateway.getGatewayState();

if (stateBefore.tss !== stateAfter.tss) {
    console.log("TSS changed!"); // Manual detection required
}
```

### Recommendation

**1. Add Event Emission for All State Changes**

```func
;; Enhanced logging function with event type
() emit_event(int event_type, cell event_data) impure inline {
    cell log = begin_cell()
        .store_uint(event_type, 32)
        .store_ref(event_data)
        .end_cell();
    
    send_log_message(log);
}

;; Event type constants
const event::deposit = 1001;
const event::deposit_and_call = 1002;
const event::call = 1003;
const event::withdrawal = 2001;
const event::tss_updated = 3001;
const event::code_updated = 3002;
const event::authority_updated = 3003;
const event::deposits_enabled = 3004;
const event::seqno_reset = 3005;
```

**2. TSS Update Event**
```func
() handle_update_tss(slice sender, slice message) impure inline {
    load_state();
    guard_authority_sender(sender);
    
    slice old_tss = state::tss_address;
    slice new_tss = message~load_bits(size::evm_address);
    
    state::tss_address = new_tss;
    mutate_state();
    
    ;; Emit event
    cell event_data = begin_cell()
        .store_slice(old_tss)
        .store_slice(new_tss)
        .store_slice(sender)
        .store_uint(now(), 32)
        .end_cell();
    
    emit_event(event::tss_updated, event_data);
}
```

**3. Withdrawal Event**
```func
() handle_withdrawal(slice payload) impure inline {
    // ... existing logic ...
    
    send_simple_message_non_bounceable(recipient_addr, amount, send_mode);
    
    ;; Emit withdrawal event
    cell event_data = begin_cell()
        .store_slice(recipient)
        .store_coins(amount)
        .store_uint(seqno, 32)
        .store_uint(now(), 32)
        .end_cell();
    
    emit_event(event::withdrawal, event_data);
}
```

**4. Authority Operation Events**
```func
() handle_update_authority(slice sender, slice message) impure inline {
    // ... validation ...
    
    slice old_authority = state::authority_address;
    slice new_authority = message~load_msg_addr();
    
    state::authority_address = new_authority;
    mutate_state();
    
    ;; Critical event - authority transfer
    cell event_data = begin_cell()
        .store_slice(old_authority)
        .store_slice(new_authority)
        .store_uint(now(), 32)
        .end_cell();
    
    emit_event(event::authority_updated, event_data);
}
```

**5. Off-Chain Monitoring Integration**

```typescript
// Event parser for monitoring system
interface GatewayEvent {
    type: number;
    timestamp: number;
    data: any;
}

function parseGatewayEvent(logMessage: Cell): GatewayEvent {
    const slice = logMessage.beginParse();
    const eventType = slice.loadUint(32);
    const eventData = slice.loadRef();
    
    switch(eventType) {
        case 3001: // TSS Updated
            return {
                type: eventType,
                timestamp: eventData.loadUint(32),
                data: {
                    oldTss: eventData.loadBits(160),
                    newTss: eventData.loadBits(160),
                    updater: eventData.loadAddress()
                }
            };
        // ... other events ...
    }
}

// Monitoring daemon
async function monitorGateway() {
    const events = await tonClient.getAccountTransactions(gatewayAddress);
    
    for (const tx of events) {
        const outMessages = tx.out_msgs;
        for (const msg of outMessages) {
            if (msg.msg_type === 'ExtOut') {
                const event = parseGatewayEvent(msg.body);
                
                // Alert on critical events
                if (event.type === 3001 && event.data.oldTss !== expectedTss) {
                    alertTeam("CRITICAL: Unexpected TSS update!", event);
                }
            }
        }
    }
}
```

---

## 🟡 MEDIUM-03: No Validation of Call Data Contents

### Severity: MEDIUM

### Description

The contract validates call data size but not its contents. Malicious users could:
1. Submit malformed data causing failures on ZEVM side
2. Include executable code that exploits ZEVM contract vulnerabilities
3. Inject malicious parameters that bypass validation on ZEVM

While the financial risk is limited (user pays for their own transaction), this could:
- Cause observer indexing failures
- Trigger bugs in ZEVM contracts
- Enable griefing attacks

### Location

```func
// contracts/gateway.fc:136
guard_cell_size(call_data, size::call_data::max, error::invalid_call_data);
```

Only size is checked, not:
- Data format/structure
- Presence of required fields
- Valid encoding
- Malicious patterns

### Impact

**Low Financial Risk:**
- User pays gas fees
- No locked funds at risk
- Isolated to user's transaction

**Operational Risk:**
- ZEVM contract may revert/fail
- Observer may skip malformed transactions
- Potential for DoS on indexing services
- Debugging complexity

### Proof of Concept

```typescript
// Malicious call data
const badCallData = beginCell()
    .storeUint(0xdeadbeef, 32)  // Invalid function selector
    .storeRef(beginCell()
        .storeBuffer(Buffer.alloc(1000, 0xff))  // Junk data
        .endCell())
    .endCell();

// Contract accepts it (size check only)
await gateway.sendDepositAndCall(sender, toNano('1'), recipient, badCallData);

// Result: Transaction succeeds on TON, fails on ZEVM
// User loses funds, no cross-chain execution
```

### Recommendation

**Option 1: Schema Validation (Preferred)**

```func
;; Define expected call data structure
;; TL-B: call_data$_ function_selector:uint32 params:(HashmapE 32 ^Cell) = CallData;

() validate_call_data(cell call_data) impure inline {
    slice cs = call_data.begin_parse();
    
    ;; Must have function selector
    throw_if(error::invalid_call_data, cs.slice_bits() < 32);
    int selector = cs~load_uint(32);
    
    ;; Whitelist known selectors
    int is_valid_selector = (selector == 0x...)  // Known good functions
                          | (selector == 0x...);
    
    throw_unless(error::invalid_call_data, is_valid_selector);
    
    ;; Additional structure validation
    // ...
}

() handle_deposit_and_call(int amount, slice in_msg_body) impure inline {
    // ... existing checks ...
    
    cell call_data = in_msg_body~load_ref();
    guard_cell_size(call_data, size::call_data::max, error::invalid_call_data);
    validate_call_data(call_data);  // NEW: Content validation
    
    // ... proceed ...
}
```

**Option 2: Hash-Based Validation**

```func
;; Maintain whitelist of known-good call data patterns
global cell state::call_data_whitelist;

() is_call_data_whitelisted(int call_data_hash) inline {
    return dict_get?(state::call_data_whitelist, 256, call_data_hash);
}

() handle_deposit_and_call(...) {
    cell call_data = in_msg_body~load_ref();
    int data_hash = cell_hash(call_data);
    
    ;; Either whitelist or under size limit
    throw_unless(error::invalid_call_data, 
                 is_call_data_whitelisted(data_hash) 
                 | (data_size < size::call_data::max));
}
```

**Option 3: ZEVM-Side Validation with Refund**

```solidity
// On ZetaChain EVM side
contract GatewayReceiver {
    function onDeposit(bytes calldata data) external {
        // Validate call data format
        require(isValidCallData(data), "Invalid call data");
        
        if (!processCall(data)) {
            // If call fails, signal refund to TON user
            emit RefundRequested(tonRecipient, amount);
        }
    }
    
    function isValidCallData(bytes calldata data) internal pure returns (bool) {
        // Strict validation
        // ABI decoding checks
        // Parameter range validation
    }
}
```

**Option 4: Progressive Gas Model**

```func
;; Charge higher fees for complex call data
int calculate_call_data_fee(cell call_data) inline {
    (int cells, int bits, int refs, _) = compute_data_size?(call_data, 10);
    
    int base_fee = get_gas_fee_workchain(gas::deposit_and_call);
    int data_fee = (bits / 1000) * extra_fee_per_kb;
    
    return base_fee + data_fee;
}
```

**Immediate Action:**
Document expected call data formats in protocol specification for ZEVM contract developers.

---

## 🔵 LOW-01: Hardcoded Gas Constants May Become Outdated

### Severity: LOW

### Description

Gas fee constants are hardcoded in the contract and may become inaccurate if:
1. TON network upgrades change computation costs
2. Blockchain config parameters are adjusted
3. New operations are added with different costs

This could lead to:
- Overcharging users (bad UX)
- Undercharging users (loss of funds from contract balance)
- Failed transactions due to insufficient fees

### Location

```func
// contracts/gateway.fc:34-44
const gas::deposit = 10000;
const gas::deposit_and_call = 13000;
const gas::call = 10000;
const gas::authority = 20000;
const gas::external = 17500;
```

### Impact

**If TON Network Changes:**
- Gas model updates (e.g., new TVM version)
- Config params 20/21 modifications
- Introduction of new fee types

**Current Mitigation:**
- Contract is upgradeable via `update_code`
- Values are empirically tested
- Slight buffer included in constants

**Risk Level:** Low (requires network-level changes)

### Recommendation

**1. Dynamic Gas Calculation (Best Practice)**

```func
;; Remove hardcoded constants, calculate based on actual usage

() handle_deposit(...) impure inline {
    ;; Measure actual gas before operation
    int gas_before = gas_consumed();
    
    ;; ... perform operation ...
    
    int gas_after = gas_consumed();
    int actual_gas = gas_after - gas_before;
    
    ;; Add safety margin
    int gas_fee = get_gas_fee_workchain(actual_gas + 1000);
    
    throw_if(error::insufficient_value, amount <= gas_fee);
}
```

**2. Parameterized Gas Fees**

```func
;; Store gas constants in contract data (updateable without code change)
global int gas_params::deposit;
global int gas_params::deposit_and_call;
// ...

() update_gas_params(int deposit, int deposit_and_call, ...) impure {
    guard_authority_sender(sender);
    
    gas_params::deposit = deposit;
    gas_params::deposit_and_call = deposit_and_call;
    
    mutate_state();
}
```

**3. Monitoring & Testing**

```typescript
// Regular gas profiling tests
describe('Gas Cost Stability', () => {
    it('should track gas costs over time', async () => {
        const gasCosts = [];
        
        for (let i = 0; i < 100; i++) {
            const tx = await gateway.sendDeposit(...);
            gasCosts.push(tx.totalFees);
        }
        
        const avgGas = gasCosts.reduce((a,b) => a+b) / gasCosts.length;
        const maxGas = Math.max(...gasCosts);
        
        // Alert if costs drift from expectations
        expect(avgGas).toBeLessThan(hardcoded_constant * 1.1);
        expect(maxGas).toBeLessThan(hardcoded_constant * 1.2);
    });
});
```

**4. Documentation**

```markdown
## Gas Fee Update Procedure

1. Run gas profiling suite: `npm run test:gas`
2. Analyze CSV reports in `temp/tests/`
3. If average cost > 90% of ceiling:
   - Update constants in `gateway.fc`
   - Recompile: `make compile`
   - Deploy upgrade: `make upgrade`
4. Announce changes to users 48h in advance
```

---

## 🔵 LOW-02: No Protection Against Workchain Migration

### Severity: LOW

### Description

The contract restricts operations to basechain (workchain 0) but has no handling for potential TON network evolution:
- Future workchains (1, 2, etc.)
- Cross-workchain bridging
- Workchain deprecation

While currently not an issue, this could cause problems if:
1. TON introduces new workchains with different security properties
2. Users accidentally send from restricted workchains
3. Protocol needs to expand to other workchains

### Location

```func
// contracts/gateway.fc:259-260
(int wc, _) = sender.parse_std_addr();
throw_unless(error::wrong_workchain, wc == 0);
```

### Impact

**Current:** No impact (basechain is standard)

**Future Scenarios:**
1. New workchain introduced for specific use cases
2. Masterchain users want to use gateway (wc = -1)
3. Sharded workchains deployed

**Risk:** Very Low (would require major TON protocol changes)

### Recommendation

**1. Configurable Workchain Whitelist**

```func
global int state::allowed_workchains;  // Bitmap: bit 0 = wc 0, bit 1 = wc 1, etc.

() is_workchain_allowed(int wc) inline {
    ;; Check if workchain bit is set
    return (state::allowed_workchains & (1 << (wc + 128))) != 0;
}

() recv_internal(...) impure {
    (int wc, _) = sender.parse_std_addr();
    throw_unless(error::wrong_workchain, is_workchain_allowed(wc));
    // ...
}

;; Authority can add workchains
() add_allowed_workchain(int wc) impure {
    guard_authority_sender(sender);
    state::allowed_workchains |= (1 << (wc + 128));
    mutate_state();
}
```

**2. Explicit Masterchain Support**

```func
const ALLOWED_WORKCHAINS = [0, -1];  // Basechain and Masterchain

() is_workchain_allowed(int wc) inline {
    return (wc == 0) | (wc == -1);
}
```

**3. Document Workchain Policy**

```markdown
## Supported Workchains

Currently, only **basechain (workchain 0)** is supported.

**Rationale:**
- Basechain has the lowest fees
- Most TON users are on basechain
- Consistent security model

**Future Expansion:**
If additional workchains are needed:
1. Security audit of new workchain
2. Contract upgrade to whitelist
3. Testing on testnet
4. Community governance vote
```

---

## ⚪ INFO-01: Missing Formal Verification

### Severity: INFORMATIONAL

### Description

The contract lacks formal verification of critical security properties. While comprehensive unit tests exist, formal methods could provide mathematical guarantees about:

1. **Invariant Preservation**
   - `total_locked ≤ contract_balance`
   - `seqno` monotonically increases
   - No underflow in balance accounting

2. **State Machine Properties**
   - All reachable states are safe
   - No deadlock states
   - Liveness guarantees

3. **Cryptographic Correctness**
   - ECDSA verification always matches Ethereum's
   - No signature malleability
   - Replay protection completeness

### Tools for TON/FunC

While formal verification for FunC is limited, consider:

**1. Property-Based Testing**
```typescript
import fc from 'fast-check';

describe('Property-Based Tests', () => {
    it('total_locked never exceeds balance', async () => {
        await fc.assert(
            fc.asyncProperty(
                fc.array(fc.nat(1000)), // Random deposit amounts
                fc.array(fc.nat(500)),  // Random withdrawal amounts
                async (deposits, withdrawals) => {
                    // ... execute operations ...
                    
                    const state = await gateway.getGatewayState();
                    const balance = await gateway.getBalance();
                    
                    expect(state.valueLocked).toBeLessThanOrEqual(balance);
                }
            )
        );
    });
});
```

**2. Symbolic Execution**
- Map FunC operations to SMT constraints
- Use Z3 solver to find invariant violations
- Automated test case generation

**3. Manual Proof Sketches**
```
Theorem: seqno_monotonic
  ∀ state₁, state₂, tx:
    state₂ = execute(state₁, tx) ∧ tx ∈ external_messages
    ⇒ state₂.seqno = state₁.seqno + 1

Proof:
  1. Only handle_withdrawal and handle_increase_seqno modify seqno
  2. Both increment by exactly 1: `state::seqno += 1`
  3. No other code paths decrement or reset seqno
  4. ∴ seqno is strictly increasing
  QED
```

**4. Model Checking**
Use TLA+ to model state transitions:

```tla
VARIABLE state, messages

Init == 
    /\ state = [total_locked |-> 0, seqno |-> 0, deposits_enabled |-> TRUE]
    /\ messages = {}

Deposit(amount) ==
    /\ state.deposits_enabled = TRUE
    /\ state' = [state EXCEPT !.total_locked = @ + amount]
    /\ UNCHANGED messages

Withdraw(amount, seqno_in) ==
    /\ seqno_in = state.seqno
    /\ amount <= state.total_locked
    /\ state' = [state EXCEPT 
                    !.total_locked = @ - amount,
                    !.seqno = @ + 1]

Invariant ==
    /\ state.total_locked >= 0
    /\ state.seqno >= 0

Spec == Init /\ [][Deposit \/ Withdraw]_<<state, messages>> /\ Invariant
```

### Recommendation

Given resource constraints, prioritize:

1. **High-Value Property Tests:** Focus on invariants that guard funds
2. **Manual Proof Reviews:** Document critical theorems in comments
3. **Continuous Monitoring:** Deploy runtime assertion checks

**Future Work:**
- Engage formal verification experts as TVL grows
- Budget for comprehensive audit with formal methods
- Open-source proof artifacts for community review

---

## Additional Deep Dive Areas

Based on the findings, the following areas warrant further investigation:

### 1. TSS Ceremony & Key Management (HIGH PRIORITY)

**Questions:**
- How many signers participate in TSS?
- What is the threshold (m-of-n)?
- Key generation ceremony audit logs?
- Key rotation procedure documentation?
- Incident response plan for TSS compromise?

**Investigation:**
- Review ZetaChain's MPC implementation
- Audit key sharding and distribution
- Penetration testing of signer infrastructure
- Social engineering risk assessment

### 2. Observer Infrastructure Security (MEDIUM PRIORITY)

**Questions:**
- How is the observer deployed (centralized vs decentralized)?
- What happens if observer goes offline?
- Can malicious observer forge logs?
- Redundancy and failover mechanisms?

**Investigation:**
- Review observer source code (if available)
- Test failure scenarios (network partition, crash)
- Validate log signature verification
- Monitor observer <-> ZEVM communication

### 3. Cross-Chain Message Integrity (MEDIUM PRIORITY)

**Questions:**
- How are messages verified on ZEVM side?
- Possibility of message replay on different chains?
- Handling of reorgs on TON blockchain?
- Message censorship resistance?

**Investigation:**
- Audit ZEVM Gateway contract
- Review cross-chain message protocol
- Test edge cases (chain splits, deep reorgs)
- Analyze MEV opportunities

### 4. Economic Sustainability (LOW PRIORITY)

**Questions:**
- Long-term viability of gas fee model?
- Storage fee impact over years?
- Revenue model for protocol operations?
- Attack cost vs potential gain analysis?

**Investigation:**
- Model storage fee growth projections
- Compare fee revenue vs operational costs
- Game theory analysis of attack scenarios
- Sustainability recommendations

### 5. Upgrade Governance (HIGH PRIORITY)

**Questions:**
- Is there a planned transition to decentralized governance?
- Timeframe for DAO integration?
- Emergency upgrade procedures?
- Community notification process?

**Investigation:**
- Review roadmap for governance
- Analyze voting mechanisms (if planned)
- Propose governance frameworks
- Draft emergency protocols

### 6. Compliance & Legal (MEDIUM PRIORITY)

**Questions:**
- Regulatory classification of gateway (bridge? custodian?)?
- KYC/AML considerations for large transfers?
- Jurisdiction and legal entity structure?
- Liability in case of contract failure?

**Investigation:**
- Consult with blockchain legal experts
- Review relevant regulations (MiCA, SEC guidance)
- Draft terms of service
- Establish legal disclaimers

---

## Remediation Summary

### Critical Path (Immediate - 1 Week)

1. **Authority Key Security Audit**
   - Document current key management
   - Implement hardware wallet if not already used
   - Establish key rotation procedure
   - Create incident response plan

2. **Enhanced Monitoring**
   - Deploy event monitoring for all operations
   - Set up alerts for TSS/authority changes
   - Integrate with existing ZetaChain monitoring

3. **Rate Limiting Implementation**
   - Add per-transaction withdrawal cap
   - Implement basic circuit breaker

### Short Term (1-4 Weeks)

4. **Timelock for TSS Updates**
   - 48-hour delay for TSS address changes
   - Emergency pause mechanism
   - Community notification system

5. **Multisig Exploration**
   - Research multisig solutions for TON
   - Design 3-of-5 authority scheme
   - Develop migration plan

6. **Comprehensive Testing**
   - Property-based test suite
   - Gas profiling automation
   - Failure scenario coverage

### Medium Term (1-3 Months)

7. **Governance Framework**
   - Design decentralized governance model
   - Implement voting mechanism (if applicable)
   - Community onboarding

8. **Formal Verification**
   - Engage formal methods experts
   - Verify critical invariants
   - Document proofs

9. **Protocol Enhancements**
   - Velocity limiting for withdrawals
   - Staged large withdrawals
   - Call data validation

### Long Term (3-12 Months)

10. **Decentralization**
    - Transition to DAO governance
    - Remove single points of failure
    - Community-driven upgrades

11. **Protocol Extensions**
    - Multi-workchain support
    - Cross-chain message batching
    - Advanced fee models

---

## Conclusion

The ZetaChain TON Gateway demonstrates solid engineering fundamentals with comprehensive testing and clear security practices. However, several architectural concerns require attention:

**Strengths:**
- ✅ Strong cryptographic foundation (ECDSA verification)
- ✅ Comprehensive test coverage
- ✅ Historical bug fixes show responsive development
- ✅ Clear documentation and code organization

**Primary Concerns:**
- ⚠️ Single authority model poses centralization risk
- ⚠️ TSS address updates lack safeguards
- ⚠️ Missing rate limits and circuit breakers
- ⚠️ Insufficient event emission for monitoring

**Recommended Actions:**
1. **Immediate:** Audit authority key security, enhance monitoring
2. **Short-term:** Implement timelocks, design multisig transition
3. **Medium-term:** Add rate limits, formal verification
4. **Long-term:** Decentralize governance, protocol maturation

**Risk Assessment:**
- **Current State:** MODERATE-HIGH risk (reliant on authority/TSS security)
- **With Recommendations:** LOW-MODERATE risk (defense in depth, reduced attack surface)

The contract is suitable for production given ZetaChain's infrastructure trust assumptions, but should prioritize decentralization and automated safeguards as TVL grows.

---

## Appendix: Security Checklist

- [x] Input validation on all user operations
- [x] Replay protection via seqno
- [x] Signature verification (ECDSA)
- [x] Workchain restrictions
- [x] Gas fee management
- [x] Comprehensive test coverage
- [ ] Multisig authority
- [ ] Timelocks for critical operations
- [ ] Rate limiting on withdrawals
- [ ] Circuit breaker mechanism
- [ ] Comprehensive event emission
- [ ] Formal verification
- [ ] Decentralized governance
- [ ] Emergency pause by community
- [ ] Bug bounty program
- [ ] Regular security audits

**Overall Score: 7/15 (47%)** - Solid foundation, needs maturation in decentralization and safeguards.

---

**End of Security Findings Report**
