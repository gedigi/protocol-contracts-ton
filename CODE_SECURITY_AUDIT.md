# ZetaChain TON Gateway - Code-Level Security Audit

**Date:** 2025-11-10  
**Auditor:** Blockchain Security Researcher  
**Focus:** Exploitable code-level vulnerabilities and logic errors

---

## Executive Summary

After thorough analysis of the smart contract code, **no critical exploitable vulnerabilities were identified** in the current implementation. The contract demonstrates solid security engineering with proper access controls, input validation, and state management.

The codebase has matured through several bug fixes (documented in git history), and the current state reflects lessons learned from those issues.

---

## Methodology

### Analysis Approach

1. **Manual Code Review** - Line-by-line analysis of all contract functions
2. **Access Control Analysis** - Verification of permission boundaries
3. **State Machine Analysis** - Validation of state transitions
4. **Arithmetic Safety** - Integer overflow/underflow checks
5. **Re-entrancy Analysis** - TON actor model considerations
6. **Historical Bug Review** - Learning from previously fixed issues

### Scope

- ✅ `contracts/gateway.fc` (main contract logic)
- ✅ `contracts/common/crypto.fc` (ECDSA verification)
- ✅ `contracts/common/state.fc` (state management)
- ✅ `contracts/common/messages.fc` (message handling)
- ✅ `contracts/common/gas.fc` (gas calculations)
- ✅ Test suite analysis for edge case coverage

---

## Findings Summary

| Category | Status | Notes |
|----------|--------|-------|
| **Access Control** | ✅ SECURE | Guards properly implemented |
| **ECDSA Verification** | ✅ SECURE | Correct implementation with normalization |
| **Replay Protection** | ✅ SECURE | Seqno mechanism works correctly |
| **Integer Arithmetic** | ✅ SECURE | No overflow/underflow issues |
| **State Management** | ✅ SECURE | Proper load/mutate/commit pattern |
| **Fund Accounting** | ✅ SECURE | total_locked tracked correctly |
| **Re-entrancy** | ✅ N/A | Actor model prevents traditional re-entrancy |

---

## Detailed Code Analysis

### 1. Access Control ✅

#### Authority Operations

```func
// Line 80-82: Authority guard
() guard_authority_sender(slice sender) impure inline_ref {
    throw_unless(error::invalid_authority, equal_slices(sender, state::authority_address));
}
```

**Analysis:**
- ✅ All authority operations (`set_deposits_enabled`, `update_tss`, `update_code`, `update_authority`, `reset_seqno`) call this guard
- ✅ Uses `equal_slices()` which is secure comparison
- ✅ Cannot be bypassed - checked inside each handler

**Authority Fee Check (Line 288-289):**
```func
int tx_fee_authority = get_gas_fee_workchain(gas::authority);
throw_if(error::insufficient_value, msg_value < tx_fee_authority);
```

**Analysis:**
- ✅ Fee check happens BEFORE routing to authority handlers
- ✅ Non-authority users who send authority ops with sufficient fee will pay the fee, then fail at the `guard_authority_sender` check
- ⚠️ **Not a vulnerability but wasteful**: User loses fee even though they're not authority
- ℹ️ This is by design - prevents spam of authority operations

#### TSS Operations (External Messages)

```func
// Line 317-338: ECDSA authentication
cell auth::ecdsa::external(slice message, slice expected_evm_address) inline {
    slice signature = message~load_bits(size::signature_size);
    cell payload = message~load_ref();
    int payload_hash = cell_hash(payload);
    
    int sig_check = check_ecdsa_signature(payload_hash, signature, expected_evm_address);
    throw_unless(error::invalid_signature, sig_check == true);
    
    return payload;
}
```

**Analysis:**
- ✅ Signature verified before any operation
- ✅ Uses cell hash (deterministic)
- ✅ Cannot be bypassed - only entry point for external messages

**Verdict:** Access control is correctly implemented. No bypass vectors found.

---

### 2. ECDSA Signature Verification ✅

```func
// Line 18-30: Recovery ID normalization
int normalize_ecdsa_recovery_id(int v) inline {
    if v >= 31 {
        return v - 31;  // Compressed format
    }
    if v >= 27 {
        return v - 27;  // Uncompressed format
    }
    return v;  // Already normalized
}

// Line 37-72: Signature verification
(int) check_ecdsa_signature(int hash, slice signature, slice expected_evm_address) impure inline_ref {
    int v = signature~load_uint(8).normalize_ecdsa_recovery_id();
    int r = signature~load_uint(256);
    int s = signature~load_uint(256);
    
    (int h, int x1, int x2, int flag) = ecdsa_recover(hash, v, r, s);
    if flag != true { return 1; }
    
    if h != 4 { return 2; }  // Must be uncompressed (0x04 prefix)
    
    // Derive EVM address from public key
    int pub_key_hash = begin_cell()
        .store_uint(x1, 256)
        .store_uint(x2, 256)
        .hash_keccak256();
    
    slice actual_evm_address = begin_cell()
        .store_uint(pub_key_hash, 256)
        .end_cell()
        .begin_parse()
        .slice_last(20 * 8);  // Last 20 bytes
    
    if equal_slices(expected_evm_address, actual_evm_address) == false {
        return 3;
    }
    
    return true;
}
```

**Analysis:**

✅ **Recovery ID Handling:** Correctly normalizes Ethereum-style v values (27, 28, 31, 32) to TVM format (0, 1)

✅ **Public Key Recovery:** Uses TVM's `ECRECOVER` instruction correctly

✅ **Compressed Key Rejection:** Only accepts uncompressed public keys (h == 4), matching Ethereum behavior

✅ **Address Derivation:** Correctly computes `keccak256(pubkey)[12:32]` to derive EVM address

✅ **Comparison:** Uses `equal_slices()` for secure comparison

**Potential Issues Checked:**
- ❌ Signature malleability: Not applicable here (seqno provides replay protection)
- ❌ Invalid curve points: Handled by `ECRECOVER` (returns flag)
- ❌ Hash collision: Uses cryptographic cell_hash

**Verdict:** ECDSA implementation is correct and secure.

---

### 3. Replay Protection ✅

```func
// Line 355: Seqno validation in withdrawal
throw_if(error::invalid_seqno, seqno != state::seqno);

// Line 366: Seqno increment
state::seqno += 1;
```

**Analysis:**
- ✅ Every withdrawal must include current seqno
- ✅ Seqno incremented by exactly 1 after validation
- ✅ No way to skip seqno or reuse old signatures
- ✅ Applies to both `withdraw` (op 200) and `increase_seqno` (op 205) operations

**Historical Bug (Fixed in commit `59f4482`):**
- **Before:** `seqno != (state::seqno + 1)` - required *next* seqno
- **After:** `seqno != state::seqno` - requires *current* seqno
- **Impact:** Fixed, no longer an issue

**Edge Cases Checked:**
- ✅ Concurrent withdrawals: Only one can succeed (seqno mismatch)
- ✅ Out-of-order execution: Not possible (sequential seqno)
- ✅ Seqno reset: Only by authority via `reset_seqno` operation

**Verdict:** Replay protection is correctly implemented.

---

### 4. Fund Accounting ✅

#### Deposit Flow

```func
// Line 111-113: Deposit accounting
int deposit_amount = amount - tx_fee;
state::total_locked += deposit_amount;
```

**Analysis:**
- ✅ Fee deducted from deposit amount
- ✅ Only net amount added to `total_locked`
- ✅ Check ensures `amount > tx_fee` (line 109)

#### Withdrawal Flow

```func
// Line 360: Sufficient funds check
throw_if(error::insufficient_value, state::total_locked < (amount + tx_fee));

// Line 365: Deduction
state::total_locked -= (amount + tx_fee);
```

**Analysis:**
- ✅ Pre-flight check prevents underflow
- ✅ Deducts both withdrawal amount AND fee
- ✅ State committed before external send (line 369-370)

**Historical Bug (Fixed in commit `fbf587f`):**
- **Before:** Missing check for `total_locked < (amount + tx_fee)`
- **After:** Added check at line 360
- **Impact:** Fixed, prevents underflow

**Invariant:**
```
total_locked <= contract_balance
```

This holds because:
1. Deposits add to both (minus fee)
2. Withdrawals deduct from both
3. Donations add to balance but NOT total_locked (by design)

**Verdict:** Fund accounting is correct and maintains invariants.

---

### 5. Call Operation (Op 103) ✅

```func
// Line 162-179: Handle call
() handle_call(int amount, slice in_msg_body) impure inline {
    load_state();
    guard_deposits();
    
    throw_if(error::invalid_evm_recipient, in_msg_body.slice_bits() < size::evm_address);
    in_msg_body~load_uint(size::evm_address);
    
    throw_if(error::invalid_call_data, in_msg_body.slice_refs_empty?());
    cell call_data = in_msg_body~load_ref();
    guard_cell_size(call_data, size::call_data::max, error::invalid_call_data);
    
    int tx_fee = get_gas_fee_workchain(gas::call);
    throw_if(error::insufficient_value, amount < tx_fee);
    
    // state::total_locked is NOT changed.
    
    mutate_state();
}
```

**Analysis:**
- ✅ Validates recipient address exists
- ✅ Validates call data exists and size ≤ 2KB
- ✅ Checks sufficient fee (`amount >= tx_fee`)
- ✅ **Does NOT modify `total_locked`** - this is correct behavior
- ✅ No funds are locked, just a cross-chain message trigger

**Why total_locked unchanged?**
- `call` operation is a message trigger, not a deposit
- User pays gas fee, but no value is locked in gateway
- Correct design for stateless cross-chain calls

**Verdict:** Call operation is correctly implemented.

---

### 6. Bounced Message Handling ✅

```func
// Line 254-256: Bounced message handler
if (flags & 1) {
    return ();  // Just accept and do nothing
}
```

**Analysis:**
- ✅ Detects bounced messages via flags bit 0
- ✅ Accepts without processing (prevents loops)
- ✅ No state changes on bounced messages
- ✅ Funds remain in contract (safer than rejecting)

**Why this is safe:**
- Bounced messages occur when outbound messages fail
- Contract accepts them to prevent infinite bounce loops
- Since no state was changed before send (for withdrawals), accepting bounce is safe

**Verdict:** Bounced message handling is correct.

---

### 7. Input Validation ✅

#### Size Limits

```func
// Line 85-97: Cell size guard
() guard_cell_size(cell data, int max_size_bits, int throw_error) impure inline {
    int max_size_cells = (max_size_bits / 1023) + 1;
    
    (_, int data_bits, _, int ok) = compute_data_size?(data, max_size_cells);
    
    if (ok == false) {
        throw(throw_error);
    }
    
    if ((data_bits == 0) | (data_bits > max_size_bits)) {
        throw(throw_error);
    }
}
```

**Analysis:**
- ✅ Validates cell can be computed (not too deep/complex)
- ✅ Checks data_bits > 0 (not empty)
- ✅ Checks data_bits ≤ max_size_bits (not too large)
- ✅ Used for call_data validation (max 2KB)

**Prevents:**
- ❌ Gas exhaustion attacks via huge cells
- ❌ Empty cell submission
- ❌ Nested cell bombs

#### Amount Validation

```func
// Deposits (line 109)
throw_if(error::insufficient_value, amount <= tx_fee);

// Withdrawals (line 354, 360)
throw_if(error::insufficient_value, amount == 0);
throw_if(error::insufficient_value, state::total_locked < (amount + tx_fee));
```

**Analysis:**
- ✅ Deposits must exceed fee (net positive deposit)
- ✅ Withdrawals must be non-zero
- ✅ Withdrawals checked against available funds

#### Address Validation

```func
// Line 259-260: Workchain check
(int wc, _) = sender.parse_std_addr();
throw_unless(error::wrong_workchain, wc == 0);

// Line 352: Self-send prevention
throw_if(error::invalid_tvm_recipient, equal_slices(recipient, my_address()));
```

**Analysis:**
- ✅ Only basechain (wc=0) addresses allowed
- ✅ Cannot withdraw to gateway itself (would lock funds)
- ✅ Prevents accidental fund locking

**Verdict:** Input validation is comprehensive and correct.

---

### 8. State Management ✅

```func
// Standard pattern throughout contract:
load_state();           // Load from storage
// ... operations ...
mutate_state();         // Write to storage
```

**Analysis:**
- ✅ State explicitly loaded at function start
- ✅ State explicitly saved after modifications
- ✅ For withdrawals: `commit()` called before external sends

**Withdrawal State Management (Line 369-373):**
```func
mutate_state();
commit();
send_simple_message_non_bounceable(recipient_addr, amount, send_mode);
```

**Why this ordering matters:**
1. `mutate_state()` - writes state to storage
2. `commit()` - ensures state persistence
3. `send_message()` - external interaction

**If send fails:** State already updated (seqno incremented, funds deducted). This prevents:
- Re-executing with same seqno (replay protection)
- Double-spending same locked funds

**Verdict:** State management follows best practices.

---

### 9. Arithmetic Safety ✅

#### Potential Overflow Points

**Deposit Addition:**
```func
state::total_locked += deposit_amount;
```

**Analysis:**
- In TON, Coins type can hold values up to ~2^120 nanotons
- Gateway max realistic balance: ~10^9 TON = 10^18 nanotons
- No overflow risk in practice
- ✅ Safe

**Withdrawal Subtraction:**
```func
throw_if(error::insufficient_value, state::total_locked < (amount + tx_fee));
state::total_locked -= (amount + tx_fee);
```

**Analysis:**
- Pre-flight check prevents underflow
- ✅ Safe

**Seqno Increment:**
```func
state::seqno += 1;
```

**Analysis:**
- uint32, max value 4,294,967,295
- At 1 withdrawal per second: ~136 years to overflow
- Authority can reset seqno if needed
- ✅ Safe in practice

**Verdict:** No arithmetic vulnerabilities found.

---

## Non-Issues (Confirmed Safe Behaviors)

### 1. Donation Mechanism

```func
// Line 272-273: Donation operation
if (op == op::internal::donate) {
    return ();  // Accept value, no state change
}
```

**Not a vulnerability because:**
- Donations go to contract balance (not total_locked)
- Used to pay for storage fees and gas costs
- Cannot be exploited to manipulate accounting
- By design: allows anyone to help cover contract costs

---

### 2. Non-Existent Recipient Withdrawals

From test suite (Gateway.spec.ts:580-626):
```typescript
// Withdraw to non-existent address
const result = await gateway.sendWithdraw(tssSigner, nonExistentAddress, amount);

// Result: 
// - Withdrawal TX succeeds on gateway
// - Transfer TX to recipient is aborted
// - Funds are lost
```

**Not a vulnerability because:**
- TSS is responsible for providing valid recipients
- Gateway cannot validate if TON address exists
- Non-bounceable messages are intentional (prevents loops)
- Risk accepted by protocol design

---

### 3. Authority Fee "Waste"

Non-authority users can send authority operations with sufficient fee, then fail at authority check.

**Not a vulnerability because:**
- User explicitly sending authority op-code
- Fee requirement filters casual spam
- Failed authority check is expected behavior
- User at fault for sending wrong operation

---

### 4. Call Data Content Not Validated

Gateway validates call_data size but not contents.

**Not a vulnerability because:**
- Content validation is ZEVM's responsibility
- Gateway is just a message relay
- Invalid data hurts sender only (loses gas fees)
- No risk to locked funds or other users

---

## Test Coverage Analysis

From `tests/Gateway.spec.ts`:

**Well-Covered Scenarios:** ✅
- Deployment and initialization
- Basic operations (deposit, deposit_and_call, call, donate)
- Withdrawals (normal, non-existent recipient, insufficient funds)
- Authority operations (all 5 operations tested)
- Access control (non-authority attempts)
- Edge cases (deposits disabled, amount too small, large call data)
- Seqno management (increment, reset)
- Gas fee tracking and profiling

**Test Quality:**
- 17 comprehensive test cases
- Gas profiling with CSV export
- Balance tracking before/after
- Exit code validation
- Edge case coverage

**Verdict:** Test suite is thorough and catches real issues.

---

## Historical Vulnerabilities (All Fixed)

### 1. Seqno Offset Bug ✅ FIXED

**Commit:** `59f4482` (Oct 23, 2024)

**Issue:** 
```func
// BEFORE (vulnerable)
throw_if(error::invalid_seqno, seqno != (state::seqno + 1));

// AFTER (fixed)
throw_if(error::invalid_seqno, seqno != state::seqno);
```

**Impact:** 
- Required users to predict next seqno
- Potential confusion in TSS signing
- Off-by-one errors in external tools

**Status:** ✅ Properly fixed, no longer exploitable

---

### 2. Withdrawal Edge Case ✅ FIXED

**Commit:** `fbf587f` (Oct 23, 2024)

**Issue:**
```func
// BEFORE (vulnerable)
accept_message();
state::total_locked -= (amount + tx_fee);  // Could underflow!
send_message(...);
mutate_state();

// AFTER (fixed)
throw_if(error::insufficient_value, state::total_locked < (amount + tx_fee));
accept_message();
state::total_locked -= (amount + tx_fee);
mutate_state();
commit();  // Commit before send!
send_message(...);
```

**Impact:**
- Could underflow total_locked
- State might not persist if send failed
- Accounting mismatch possible

**Status:** ✅ Properly fixed with two improvements:
1. Pre-flight balance check
2. State committed before external send

---

### 3. Gas Fee Implementation (Feature, not bug)

**Commit:** `e3b0098` (Oct 16, 2024)

**Change:** Added gas ceiling approach with dynamic calculation

**Impact:** Improved user experience and fee accuracy

**Status:** ✅ Enhancement, not a security fix

---

## Code Quality Observations

### Strengths ✨

1. **Clear Structure:** Modular includes, well-organized functions
2. **Explicit Guards:** Access control clearly defined and used consistently
3. **Comprehensive Comments:** Complex logic well-documented
4. **Error Handling:** Specific error codes for different failure modes
5. **State Safety:** Consistent load/mutate/commit pattern
6. **Test Coverage:** Extensive test suite with edge cases

### Minor Improvements (Not Vulnerabilities)

1. **Gas Constants:** Hardcoded values may need updates if network changes
   - **Mitigation:** Contract is upgradeable
   - **Impact:** Low (requires protocol-level changes)

2. **Error Messages:** Exit codes only, no string messages
   - **Impact:** Debugging requires code reference
   - **Not a security issue**

3. **Event Emission:** Limited to deposit logs
   - **Impact:** Reduced observability
   - **Not a security issue**

---

## Conclusion

### Security Status: ✅ SECURE

After thorough analysis of the codebase, **no exploitable vulnerabilities** were identified. The contract implements its security model correctly with:

- ✅ Proper access control (authority & TSS verification)
- ✅ Secure ECDSA signature verification
- ✅ Effective replay protection (seqno)
- ✅ Safe fund accounting
- ✅ Comprehensive input validation
- ✅ Sound state management

### Historical Context

The codebase has matured through real-world bug fixes:
- Seqno offset bug (fixed)
- Withdrawal edge case (fixed)
- Gas fee modeling (improved)

These fixes demonstrate responsive development and learning from issues.

### What's NOT a Vulnerability

The previous report incorrectly flagged design decisions as vulnerabilities:
- ❌ Single authority model → Design choice, not a bug
- ❌ No rate limits → Trust assumption, not a bug
- ❌ Missing events → Observability concern, not a bug
- ❌ No timelock → Governance choice, not a bug

### Actual Risk Profile

**Code-Level Risk:** LOW ✅
- No exploitable logic errors found
- Access controls work correctly
- State management is sound

**Protocol-Level Risk:** Depends on deployment choices
- Authority key security (operational concern)
- TSS infrastructure (trust assumption)
- Observer reliability (availability concern)

### Recommendations

1. **Continue Current Practices:**
   - Comprehensive testing before upgrades
   - Careful review of all code changes
   - Gas profiling on new operations

2. **Operational Security:**
   - Secure authority key management
   - TSS key ceremony audits
   - Monitoring for anomalous transactions

3. **Future Enhancements (Optional):**
   - Event emission for better observability
   - Parameterized gas fees (updateable without code change)
   - Additional getter functions for external tools

---

## Verification Checklist

- [x] Manual code review completed
- [x] Access control verified
- [x] ECDSA implementation validated
- [x] Replay protection confirmed
- [x] Arithmetic safety checked
- [x] State management analyzed
- [x] Test coverage reviewed
- [x] Historical bugs researched
- [x] Edge cases considered
- [x] No exploitable vulnerabilities found

---

**Final Verdict:** The ZetaChain TON Gateway smart contract is **secure and production-ready** from a code-level perspective. The implementation correctly realizes its security model without exploitable logic errors or access control bypasses.

---

**End of Code-Level Security Audit**
