# Pay on deposit

In the current setup, deposits are free and permissionless (i.e. no authentication required to generate a shared key deposit addresses) and the mercury server fee (as a fixed percentage of the coin value) is collected in the withdrawal transaction as a UTXO paid to a fixed, specified bitcoin address. This has the advantage of making the deposit process low friction and user friendly, but has some disadvantages:

The withdrawal transaction fee output is typically a small fraction of the coin value and for the smallest coin values is close to the dust limit (i.e. these outputs may not be spendable in a high tx fee environment).
The on-chain mercury fee explicitly labels all withdrawn coins as mercury statechain withdrawals, which is a privacy concern for many users.

The alternative that mitigates these issues is to charge the fee up-front, via a LN invoice, before the shared key deposit address is generated. In this approach, a user would specify in the wallet that they wanted to deposit a specific amount into a statecoin, and instead of performing a shared key generation with the server, would request a LN invoice for the withdrawal fee from the server, which would be returned to the wallet and displayed to the user.

The user would then copy this invoice (by C&P or QR code) into a third party LN wallet and pay the fee. A LN node running on the mercury server back end would then verify that the payment had been made, and enable the wallet to continue with the deposit keygen and deposit process. This coin would be labeled as ‘fee paid’ by the wallet and server, and not be subject to an on-chain fee payment on withdrawal.

## Design

To enable many ways to give permission to deposit coins, the deposit permission system will utilize a token system where tokens can be issued separately to the deposit process and then redeemed on deposit. This will enable fees to be paid via any mechanism and also managed separately and batched from within the wallet. 

### Tokens

**Deposit tokens** will be managed via a new table `tokens` (which can be set up as a separate DB to the main `mercury` DB so separate permissions can be applied). This table will have 4 columns: `token_id` (Uuid), `ln_invoice` (string), `address` (string), `value` (integer), `confirmed` (boolean) and `spent` (boolean). 

The `tokens` table will be interacted with via two new mercury server functions: `token_init` and `token_verify`. 

The `token_init` function will take one argument (`value`). This function will generate a new random `token_id` (Uuid) and then use the command: `invoice *value* *token_id*` and `newaddr` to the lighning node via the RPC connection of the mercury server. The `token_id`, invoice returned from the lighning node and the address returned are then added to the `tokens` table with `confirmed = false` in a new row. The `token_id`, invoice string and address are then also returned from the function. This function will be called from a `GET` http request. 

The `token_verify` function will take one argument (`token_id`) and return a boolean (`valid`). This function will first query the `tokens` table with the `token_id`. If no entry found, it will return an error. If a row is found, it will return false if `spent = true`. If `spent = false` and `confirmed = true` it will return `true`. If `spent = false` and `confirmed = true` it will then query the lighning node to check if either the invoice has been paid or that the `value` has been recieved at the bitcoin address. If the payment has been made to either, the row is updated with the `confirmed = true` and the function returns `true`. This function is also called from a new http request route. 

### Deposit process

The current deposit process is controlled via a Proof of work system: a challenge is issued (along with `shared_key_id`) when `deposit_init` is called, and an entry is created in the `usersession` table. The next step is the call of `first_message` which initates the shared key generation protocol. `first_message` takes the argument `KeyGenMsg1` which contains `shared_key_id` and the proof-of-work `solution`. `first_message` then verifies that the PoW is valid, and then continues with the key generation, returning `KeyGenReply1`. 

The new deposit process will verify that a valid (i.e. confirmed and unspent) token is in the `tokens` table before creating a `user_id` and entry in the `usersession` table. 
When `deposit_init` is called, a `token_id` must now be supplied as an argument. This function will then query the `tokens` table with the `token_id`. If `confirmed = true` and `spent = false` it will generate a new `user_id` and row in the `usersession` table and return the `user_id`, otherwise it will return an error. It will also add the `value` of the `token_id` to the `challenge` column of the `usersession` table. 

### Withdrawal

The withdrawal fee address will be removed from `fee_info` and the amount verification check from `tx_withdraw_verify`. 

## Wallet process

The wallet will initially change to have a fee (token) payment UI before the address generation (later features to manage multiple tokens can be added). Currently, the user selects a coin value, confirms and then `deposit_init` and the key generation follows (with PoW performed with wasm code). Once the shared key generation is complete, the deposit address is displayed (with QR code) awaiting deposit. 

The new process will have the user select a coin amount as before, and confirm, but instead `token_init` will be called (with a value argument as a percentage set in `fee_info`) returning invoice and bitcoin address. These will then be displayed in the wallet (with QR codes). The wallet will then begin polling `token_verify` every few seconds waiting for payment to be confirmed (and the function to return `true`). Once this happens, wallet then calls `deposit_init` with the `token_id` and displays the deposit address as before. 

### Value enforcement

Since the fee is now being paid before deposit of the statecoin, there needs to be a mechanism of enforcing the payment of the correct fee in proportion to the coin value. E.g. someone could pay a fee for the smallest possible coin, and then deposit a much larger coin, saving on the fee. To prevent this, the server will verify that the amount is in proportion to the fee when a coin is transfered or registered for a swap (the verification can be done in the `verify_tx_confirmed` function, which is called on these operations anyway). If the fee amount is incorrect, the coin can be withdrawn, but not able to be transferred or swapped. 

### Withdrawal

The withdrawal fee will be removed from `txWithdrawBuild`. 

