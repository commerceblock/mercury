---
title: Mercury Layer server v0.5.0
language_tabs:
  - rust: Rust
language_clients:
  - rust: ""
toc_footers: []
includes: []
search: false
highlight_theme: darkula
headingLevel: 2

---

<!-- Generator: Widdershins v4.0.1 -->

<h1 id="mercury-server">Mercury Layer server v0.5.0</h1>

> Mercury Layer blinded statechain protocol API specification

<h1 id="mercury-server-default">Default</h1>

## Confirm the deposit process has completed and retreive the statechain ID

<a id="opIddeposit_deposit_confirm"></a>

> Code samples

`POST /deposit/confirm`

> Body parameter

```json
{
  "shared_key_id": "string"
}
```

<h3 id="confirm-the-deposit-process-has-completed-and-retreive-the-statechain-id-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[DepositMsg2](#schemadepositmsg2)|true|none|

> Example responses

> 200 Response

```json
{
  "id": "string"
}
```

<h3 id="confirm-the-deposit-process-has-completed-and-retreive-the-statechain-id-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[StatechainID](#schemastatechainid)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Pay On Deposit: Initiate a statechain deposit and generate a shared key ID, statechain ID and server public key share

<a id="opIddeposit_deposit_init_pod"></a>

> Code samples

`POST /deposit/init/pod`

> Body parameter

```json
{
  "amount": 0,
  "auth_key": "string",
  "token_id": "string"
}
```

<h3 id="pay-on-deposit:-initiate-a-statechain-deposit-and-generate-a-shared-key-id,-statechain-id-and-server-public-key-share-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[DepositMsg1POD](#schemadepositmsg1pod)|true|none|

> Example responses

> 200 Response

```json
{
  "user_id": "string",
  "statechain_id": "string",
  "se_pubkey": "string"
}
```

<h3 id="pay-on-deposit:-initiate-a-statechain-deposit-and-generate-a-shared-key-id,-statechain-id-and-server-public-key-share-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[DepositInitResponse](#schemadepositinitresponse)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## First round of the signing protocol: ephemeral commitments and generation

<a id="opIdsign_first"></a>

> Code samples

`POST /sign/first`

> Body parameter

```json
{
  "r2_commitment": "string",
  "blind_commitment": "string",
  "statechain_id": "string",
  "user_id": "string",
  "auth_sig": "string"
}
```

<h3 id="first-round-of-the-signing-protocol:-ephemeral-commitments-and-generation-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[SignMsg1](#schemasignmsg1)|true|none|

> Example responses

> 200 Response

```json
{
  "r1_public": "string"
}
```

<h3 id="first-round-of-the-signing-protocol:-ephemeral-commitments-and-generation-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[SignReply1](#schemasignreply1)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Second round of the signing protocol: partial signature on challenge

<a id="opIdsign_second"></a>

> Code samples

`POST /sign/second`

> Body parameter

```json
{
  "shared_key_id": "string",
  "challenge": "string",
  "user_id": "string",
  "auth_sig": "string"
}
```

<h3 id="second-round-of-the-signing-protocol:-partial-signature-on-challenge-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[SignMsg2](#schemasignmsg2)|true|none|

> Example responses

> 200 Response

```json
"string"
```

<h3 id="second-round-of-the-signing-protocol:-partial-signature-on-challenge-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|string|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Get the current statecoin amount histogram

<a id="opIdutil_get_coin_info"></a>

> Code samples

`GET /info/coins`

> Example responses

> 200 Response

```json
{
  "values": {
    "property1": 1,
    "property2": 1
  }
}
```

<h3 id="get-the-current-statecoin-amount-histogram-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[CoinValueInfo](#schemacoinvalueinfo)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Get statechain entity operating information

<a id="opIdutil_get_fees"></a>

> Code samples

`GET /info/fee`

> Example responses

> 200 Response

```json
{
  "address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
  "backup_fee_rate": 1,
  "deposit": 0,
  "initlock": 14400,
  "interval": 144,
  "wallet_message": "Warning",
  "wallet_version": "0.4.65",
  "withdraw": 300
}
```

<h3 id="get-statechain-entity-operating-information-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[StateEntityFeeInfoAPI](#schemastateentityfeeinfoapi)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Get current statechain information for specified statechain ID

<a id="opIdutil_get_statechain"></a>

> Code samples

`GET /info/statechain/{statechain_id}`

<h3 id="get-current-statechain-information-for-specified-statechain-id-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|statechain_id|path|string|true|none|

> Example responses

> 200 Response

```json
{
  "amount": 0,
  "chain": [
    {
      "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
      "next_state": {
        "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
        "purpose": "TRANSFER",
        "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
      }
    }
  ]
}
```

<h3 id="get-current-statechain-information-for-specified-statechain-id-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[StateChainDataAPI](#schemastatechaindataapi)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Get the published list of SE public keys

<a id="opIdutil_get_key_list"></a>

> Code samples

`GET /info/rookeylist`

> Example responses

> 200 Response

```json
{
  "pubkeys": [
    "string"
  ]
}
```

<h3 id="get-the-published-list-of-se-public-keys-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[KeyList](#schemakeylist)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Get transfer finalize data for specified statechain ID

<a id="opIdutil_get_sc_transfer_finalize_data"></a>

> Code samples

`GET /info/sc-transfer-finalize-data/{statechain_id}`

<h3 id="get-transfer-finalize-data-for-specified-statechain-id-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|statechain_id|path|string|true|none|

> Example responses

> 200 Response

```json
{
  "batch_data": null,
  "new_shared_key_id": "8853bbb8-c6f2-4b0d-b7f1-4648d38d8d5b",
  "new_tx_backup_hex": "02000000000101ca878085da49c33eb9816c10e4056424e5e062689ea547ea91bb3aa840a3c5fb0000000000ffffffff02307500000000000016001412cc36c9533290c02f0c78f992df6e6ddfe50c8c0064f50500000000160014658fd2dc72e58168f3656fb632d63be54f80fbe4024730440220457cf52873ae5854859a7d48b39cb57eba880ea4011806e5058da7619f4c0fab02206303326f06bbebf7170b679ba787c856dec4b6462109bf66e1cb8dc087be7ebf012102a95498bdde2c8c4078f01840b3bc8f4ae5bb1a90b880a621f50ce221bce3ddbe00000000",
  "s2": "572b4094b5a6da640829f7923bc55324e123604f6d2b5f6d20b3483cd89ce828",
  "statechain_id": "81810e33-b23c-4fa5-b36b-60bc14b0787e",
  "statechain_sig": {
    "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
    "purpose": "TRANSFER",
    "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
  }
}
```

<h3 id="get-transfer-finalize-data-for-specified-statechain-id-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[TransferFinalizeData](#schematransferfinalizedata)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Get current statecoin (statechain tip) information for specified statechain ID

<a id="opIdutil_get_statecoin"></a>

> Code samples

`GET /info/statecoin/{statechain_id}`

<h3 id="get-current-statecoin-(statechain-tip)-information-for-specified-statechain-id-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|statechain_id|path|string|true|none|

> Example responses

> 200 Response

```json
{
  "amount": 1000000,
  "confirmed": true,
  "locktime": 712903,
  "statecoin": {
    "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
    "next_state": {
      "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
      "purpose": "TRANSFER",
      "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
    }
  },
  "utxo": "0000000000000000000000000000000000000000000000000000000000000000:4294967295"
}
```

<h3 id="get-current-statecoin-(statechain-tip)-information-for-specified-statechain-id-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[StateCoinDataAPI](#schemastatecoindataapi)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Get batch transfer status and statecoin IDs for specified batch ID

<a id="opIdutil_get_transfer_batch_status"></a>

> Code samples

`GET /info/transfer-batch/{batch_id}`

<h3 id="get-batch-transfer-status-and-statecoin-ids-for-specified-batch-id-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|batch_id|path|string|true|none|

> Example responses

> 200 Response

```json
{
  "finalized": true,
  "state_chains": "string"
}
```

<h3 id="get-batch-transfer-status-and-statecoin-ids-for-specified-batch-id-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[TransferBatchDataAPI](#schematransferbatchdataapi)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Initialize a pay-on-demand token

<a id="opIdpay_on_deposit_pod_token_init"></a>

> Code samples

`GET /pod/token/init/{value}`

<h3 id="initialize-a-pay-on-demand-token-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|value|path|integer(uint64)|true|none|

> Example responses

> 200 Response

```json
{
  "btc_payment_address": "string",
  "lightning_invoice": {
    "bolt11": "string",
    "expires_at": 0,
    "payment_hash": "string"
  },
  "token_id": "string",
  "value": 0
}
```

<h3 id="initialize-a-pay-on-demand-token-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[PODInfo](#schemapodinfo)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Verify confirmed and spent status of pod token

<a id="opIdpay_on_deposit_pod_token_verify"></a>

> Code samples

`GET /pod/token/verify/{pod_token_id}`

<h3 id="verify-confirmed-and-spent-status-of-pod-token-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|pod_token_id|path|string|true|none|

> Example responses

> 200 Response

```json
{
  "amount": 0,
  "confirmed": true
}
```

<h3 id="verify-confirmed-and-spent-status-of-pod-token-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[PODStatus](#schemapodstatus)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Get blinded spend token required for second message

<a id="opIdconductor_get_blinded_spend_signature"></a>

> Code samples

`POST /swap/blinded-spend-signature`

> Body parameter

```json
{
  "statechain_id": "string",
  "swap_id": "string"
}
```

<h3 id="get-blinded-spend-token-required-for-second-message-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[BSTMsg](#schemabstmsg)|true|none|

> Example responses

> 200 Response

```json
{
  "s_prime": [
    0
  ]
}
```

<h3 id="get-blinded-spend-token-required-for-second-message-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[BlindedSpendSignature](#schemablindedspendsignature)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## conductor_deregister_utxo

<a id="opIdconductor_deregister_utxo"></a>

> Code samples

`POST /swap/deregister-utxo`

Remove coin from awaiting in swap pool

> Body parameter

```json
{
  "id": "string"
}
```

<h3 id="conductor_deregister_utxo-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[StatechainID](#schemastatechainid)|true|none|

> Example responses

> 200 Response

```json
null
```

<h3 id="conductor_deregister_utxo-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|null|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Phase 1 of coinswap: Participants sign SwapToken and provide a statechain address and e_prime for blind spend token.

<a id="opIdconductor_swap_first_message"></a>

> Code samples

`POST /swap/first`

> Body parameter

```json
{
  "address": {
    "proof_key": [
      0
    ],
    "tx_backup_addr": "string"
  },
  "bst_e_prime": [
    0
  ],
  "statechain_id": "string",
  "swap_id": "string",
  "swap_token_sig": "string",
  "transfer_batch_sig": {
    "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
    "purpose": "TRANSFER",
    "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
  }
}
```

<h3 id="phase-1-of-coinswap:-participants-sign-swaptoken-and-provide-a-statechain-address-and-e_prime-for-blind-spend-token.-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[SwapMsg1](#schemaswapmsg1)|true|none|

> Example responses

> 200 Response

```json
null
```

<h3 id="phase-1-of-coinswap:-participants-sign-swaptoken-and-provide-a-statechain-address-and-e_prime-for-blind-spend-token.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|null|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Get information on current group registrations

<a id="opIdconductor_get_group_info"></a>

> Code samples

`GET /swap/groupinfo`

> Example responses

> 200 Response

```json
{
  "property1": "2:1691151686",
  "property2": "2:1691151686"
}
```

<h3 id="get-information-on-current-group-registrations-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|Inline|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<h3 id="get-information-on-current-group-registrations-responseschema">Response Schema</h3>

Status Code **200**

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» **additionalProperties**|[GroupStatus](#schemagroupstatus)|false|none|Swap group status data|
|»» number|integer(uint64)|true|none|none|
|»» time|string(partial-date-time)|true|none|none|

<aside class="success">
This operation does not require authentication
</aside>

## Get information a specified swap ID

<a id="opIdconductor_get_swap_info"></a>

> Code samples

`POST /swap/info`

> Body parameter

```json
{
  "id": "string"
}
```

<h3 id="get-information-a-specified-swap-id-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[SwapID](#schemaswapid)|true|none|

> Example responses

> 200 Response

```json
{
  "bst_sender_data": {
    "k": [
      0
    ],
    "q": [
      0
    ],
    "r_prime": [
      0
    ],
    "x": [
      0
    ]
  },
  "status": "Phase1",
  "swap_token": {
    "amount": 0,
    "id": "string",
    "statechain_ids": "string",
    "time_out": 0
  }
}
```

<h3 id="get-information-a-specified-swap-id-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[SwapInfo](#schemaswapinfo)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Poll conductor for the status of a specified swap ID

<a id="opIdconductor_poll_swap"></a>

> Code samples

`POST /swap/poll/swap`

> Body parameter

```json
{
  "id": "string"
}
```

<h3 id="poll-conductor-for-the-status-of-a-specified-swap-id-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[SwapID](#schemaswapid)|true|none|

> Example responses

> 200 Response

```json
"Phase1"
```

<h3 id="poll-conductor-for-the-status-of-a-specified-swap-id-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[SwapStatus](#schemaswapstatus)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Poll conductor for the status of a specified registered statecoin ID

<a id="opIdconductor_poll_utxo"></a>

> Code samples

`POST /swap/poll/utxo`

> Body parameter

```json
{
  "id": "string"
}
```

<h3 id="poll-conductor-for-the-status-of-a-specified-registered-statecoin-id-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[StatechainID](#schemastatechainid)|true|none|

> Example responses

> 200 Response

```json
{
  "id": "string"
}
```

<h3 id="poll-conductor-for-the-status-of-a-specified-registered-statecoin-id-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[SwapID](#schemaswapid)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Phase 0 of coinswap: Notify conductor of desire to take part in a swap with signature to prove ownership of statecoin.

<a id="opIdconductor_register_utxo"></a>

> Code samples

`POST /swap/register-utxo`

> Body parameter

```json
{
  "signature": {
    "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
    "purpose": "TRANSFER",
    "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
  },
  "statechain_id": "string",
  "swap_size": 0,
  "wallet_version": "string"
}
```

<h3 id="phase-0-of-coinswap:-notify-conductor-of-desire-to-take-part-in-a-swap-with-signature-to-prove-ownership-of-statecoin.-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[RegisterUtxo](#schemaregisterutxo)|true|none|

> Example responses

> 200 Response

```json
null
```

<h3 id="phase-0-of-coinswap:-notify-conductor-of-desire-to-take-part-in-a-swap-with-signature-to-prove-ownership-of-statecoin.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|null|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Phase 2 of coinswap: Participants provide blind spend token and recieve address.

<a id="opIdconductor_swap_second_message"></a>

> Code samples

`POST /swap/second`

> Body parameter

```json
{
  "blinded_spend_token": {
    "m": "string",
    "r": [
      0
    ],
    "s": [
      0
    ]
  },
  "swap_id": "string"
}
```

<h3 id="phase-2-of-coinswap:-participants-provide-blind-spend-token-and-recieve-address.-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[SwapMsg2](#schemaswapmsg2)|true|none|

> Example responses

> 200 Response

```json
{
  "proof_key": [
    0
  ],
  "tx_backup_addr": "string"
}
```

<h3 id="phase-2-of-coinswap:-participants-provide-blind-spend-token-and-recieve-address.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[SCEAddress](#schemasceaddress)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Initiate the batch transfer protocol: provide statechain signatures

<a id="opIdtransfer_batch_transfer_batch_init"></a>

> Code samples

`POST /transfer/batch/init`

> Body parameter

```json
{
  "id": "string",
  "signatures": [
    {
      "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
      "purpose": "TRANSFER",
      "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
    }
  ]
}
```

<h3 id="initiate-the-batch-transfer-protocol:-provide-statechain-signatures-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[TransferBatchInitMsg](#schematransferbatchinitmsg)|true|none|

> Example responses

> 200 Response

```json
null
```

<h3 id="initiate-the-batch-transfer-protocol:-provide-statechain-signatures-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|null|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Complete Batch transfer: reveal transfer nonce

<a id="opIdtransfer_batch_transfer_reveal_nonce"></a>

> Code samples

`POST /transfer/batch/reveal`

> Body parameter

```json
{
  "batch_id": "string",
  "hash": "string",
  "nonce": [
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  ],
  "statechain_id": "string"
}
```

<h3 id="complete-batch-transfer:-reveal-transfer-nonce-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[TransferRevealNonce](#schematransferrevealnonce)|true|none|

> Example responses

> 200 Response

```json
null
```

<h3 id="complete-batch-transfer:-reveal-transfer-nonce-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|null|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Get stored transfer message (TransferMsg3)

<a id="opIdtransfer_transfer_get_msg_addr"></a>

> Code samples

`GET /transfer/get_msg_addr/{receive_addr}`

<h3 id="get-stored-transfer-message-(transfermsg3)-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|receive_addr|path|string|true|none|

> Example responses

> 200 Response

```json
[
  {
    "rec_auth_key": "string",
    "transfer_data": "string"
  }
]
```

<h3 id="get-stored-transfer-message-(transfermsg3)-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|Inline|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<h3 id="get-stored-transfer-message-(transfermsg3)-responseschema">Response Schema</h3>

Status Code **200**

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|[[TransferMsg3](#schematransfermsg3)]|false|none|[Sender -> Receiver]|
|» rec_auth_key|string|true|none|none|
|» transfer_data|string|true|none|none|

<aside class="success">
This operation does not require authentication
</aside>

## Transfer completing by receiver: key share update and deletion

<a id="opIdtransfer_keyupdate_complete"></a>

> Code samples

`POST /transfer/keyupdate_complete`

> Body parameter

```json
{
  "shared_key_id": "string",
  "statechain_id": "string",
  "auth_sig": "string"
}
```

<h3 id="transfer-completing-by-receiver:-key-share-update-and-deletion-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[KUFinalize](#schemakufinalize)|true|none|

> Example responses

> 200 Response

```json
null
```

<h3 id="transfer-completing-by-receiver:-key-share-update-and-deletion-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|null|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Transfer completing by receiver: retreival of signature verification key information and key share update

<a id="opIdtransfer_transfer_receiver"></a>

> Code samples

`POST /transfer/receiver`

> Body parameter

```json
{
  "batch_data": {
    "commitment": "string",
    "id": "string"
  },
  "shared_key_id": "string",
  "statechain_id": "string",
  "statechain_sig": {
    "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
    "purpose": "TRANSFER",
    "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
  },
  "t2": [
    0
  ]
}
```

<h3 id="transfer-completing-by-receiver:-retreival-of-signature-verification-key-information-and-key-share-update-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[TransferMsg4](#schematransfermsg4)|true|none|

> Example responses

> 200 Response

```json
{
  "new_shared_key_id": "string",
  "s2_pub": [
    0
  ],
  "blind_commits": [
    "string"
  ],
  "r2_commits": [
    "string"
  ]
}
```

<h3 id="transfer-completing-by-receiver:-retreival-of-signature-verification-key-information-and-key-share-update-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[TransferMsg5](#schematransfermsg5)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Transfer initiation by sender: get x1 transfer nonce and authorise reciver auth key

<a id="opIdtransfer_transfer_sender"></a>

> Code samples

`POST /transfer/sender`

> Body parameter

```json
{
  "batch_id": "string",
  "shared_key_id": "string",
  "auth_sig": {
    "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
    "purpose": "TRANSFER",
    "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
  }
}
```

<h3 id="transfer-initiation-by-sender:-get-x1-transfer-nonce-and-authorise-reciver-auth-key-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[TransferMsg1](#schematransfermsg1)|true|none|

> Example responses

> 200 Response

```json
{
  "x1": {
    "secret_bytes": [
      0
    ]
  }
}
```

<h3 id="transfer-initiation-by-sender:-get-x1-transfer-nonce-and-authorise-reciver-auth-key-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[TransferMsg2](#schematransfermsg2)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Update stored transfer message (TransferMsg3)

<a id="opIdtransfer_transfer_update_msg"></a>

> Code samples

`POST /transfer/update_msg`

> Body parameter

```json
{
  "rec_auth_key": "string",
  "transfer_data": "string"
}
```

<h3 id="update-stored-transfer-message-(transfermsg3)-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[TransferMsg3](#schematransfermsg3)|true|none|

> Example responses

> 200 Response

```json
null
```

<h3 id="update-stored-transfer-message-(transfermsg3)-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|null|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

## Complete the withdrawal process: confirm withdrawal transaction

<a id="opIdwithdraw_withdraw_confirm"></a>

> Code samples

`POST /withdraw/confirm`

> Body parameter

```json
{
  "shared_key_id": "string",
  "statechain_id": "string",
  "auth_sig": [
    {
      "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
      "purpose": "TRANSFER",
      "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
    }
  ]
}
```

<h3 id="complete-the-withdrawal-process:-confirm-withdrawal-transaction-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[WithdrawMsg](#schemawithdrawmsg)|true|none|

> Example responses

> 200 Response

```json
null
```

<h3 id="complete-the-withdrawal-process:-confirm-withdrawal-transaction-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|null|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|# [500 Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
This response is given when the server has an internal error that it could not recover from.

If you get this response please report this as an issue at github.com/commerceblock/mercury.|None|

<aside class="success">
This operation does not require authentication
</aside>

# Schemas

<h2 id="tocS_Address">Address</h2>
<!-- backwards compatibility -->
<a id="schemaaddress"></a>
<a id="schema_Address"></a>
<a id="tocSaddress"></a>
<a id="tocsaddress"></a>

```json
"string"

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|none|

<h2 id="tocS_BSTMsg">BSTMsg</h2>
<!-- backwards compatibility -->
<a id="schemabstmsg"></a>
<a id="schema_BSTMsg"></a>
<a id="tocSbstmsg"></a>
<a id="tocsbstmsg"></a>

```json
{
  "statechain_id": "string",
  "swap_id": "string"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|statechain_id|string|true|none|none|
|swap_id|string|true|none|none|

<h2 id="tocS_BSTSenderData">BSTSenderData</h2>
<!-- backwards compatibility -->
<a id="schemabstsenderdata"></a>
<a id="schema_BSTSenderData"></a>
<a id="tocSbstsenderdata"></a>
<a id="tocsbstsenderdata"></a>

```json
{
  "k": [
    0
  ],
  "q": [
    0
  ],
  "r_prime": [
    0
  ],
  "x": [
    0
  ]
}

```

Blind Spend Token data for each Swap. (priv, pub) keypair, k and R' value for signing and verification.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|k|[FE](#schemafe)|true|none|none|
|q|[GE](#schemage)|true|none|none|
|r_prime|[GE](#schemage)|true|none|none|
|x|[FE](#schemafe)|true|none|none|

<h2 id="tocS_BatchData">BatchData</h2>
<!-- backwards compatibility -->
<a id="schemabatchdata"></a>
<a id="schema_BatchData"></a>
<a id="tocSbatchdata"></a>
<a id="tocsbatchdata"></a>

```json
{
  "commitment": "string",
  "id": "string"
}

```

Data present if transfer is part of an atomic batch transfer

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|commitment|string|true|none|none|
|id|[Uuid](#schemauuid)|true|none|none|

<h2 id="tocS_BlindedSpendSignature">BlindedSpendSignature</h2>
<!-- backwards compatibility -->
<a id="schemablindedspendsignature"></a>
<a id="schema_BlindedSpendSignature"></a>
<a id="tocSblindedspendsignature"></a>
<a id="tocsblindedspendsignature"></a>

```json
{
  "s_prime": [
    0
  ]
}

```

blind spend signature

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|s_prime|[FE](#schemafe)|true|none|none|

<h2 id="tocS_BlindedSpendToken">BlindedSpendToken</h2>
<!-- backwards compatibility -->
<a id="schemablindedspendtoken"></a>
<a id="schema_BlindedSpendToken"></a>
<a id="tocSblindedspendtoken"></a>
<a id="tocsblindedspendtoken"></a>

```json
{
  "m": "string",
  "r": [
    0
  ],
  "s": [
    0
  ]
}

```

(s,r) blind spend token

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|m|string|true|none|none|
|r|[GE](#schemage)|true|none|none|
|s|[FE](#schemafe)|true|none|none|

<h2 id="tocS_CoinValueInfo">CoinValueInfo</h2>
<!-- backwards compatibility -->
<a id="schemacoinvalueinfo"></a>
<a id="schema_CoinValueInfo"></a>
<a id="tocScoinvalueinfo"></a>
<a id="tocscoinvalueinfo"></a>

```json
{
  "values": {
    "property1": 1,
    "property2": 1
  }
}

```

List of current statecoin amounts and the number of each

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|values|object|true|none|none|
|» **additionalProperties**|integer(uint64)|false|none|none|

<h2 id="tocS_DepositMsg1POD">DepositMsg1POD</h2>
<!-- backwards compatibility -->
<a id="schemadepositmsg1pod"></a>
<a id="schema_DepositMsg1POD"></a>
<a id="tocSdepositmsg1pod"></a>
<a id="tocsdepositmsg1pod"></a>

```json
{
  "amount": 0,
  "auth_key": "string",
  "token_id": "string"
}

```

Client -> SE

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|amount|integer(uint64)|true|none|none|
|auth_key|string|true|none|none|
|token_id|[Uuid](#schemauuid)|true|none|none|

<h2 id="tocS_DepositMsg2">DepositMsg2</h2>
<!-- backwards compatibility -->
<a id="schemadepositmsg2"></a>
<a id="schema_DepositMsg2"></a>
<a id="tocSdepositmsg2"></a>
<a id="tocsdepositmsg2"></a>

```json
{
  "shared_key_id": "string"
}

```

Client -> SE

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|shared_key_id|[Uuid](#schemauuid)|true|none|none|

<h2 id="tocS_FE">FE</h2>
<!-- backwards compatibility -->
<a id="schemafe"></a>
<a id="schema_FE"></a>
<a id="tocSfe"></a>
<a id="tocsfe"></a>

```json
[
  0
]

```

### Properties

*None*

<h2 id="tocS_FESer">FESer</h2>
<!-- backwards compatibility -->
<a id="schemafeser"></a>
<a id="schema_FESer"></a>
<a id="tocSfeser"></a>
<a id="tocsfeser"></a>

```json
{
  "secret_bytes": [
    0
  ]
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|secret_bytes|[integer]|true|none|none|

<h2 id="tocS_GE">GE</h2>
<!-- backwards compatibility -->
<a id="schemage"></a>
<a id="schema_GE"></a>
<a id="tocSge"></a>
<a id="tocsge"></a>

```json
[
  0
]

```

### Properties

*None*

<h2 id="tocS_GroupStatus">GroupStatus</h2>
<!-- backwards compatibility -->
<a id="schemagroupstatus"></a>
<a id="schema_GroupStatus"></a>
<a id="tocSgroupstatus"></a>
<a id="tocsgroupstatus"></a>

```json
"2:1691151686"

```

Swap group status data

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|number|integer(uint64)|true|none|none|
|time|string(partial-date-time)|true|none|none|

<h2 id="tocS_Invoice">Invoice</h2>
<!-- backwards compatibility -->
<a id="schemainvoice"></a>
<a id="schema_Invoice"></a>
<a id="tocSinvoice"></a>
<a id="tocsinvoice"></a>

```json
{
  "bolt11": "string",
  "expires_at": 0,
  "payment_hash": "string"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|bolt11|string|true|none|none|
|expires_at|integer(uint64)|true|none|none|
|payment_hash|string|true|none|none|

<h2 id="tocS_KUFinalize">KUFinalize</h2>
<!-- backwards compatibility -->
<a id="schemakufinalize"></a>
<a id="schema_KUFinalize"></a>
<a id="tocSkufinalize"></a>
<a id="tocskufinalize"></a>

```json
{
  "shared_key_id": "string",
  "statechain_id": "string",
  "auth_sig": "string"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|shared_key_id|[Uuid](#schemauuid)|true|none|none|
|statechain_id|[Uuid](#schemauuid)|true|none|none|
|auth_sig|[Uuid](#schemauuid)|true|none|none|

<h2 id="tocS_OwnerID">OwnerID</h2>
<!-- backwards compatibility -->
<a id="schemaownerid"></a>
<a id="schema_OwnerID"></a>
<a id="tocSownerid"></a>
<a id="tocsownerid"></a>

```json
{
  "shared_key_id": "string"
}

```

State Entity -> Receiver

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|shared_key_id|[Uuid](#schemauuid)|true|none|none|

<h2 id="tocS_PK">PK</h2>
<!-- backwards compatibility -->
<a id="schemapk"></a>
<a id="schema_PK"></a>
<a id="tocSpk"></a>
<a id="tocspk"></a>

```json
[
  0
]

```

### Properties

*None*

<h2 id="tocS_PODInfo">PODInfo</h2>
<!-- backwards compatibility -->
<a id="schemapodinfo"></a>
<a id="schema_PODInfo"></a>
<a id="tocSpodinfo"></a>
<a id="tocspodinfo"></a>

```json
{
  "btc_payment_address": "string",
  "lightning_invoice": {
    "bolt11": "string",
    "expires_at": 0,
    "payment_hash": "string"
  },
  "token_id": "string",
  "value": 0
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|btc_payment_address|[Address](#schemaaddress)|true|none|none|
|lightning_invoice|[Invoice](#schemainvoice)|true|none|none|
|token_id|[Uuid](#schemauuid)|true|none|none|
|value|integer(uint64)|true|none|none|

<h2 id="tocS_PODStatus">PODStatus</h2>
<!-- backwards compatibility -->
<a id="schemapodstatus"></a>
<a id="schema_PODStatus"></a>
<a id="tocSpodstatus"></a>
<a id="tocspodstatus"></a>

```json
{
  "amount": 0,
  "confirmed": true
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|amount|integer(uint64)|true|none|none|
|confirmed|boolean|true|none|none|

<h2 id="tocS_DepositInitResponse">DepositInitResponse</h2>
<!-- backwards compatibility -->
<a id="schemadepositinitresponse"></a>
<a id="schema_DepositInitResponse"></a>
<a id="tocSdepositinitresponse"></a>
<a id="tocsdepositinitresponse"></a>

```json
{
  "user_id": "string",
  "statechain_id": "string",
  "se_pubkey": "string"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|user_id|[Uuid](#schemauuid)|true|none|none|
|statechain_id|[Uuid](#schemauuid)|true|none|none|
|se_pubkey|string¦null|true|none|Server public key share|

<h2 id="tocS_Protocol">Protocol</h2>
<!-- backwards compatibility -->
<a id="schemaprotocol"></a>
<a id="schema_Protocol"></a>
<a id="tocSprotocol"></a>
<a id="tocsprotocol"></a>

```json
"Deposit"

```

State Entity protocols

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|State Entity protocols|

#### Enumerated Values

|Property|Value|
|---|---|
|*anonymous*|Deposit|
|*anonymous*|Transfer|
|*anonymous*|Withdraw|

<h2 id="tocS_PublicKey">PublicKey</h2>
<!-- backwards compatibility -->
<a id="schemapublickey"></a>
<a id="schema_PublicKey"></a>
<a id="tocSpublickey"></a>
<a id="tocspublickey"></a>

```json
[
  0
]

```

### Properties

*None*

<h2 id="tocS_RecoveryDataMsg">RecoveryDataMsg</h2>
<!-- backwards compatibility -->
<a id="schemarecoverydatamsg"></a>
<a id="schema_RecoveryDataMsg"></a>
<a id="tocSrecoverydatamsg"></a>
<a id="tocsrecoverydatamsg"></a>

```json
{
  "amount": 0,
  "proof_key": "03b2483ab9bea9843bd9bfb941e8c86c1308e77aa95fccd0e63c2874c0e3ead3f5",
  "shared_key_data": "",
  "shared_key_id": "d0e43718-08f5-4e54-b1d1-98d55deea4ae",
  "statechain_id": "d11ce1c9-6e91-4b21-a960-fa83e2f23c55",
  "tx_hex": "02000000000101ca878085da49c33eb9816c10e4056424e5e062689ea547ea91bb3aa840a3c5fb0000000000ffffffff02307500000000000016001412cc36c9533290c02f0c78f992df6e6ddfe50c8c0064f50500000000160014658fd2dc72e58168f3656fb632d63be54f80fbe4024730440220457cf52873ae5854859a7d48b39cb57eba880ea4011806e5058da7619f4c0fab02206303326f06bbebf7170b679ba787c856dec4b6462109bf66e1cb8dc087be7ebf012102a95498bdde2c8c4078f01840b3bc8f4ae5bb1a90b880a621f50ce221bce3ddbe00000000",
  "withdrawing": null
}

```

Struct with recovery information for specified proof key

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|amount|integer(uint64)¦null|false|none|none|
|proof_key|string|true|none|none|
|shared_key_data|string|true|none|none|
|shared_key_id|[Uuid](#schemauuid)|true|none|none|
|statechain_id|[Uuid](#schemauuid)|true|none|none|
|tx_hex|string¦null|false|none|none|
|withdrawing|[WithdrawingData](#schemawithdrawingdata)¦null|false|none|none|

<h2 id="tocS_RegisterUtxo">RegisterUtxo</h2>
<!-- backwards compatibility -->
<a id="schemaregisterutxo"></a>
<a id="schema_RegisterUtxo"></a>
<a id="tocSregisterutxo"></a>
<a id="tocsregisterutxo"></a>

```json
{
  "signature": {
    "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
    "purpose": "TRANSFER",
    "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
  },
  "statechain_id": "string",
  "swap_size": 0,
  "wallet_version": "string"
}

```

Owner -> Conductor

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|signature|[AuthSig](#schemaauthsig)|true|none|Signature object Data necessary to create ownership transfer signatures|
|statechain_id|[Uuid](#schemauuid)|true|none|none|
|swap_size|integer(uint64)|true|none|none|
|wallet_version|string|true|none|none|

<h2 id="tocS_KeyList">KeyList</h2>
<!-- backwards compatibility -->
<a id="schemakeylist"></a>
<a id="schema_KeyList"></a>
<a id="tocSkeylist"></a>
<a id="tocskeylist"></a>

```json
{
  "pubkeys": [
    "string"
  ]
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|pubkeys|[string]¦null|false|none|none|

<h2 id="tocS_S1PubKey">S1PubKey</h2>
<!-- backwards compatibility -->
<a id="schemas1pubkey"></a>
<a id="schema_S1PubKey"></a>
<a id="tocSs1pubkey"></a>
<a id="tocss1pubkey"></a>

```json
{
  "key": "string"
}

```

SE public key share for encryption

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|key|string|true|none|none|

<h2 id="tocS_SCEAddress">SCEAddress</h2>
<!-- backwards compatibility -->
<a id="schemasceaddress"></a>
<a id="schema_SCEAddress"></a>
<a id="tocSsceaddress"></a>
<a id="tocssceaddress"></a>

```json
{
  "proof_key": [
    0
  ],
  "tx_backup_addr": "string"
}

```

Address generated for State Entity transfer protocol

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|proof_key|[PublicKey](#schemapublickey)|true|none|none|
|tx_backup_addr|[Address](#schemaaddress)|true|none|none|

<h2 id="tocS_SignMessage">SignMessage</h2>
<!-- backwards compatibility -->
<a id="schemasignmessage"></a>
<a id="schema_SignMessage"></a>
<a id="tocSsignmessage"></a>
<a id="tocssignmessage"></a>

```json
"string"

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|none|

<h2 id="tocS_SignMsg1">SignMsg1</h2>
<!-- backwards compatibility -->
<a id="schemasignmsg1"></a>
<a id="schema_SignMsg1"></a>
<a id="tocSsignmsg1"></a>
<a id="tocssignmsg1"></a>

```json
{
  "r2_commitment": "string",
  "blind_commitment": "string",
  "statechain_id": "string",
  "user_id": "string",
  "auth_sig": "string"
}

```

User commitments for signing

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|r2_commitment|string|true|none|none|
|blind_commitment|string|true|none|none|
|statechain_id|[Uuid](#schemauuid)|true|none|none|
|user_id|[Uuid](#schemauuid)|true|none|none|
|auth_sig|string|true|none|none|

<h2 id="tocS_SignMsg2">SignMsg2</h2>
<!-- backwards compatibility -->
<a id="schemasignmsg2"></a>
<a id="schema_SignMsg2"></a>
<a id="tocSsignmsg2"></a>
<a id="tocssignmsg2"></a>

```json
{
  "shared_key_id": "string",
  "challenge": "string",
  "user_id": "string",
  "auth_sig": "string"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|shared_key_id|[Uuid](#schemauuid)|false|none|none|
|challenge|string|true|none|none|
|user_id|[Uuid](#schemauuid)|true|none|none|
|auth_sig|string|true|none|none|

<h2 id="tocS_SignReply1">SignReply1</h2>
<!-- backwards compatibility -->
<a id="schemasignreply1"></a>
<a id="schema_SignReply1"></a>
<a id="tocSsignreply1"></a>
<a id="tocssignreply1"></a>

```json
{
  "r1_public": "string"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|r1_public|string|true|none|none|

<h2 id="tocS_Signature">Signature</h2>
<!-- backwards compatibility -->
<a id="schemasignature"></a>
<a id="schema_Signature"></a>
<a id="tocSsignature"></a>
<a id="tocssignature"></a>

```json
"string"

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|none|

<h2 id="tocS_SmtProofMsgAPI">SmtProofMsgAPI</h2>
<!-- backwards compatibility -->
<a id="schemasmtproofmsgapi"></a>
<a id="schema_SmtProofMsgAPI"></a>
<a id="tocSsmtproofmsgapi"></a>
<a id="tocssmtproofmsgapi"></a>

```json
{
  "funding_txid": "string",
  "root": null
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|funding_txid|string|true|none|none|
|root|[Root](#schemaroot)|true|none|none|

<h2 id="tocS_State">State</h2>
<!-- backwards compatibility -->
<a id="schemastate"></a>
<a id="schema_State"></a>
<a id="tocSstate"></a>
<a id="tocsstate"></a>

```json
{
  "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
  "next_state": {
    "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
    "purpose": "TRANSFER",
    "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
  }
}

```

State update object State to change statecoin ownership to new owner

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|data|string|true|none|The new owner proof public key (if transfer) or address (if withdrawal)|
|next_state|[AuthSig](#schemaauthsig)¦null|false|none|Current owner signature representing passing of ownership|

<h2 id="tocS_StateChainDataAPI">StateChainDataAPI</h2>
<!-- backwards compatibility -->
<a id="schemastatechaindataapi"></a>
<a id="schema_StateChainDataAPI"></a>
<a id="tocSstatechaindataapi"></a>
<a id="tocsstatechaindataapi"></a>

```json
{
  "amount": 0,
  "chain": [
    {
      "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
      "next_state": {
        "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
        "purpose": "TRANSFER",
        "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
      }
    }
  ]
}

```

Statechain data This struct is returned containing the statechain of the specified statechain ID

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|amount|integer(uint64)|true|none|The value of the statecoin (in satoshis)|
|chain|[[State](#schemastate)]|true|none|The statechain of owner proof keys and signatures|

<h2 id="tocS_AuthSig">AuthSig</h2>
<!-- backwards compatibility -->
<a id="schemaauthsig"></a>
<a id="schema_AuthSig"></a>
<a id="tocSauthsig"></a>
<a id="tocsauthsig"></a>

```json
{
  "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
  "purpose": "TRANSFER",
  "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
}

```

Signature object Data necessary to create ownership transfer signatures

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|data|string|true|none|The new owner auth public key (if transfer)|
|purpose|string|true|none|Purpose: "TRANSFER", "TRANSFER-BATCH" or "WITHDRAW"|
|sig|string|true|none|Current owner signature.|

<h2 id="tocS_StateCoinDataAPI">StateCoinDataAPI</h2>
<!-- backwards compatibility -->
<a id="schemastatecoindataapi"></a>
<a id="schema_StateCoinDataAPI"></a>
<a id="tocSstatecoindataapi"></a>
<a id="tocsstatecoindataapi"></a>

```json
{
  "amount": 1000000,
  "confirmed": true,
  "locktime": 712903,
  "statecoin": {
    "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
    "next_state": {
      "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
      "purpose": "TRANSFER",
      "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
    }
  },
  "utxo": "0000000000000000000000000000000000000000000000000000000000000000:4294967295"
}

```

Statechain tip data This struct is returned containing the statecoin (statechain tip) of the specified statechain ID

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|amount|integer(uint64)|true|none|The value of the statecoin (in satoshis)|
|confirmed|boolean|true|none|The coin confirmation status|
|locktime|integer(uint32)|true|none|The current owner nLocktime|
|statecoin|[State](#schemastate)|true|none|The tip of the statechain of owner proof keys and signatures|
|utxo|[OutPoint](#schemaoutpoint)|true|none|The statecoin UTXO OutPoint|

<h2 id="tocS_StateEntityFeeInfoAPI">StateEntityFeeInfoAPI</h2>
<!-- backwards compatibility -->
<a id="schemastateentityfeeinfoapi"></a>
<a id="schema_StateEntityFeeInfoAPI"></a>
<a id="tocSstateentityfeeinfoapi"></a>
<a id="tocsstateentityfeeinfoapi"></a>

```json
{
  "address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
  "backup_fee_rate": 1,
  "deposit": 0,
  "initlock": 14400,
  "interval": 144,
  "wallet_message": "Warning",
  "wallet_version": "0.4.65",
  "withdraw": 300
}

```

Statechain entity operating information This struct is returned containing information on operating requirements of the statechain entity which must be conformed with in the protocol.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|address|string|true|none|The Bitcoin address that the SE fee must be paid to|
|backup_fee_rate|integer(uint64)|true|none|Current backup tx fee rate|
|deposit|integer(int64)|true|none|The deposit fee, which is specified as a proportion of the deposit amount in basis points|
|initlock|integer(uint32)|true|none|The initial nLocktime from the current blockheight for the first backup|
|interval|integer(uint32)|true|none|The decementing nLocktime (block height) interval enforced for backup transactions|
|wallet_message|string|true|none|Message to display to all wallet users on startup|
|wallet_version|string|true|none|The minumum wallet version required|
|withdraw|integer(uint64)|true|none|The withdrawal fee, which is specified as a proportion of the deposit amount in basis points|

<h2 id="tocS_StatechainID">StatechainID</h2>
<!-- backwards compatibility -->
<a id="schemastatechainid"></a>
<a id="schema_StatechainID"></a>
<a id="tocSstatechainid"></a>
<a id="tocsstatechainid"></a>

```json
{
  "id": "string"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|[Uuid](#schemauuid)|true|none|none|

<h2 id="tocS_SwapID">SwapID</h2>
<!-- backwards compatibility -->
<a id="schemaswapid"></a>
<a id="schema_SwapID"></a>
<a id="tocSswapid"></a>
<a id="tocsswapid"></a>

```json
{
  "id": "string"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|[Uuid](#schemauuid)|true|none|none|

<h2 id="tocS_SwapInfo">SwapInfo</h2>
<!-- backwards compatibility -->
<a id="schemaswapinfo"></a>
<a id="schema_SwapInfo"></a>
<a id="tocSswapinfo"></a>
<a id="tocsswapinfo"></a>

```json
{
  "bst_sender_data": {
    "k": [
      0
    ],
    "q": [
      0
    ],
    "r_prime": [
      0
    ],
    "x": [
      0
    ]
  },
  "status": "Phase1",
  "swap_token": {
    "amount": 0,
    "id": "string",
    "statechain_ids": "string",
    "time_out": 0
  }
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|bst_sender_data|[BSTSenderData](#schemabstsenderdata)|true|none|Blind Spend Token data for each Swap. (priv, pub) keypair, k and R' value for signing and verification.|
|status|[SwapStatus](#schemaswapstatus)|true|none|none|
|swap_token|[SwapToken](#schemaswaptoken)|true|none|Struct defines a Swap. This is signed by each participant as agreement to take part in the swap.|

<h2 id="tocS_SwapMsg1">SwapMsg1</h2>
<!-- backwards compatibility -->
<a id="schemaswapmsg1"></a>
<a id="schema_SwapMsg1"></a>
<a id="tocSswapmsg1"></a>
<a id="tocsswapmsg1"></a>

```json
{
  "address": {
    "proof_key": [
      0
    ],
    "tx_backup_addr": "string"
  },
  "bst_e_prime": [
    0
  ],
  "statechain_id": "string",
  "swap_id": "string",
  "swap_token_sig": "string",
  "transfer_batch_sig": {
    "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
    "purpose": "TRANSFER",
    "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
  }
}

```

Owner -> Conductor

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|address|[SCEAddress](#schemasceaddress)|true|none|Address generated for State Entity transfer protocol|
|bst_e_prime|[FE](#schemafe)|true|none|none|
|statechain_id|[Uuid](#schemauuid)|true|none|none|
|swap_id|[Uuid](#schemauuid)|true|none|none|
|swap_token_sig|[Signature](#schemasignature)|true|none|none|
|transfer_batch_sig|[AuthSig](#schemaauthsig)|true|none|Signature object Data necessary to create ownership transfer signatures|

<h2 id="tocS_SwapMsg2">SwapMsg2</h2>
<!-- backwards compatibility -->
<a id="schemaswapmsg2"></a>
<a id="schema_SwapMsg2"></a>
<a id="tocSswapmsg2"></a>
<a id="tocsswapmsg2"></a>

```json
{
  "blinded_spend_token": {
    "m": "string",
    "r": [
      0
    ],
    "s": [
      0
    ]
  },
  "swap_id": "string"
}

```

Owner -> Conductor

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|blinded_spend_token|[BlindedSpendToken](#schemablindedspendtoken)|true|none|(s,r) blind spend token|
|swap_id|[Uuid](#schemauuid)|true|none|none|

<h2 id="tocS_SwapStatus">SwapStatus</h2>
<!-- backwards compatibility -->
<a id="schemaswapstatus"></a>
<a id="schema_SwapStatus"></a>
<a id="tocSswapstatus"></a>
<a id="tocsswapstatus"></a>

```json
"Phase1"

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|none|

#### Enumerated Values

|Property|Value|
|---|---|
|*anonymous*|Phase1|
|*anonymous*|Phase2|
|*anonymous*|Phase3|
|*anonymous*|Phase4|
|*anonymous*|End|

<h2 id="tocS_SwapToken">SwapToken</h2>
<!-- backwards compatibility -->
<a id="schemaswaptoken"></a>
<a id="schema_SwapToken"></a>
<a id="tocSswaptoken"></a>
<a id="tocsswaptoken"></a>

```json
{
  "amount": 0,
  "id": "string",
  "statechain_ids": "string",
  "time_out": 0
}

```

Struct defines a Swap. This is signed by each participant as agreement to take part in the swap.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|amount|integer(uint64)|true|none|none|
|id|[Uuid](#schemauuid)|true|none|none|
|statechain_ids|[Uuid](#schemauuid)|true|none|none|
|time_out|integer(uint64)|true|none|none|

<h2 id="tocS_TransferBatchDataAPI">TransferBatchDataAPI</h2>
<!-- backwards compatibility -->
<a id="schematransferbatchdataapi"></a>
<a id="schema_TransferBatchDataAPI"></a>
<a id="tocStransferbatchdataapi"></a>
<a id="tocstransferbatchdataapi"></a>

```json
{
  "finalized": true,
  "state_chains": "string"
}

```

/info/transfer-batch return struct

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|finalized|boolean|true|none|none|
|state_chains|[Uuid](#schemauuid)|true|none|none|

<h2 id="tocS_TransferBatchInitMsg">TransferBatchInitMsg</h2>
<!-- backwards compatibility -->
<a id="schematransferbatchinitmsg"></a>
<a id="schema_TransferBatchInitMsg"></a>
<a id="tocStransferbatchinitmsg"></a>
<a id="tocstransferbatchinitmsg"></a>

```json
{
  "id": "string",
  "signatures": [
    {
      "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
      "purpose": "TRANSFER",
      "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
    }
  ]
}

```

Conductor -> StateEntity

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|[Uuid](#schemauuid)|true|none|none|
|signatures|[[AuthSig](#schemaauthsig)]|true|none|[Signature object Data necessary to create ownership transfer signatures]|

<h2 id="tocS_TransferFinalizeData">TransferFinalizeData</h2>
<!-- backwards compatibility -->
<a id="schematransferfinalizedata"></a>
<a id="schema_TransferFinalizeData"></a>
<a id="tocStransferfinalizedata"></a>
<a id="tocstransferfinalizedata"></a>

```json
{
  "batch_data": null,
  "new_shared_key_id": "8853bbb8-c6f2-4b0d-b7f1-4648d38d8d5b",
  "new_tx_backup_hex": "02000000000101ca878085da49c33eb9816c10e4056424e5e062689ea547ea91bb3aa840a3c5fb0000000000ffffffff02307500000000000016001412cc36c9533290c02f0c78f992df6e6ddfe50c8c0064f50500000000160014658fd2dc72e58168f3656fb632d63be54f80fbe4024730440220457cf52873ae5854859a7d48b39cb57eba880ea4011806e5058da7619f4c0fab02206303326f06bbebf7170b679ba787c856dec4b6462109bf66e1cb8dc087be7ebf012102a95498bdde2c8c4078f01840b3bc8f4ae5bb1a90b880a621f50ce221bce3ddbe00000000",
  "s2": "572b4094b5a6da640829f7923bc55324e123604f6d2b5f6d20b3483cd89ce828",
  "statechain_id": "81810e33-b23c-4fa5-b36b-60bc14b0787e",
  "statechain_sig": {
    "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
    "purpose": "TRANSFER",
    "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
  }
}

```

Struct holds data when transfer is complete but not yet finalized

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|batch_data|[BatchData](#schemabatchdata)¦null|false|none|Data present if transfer is part of an atomic batch transfer|
|new_shared_key_id|[Uuid](#schemauuid)|true|none|none|
|new_tx_backup_hex|string|true|none|none|
|s2|[FE](#schemafe)|true|none|none|
|statechain_id|[Uuid](#schemauuid)|true|none|none|
|statechain_sig|[AuthSig](#schemaauthsig)|true|none|Signature object Data necessary to create ownership transfer signatures|

<h2 id="tocS_TransferMsg1">TransferMsg1</h2>
<!-- backwards compatibility -->
<a id="schematransfermsg1"></a>
<a id="schema_TransferMsg1"></a>
<a id="tocStransfermsg1"></a>
<a id="tocstransfermsg1"></a>

```json
{
  "batch_id": "string",
  "shared_key_id": "string",
  "auth_sig": {
    "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
    "purpose": "TRANSFER",
    "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
  }
}

```

Sender -> SE

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|batch_id|[Uuid](#schemauuid)|true|none|none|
|shared_key_id|[Uuid](#schemauuid)|true|none|none|
|auth_sig|[AuthSig](#schemaauthsig)|true|none|Signature object Data necessary to create ownership transfer signatures|

<h2 id="tocS_TransferMsg2">TransferMsg2</h2>
<!-- backwards compatibility -->
<a id="schematransfermsg2"></a>
<a id="schema_TransferMsg2"></a>
<a id="tocStransfermsg2"></a>
<a id="tocstransfermsg2"></a>

```json
{
  "x1": {
    "secret_bytes": [
      0
    ]
  }
}

```

SE -> Sender

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|x1|[FESer](#schemafeser)|true|none|none|

<h2 id="tocS_TransferMsg3">TransferMsg3</h2>
<!-- backwards compatibility -->
<a id="schematransfermsg3"></a>
<a id="schema_TransferMsg3"></a>
<a id="tocStransfermsg3"></a>
<a id="tocstransfermsg3"></a>

```json
{
  "rec_auth_key": "string",
  "transfer_data": "string"
}

```

Sender -> Receiver

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|rec_auth_key|string|true|none|none|
|transfer_data|string|true|none|none|

<h2 id="tocS_TransferMsg4">TransferMsg4</h2>
<!-- backwards compatibility -->
<a id="schematransfermsg4"></a>
<a id="schema_TransferMsg4"></a>
<a id="tocStransfermsg4"></a>
<a id="tocstransfermsg4"></a>

```json
{
  "batch_data": {
    "commitment": "string",
    "id": "string"
  },
  "shared_key_id": "string",
  "statechain_id": "string",
  "statechain_sig": {
    "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
    "purpose": "TRANSFER",
    "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
  },
  "t2": [
    0
  ]
}

```

Receiver -> State Entity

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|batch_data|[BatchData](#schemabatchdata)¦null|false|none|Data present if transfer is part of an atomic batch transfer|
|shared_key_id|[Uuid](#schemauuid)|false|none|none|
|statechain_id|[Uuid](#schemauuid)|true|none|none|
|statechain_sig|[AuthSig](#schemaauthsig)|false|none|Signature object Data necessary to create ownership transfer signatures|
|t2|[FE](#schemafe)|true|none|none|

<h2 id="tocS_TransferMsg5">TransferMsg5</h2>
<!-- backwards compatibility -->
<a id="schematransfermsg5"></a>
<a id="schema_TransferMsg5"></a>
<a id="tocStransfermsg5"></a>
<a id="tocstransfermsg5"></a>

```json
{
  "new_shared_key_id": "string",
  "s2_pub": [
    0
  ],
  "blind_commits": [
    "string"
  ],
  "r2_commits": [
    "string"
  ]
}

```

State Entity -> Receiver

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|new_shared_key_id|[Uuid](#schemauuid)|true|none|none|
|s2_pub|[GE](#schemage)|true|none|none|
|blind_commits|[string]|true|none|none|
|r2_commits|[string]|true|none|none|

<h2 id="tocS_TransferRevealNonce">TransferRevealNonce</h2>
<!-- backwards compatibility -->
<a id="schematransferrevealnonce"></a>
<a id="schema_TransferRevealNonce"></a>
<a id="tocStransferrevealnonce"></a>
<a id="tocstransferrevealnonce"></a>

```json
{
  "batch_id": "string",
  "hash": "string",
  "nonce": [
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  ],
  "statechain_id": "string"
}

```

User -> State Entity

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|batch_id|[Uuid](#schemauuid)|true|none|none|
|hash|string|true|none|none|
|nonce|[integer]|true|none|none|
|statechain_id|[Uuid](#schemauuid)|true|none|none|

<h2 id="tocS_UserID">UserID</h2>
<!-- backwards compatibility -->
<a id="schemauserid"></a>
<a id="schema_UserID"></a>
<a id="tocSuserid"></a>
<a id="tocsuserid"></a>

```json
{
  "challenge": "string",
  "id": "string"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|challenge|string¦null|false|none|none|
|id|[Uuid](#schemauuid)|true|none|none|

<h2 id="tocS_Uuid">Uuid</h2>
<!-- backwards compatibility -->
<a id="schemauuid"></a>
<a id="schema_Uuid"></a>
<a id="tocSuuid"></a>
<a id="tocsuuid"></a>

```json
"string"

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|none|

<h2 id="tocS_WithdrawMsg">WithdrawMsg</h2>
<!-- backwards compatibility -->
<a id="schemawithdrawmsg"></a>
<a id="schema_WithdrawMsg"></a>
<a id="tocSwithdrawmsg"></a>
<a id="tocswithdrawmsg"></a>

```json
{
  "shared_key_id": "string",
  "statechain_id": "string",
  "auth_sig": [
    {
      "data": "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd",
      "purpose": "TRANSFER",
      "sig": "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6"
    }
  ]
}

```

Owner -> State Entity

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|shared_key_id|[Uuid](#schemauuid)|true|none|none|
|statechain_id|[Uuid](#schemauuid)|true|none|none|
|auth_sig|[[AuthSig](#schemaauthsig)]|true|none|[Signature object Data necessary to create ownership transfer signatures]|

