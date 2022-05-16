# liblogin-server

---

> ## This package is part of liblogin

### `For use on server side only!!`

### `ServerUtilClass`

```typescript
export class ServerUtil<T extends object | string> {
  /**
   * @param domainUrl url used in hashConnect.authenticate method usually referring to domain of frontend
   * @param privateKey server private key used for signing the payload
   * @param mirrorNodeURL Mirror Node url to use for verification purpose. Including /api/v1 etc so in order to keep it as vendor agnostic as possible and allow it to stay updated
   */
  constructor(
    public domainUrl: string,
    privateKey: string | PrivateKey,
    mirrorNodeURL: string
  ) {}
}
```

#### Functions included inside ServerUtil ->

- ###### validateAccountId
- ###### getPayloadToSign
- ###### getDeterministicObjBuffer
- ###### verifyPayloadSig

### validateAccountId

#### `For a given user's account id checks if it exists and returns its keyType and public key that can be saved in database`

```typescript
/**
 * @param accountID accountID of user
 * @returns publicKey and key type from mirror node for the given accountID
 */
validateAccountId(accountID: string): Promise<{
    accountId: string;
    key: {
      keyType: "ED25519" | "ECDSA";
      key: string;
    };
}>;
```

### getPayloadToSign

#### `Generate the payload and signature to send on frontend`

```typescript
/**
 * @param data object or string to be signed under data field of hashpack #Do not provide a json object as objects are non deterministic liblogin takes care of making a deterministic payload object for you
 * @returns payload object and server signature in base64 format
 */
getPayloadToSign(data: T): {
  payload: {
    url: string;
    data: T;
  };
  serverSig: string;
};
```

### verifyPayloadSig

#### `Verifies the signed payload and user signature from frontend response`

```typescript
/**
 * @param userPubKey as received from mirror node in validateAccountId response
 * @param signedPayload Signed Object as returned from hashconnect.authenticate method
 * @param userSignature base64 formatted sig as provided by liblogin-client
 * @returns If user signed the payload
 */
verifyPayloadSig(userPubKey: string, signedPayload: SignedPayload<T>, userSignature: string): boolean;
```

### getDeterministicObjBuffer

#### `Generates a buffer from an object using deterministic stringification`

```typescript
/**
 * @param userPubKey as received from mirror node in validateAccountId response
 * @param signedPayload Signed Object as returned from hashconnect.authenticate method
 * @param userSignature base64 formatted sig as provided by liblogin-client
 * @returns If user signed the payload
 */
verifyPayloadSig(userPubKey: string, signedPayload: SignedPayload<T>, userSignature: string): boolean;
```

`Addtionaly stand alone stringify is available if needed the api is similar to JSON.stringify `
visit [json-stringify-deterministic](https://github.com/visitkikobeats/json-stringify-deterministic) for more info
