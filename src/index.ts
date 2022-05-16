import { PrivateKey, PublicKey } from "@hashgraph/sdk";
import axios from "axios";
//@ts-ignore
import stringify from "json-stringify-deterministic";
import { Buffer } from "buffer";

export type Network = "mainnet" | "testnet";

export interface SignedPayload<T extends object | string = any> {
  serverSignature: string;
  originalPayload: {
    url: string;
    data: T;
  };
}

interface Payload {
  url: string;
  data: object | string;
}

export class ServerUtil<T extends object | string> {
  private static _instance: ServerUtil<object | string>;
  private publicKey: PublicKey;
  private privateKey: PrivateKey;
  public mirrorNodeURL: string;

  /**
   * @param mirrorNodeURL Mirror Node url to use for verification purpose. Including /api/v1 etc so in order to keep it as vendor agnostic as possible and allow it to stay updated
   * @param privateKey server private key used for signing the payload
   * @param domainUrl url used in hashConnect.authenticate method usually referring to domain of frontend
   */
  constructor(
    public domainUrl: string,
    privateKey: string | PrivateKey,
    mirrorNodeURL: string
  ) {
    if (typeof privateKey === "string") {
      this.privateKey = PrivateKey.fromString(privateKey);
    } else this.privateKey = privateKey;
    this.publicKey = this.privateKey.publicKey;
    this.mirrorNodeURL = mirrorNodeURL;
    ServerUtil._instance = this;
  }

  public static Instance() {
    if (this._instance) return this._instance;
    else throw new Error("not initiaized");
  }

  /**
   * @param accountID account id of user
   * @returns publicKey and key type from mirror node for the given accountID
   */
  async validateAccountId(accountID: string) {
    const { data } = await axios.get<MirrorNodeResponse>(
      `${this.mirrorNodeURL}/accounts?account.id=${accountID}`
    );

    if (data.accounts.length < 1) throw new Error("Invalid account ID");

    const filteredAccounts = data.accounts.filter((account) => {
      return account.account === accountID;
    });

    if (filteredAccounts.length < 1) throw new Error("Invalid account ID");

    if (!filteredAccounts[0].key || !filteredAccounts[0].key.key)
      throw new Error("Account publicKey not found");
    const { _type, key } = filteredAccounts[0].key;
    return {
      accountId: accountID,
      key: {
        keyType: _type,
        key,
      },
    };
  }

  /**
   * @param data object or string to be signed under data field of hashpack #Do not provide a json object as objects are non deterministic liblogin takes care of making a deterministic payload object for you
   * @returns payload object and server signature in base64 format
   */
  getPayloadToSign(data: T) {
    const payload = {
      url: this.domainUrl,
      data: data,
    };
    const serverSig = Buffer.from(
      this.privateKey.sign(this.getDeterministicObjBuffer(payload))
    ).toString("base64");
    return {
      payload,
      serverSig,
    };
  }

  private getDeterministicObjBuffer(payload: object) {
    let payloadForServerSig = Buffer.from(JSON.stringify(payload));
    return payloadForServerSig;
  }

  /**
   * @param userPubKey as received from mirror node
   * @param signedPayload Signed Object as returned from hashconnect.authenticate method
   * @param userSignature base64 formatted sig as provided by liblogin-client
   * @returns If user signed the payload
   */
  verifyPayloadSig(
    userPubKey: string,
    signedPayload: SignedPayload<T>,
    userSignature: string
  ) {
    if (!userPubKey || !signedPayload || !userSignature)
      throw new Error("invalid params");
    const hasServerSigned = this.publicKey.verify(
      this.getDeterministicObjBuffer(signedPayload.originalPayload),
      Buffer.from(signedPayload.serverSignature, "base64")
    );
    console.log({ hasServerSigned });
    if (!hasServerSigned) throw new Error("Unauthorized payload submitted");
    const hasUserSigned = PublicKey.fromString(userPubKey).verify(
      this.getDeterministicObjBuffer(signedPayload),
      Buffer.from(userSignature, "base64")
    );
    console.log({ hasUserSigned, userPubKey });
    return hasUserSigned;
  }
}

interface MirrorNodeResponse {
  accounts: Account[];
  links: Links;
}

interface Links {
  next?: any;
}

interface Account {
  account: string;
  alias?: any;
  auto_renew_period: number;
  balance: Balance;
  deleted: boolean;
  expiry_timestamp?: any;
  key: Key;
  max_automatic_token_associations: number;
  memo: string;
  receiver_sig_required: boolean;
}

interface Key {
  _type: "ED25519" | "ECDSA";
  key: string;
}

interface Balance {
  balance: number;
  timestamp: string;
  tokens: any[];
}
