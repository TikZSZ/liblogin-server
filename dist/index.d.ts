import { PrivateKey } from "@hashgraph/sdk";
import stringify from "json-stringify-deterministic";
export declare type Network = "mainnet" | "testnet";
/**
 * deterministic version of json.stringify
 */
export { stringify };
export interface SignedPayload<T extends object | string = any> {
    serverSignature: string;
    originalPayload: {
        url: string;
        data: T;
    };
}
export declare class ServerUtil<T extends object | string> {
    domainUrl: string;
    private static _instance;
    private publicKey;
    private privateKey;
    mirrorNodeURL: string;
    /**
     * @param mirrorNodeURL Mirror Node url to use for verification purpose. Including /api/v1 etc so in order to keep it as vendor agnostic as possible and allow it to stay updated
     * @param privateKey server private key used for signing the payload
     * @param domainUrl url used in hashConnect.authenticate method usually referring to domain of frontend
     */
    constructor(domainUrl: string, privateKey: string | PrivateKey, mirrorNodeURL: string);
    static Instance(): ServerUtil<string | object>;
    /**
     * @param accountID account id of user
     * @returns publicKey and key type from mirror node for the given accountID
     */
    validateAccountId(accountID: string): Promise<{
        accountId: string;
        key: {
            keyType: "ED25519" | "ECDSA";
            key: string;
        };
    }>;
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
    private getDeterministicObjBuffer;
    /**
     * @param userPubKey as received from mirror node
     * @param signedPayload Signed Object as returned from hashconnect.authenticate method
     * @param userSignature base64 formatted sig as provided by liblogin-client
     * @returns If user signed the payload
     */
    verifyPayloadSig(userPubKey: string, signedPayload: SignedPayload<T>, userSignature: string): boolean;
}
