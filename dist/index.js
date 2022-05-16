import { PrivateKey, PublicKey } from "@hashgraph/sdk";
import axios from "axios";
import { Buffer } from "buffer";
export class ServerUtil {
    domainUrl;
    static _instance;
    publicKey;
    privateKey;
    mirrorNodeURL;
    /**
     * @param mirrorNodeURL Mirror Node url to use for verification purpose. Including /api/v1 etc so in order to keep it as vendor agnostic as possible and allow it to stay updated
     * @param privateKey server private key used for signing the payload
     * @param domainUrl url used in hashConnect.authenticate method usually referring to domain of frontend
     */
    constructor(domainUrl, privateKey, mirrorNodeURL) {
        this.domainUrl = domainUrl;
        if (typeof privateKey === "string") {
            this.privateKey = PrivateKey.fromString(privateKey);
        }
        else
            this.privateKey = privateKey;
        this.publicKey = this.privateKey.publicKey;
        this.mirrorNodeURL = mirrorNodeURL;
        ServerUtil._instance = this;
    }
    static Instance() {
        if (this._instance)
            return this._instance;
        else
            throw new Error("not initiaized");
    }
    /**
     * @param accountID account id of user
     * @returns publicKey and key type from mirror node for the given accountID
     */
    async validateAccountId(accountID) {
        const { data } = await axios.get(`${this.mirrorNodeURL}/accounts?account.id=${accountID}`);
        if (data.accounts.length < 1)
            throw new Error("Invalid account ID");
        const filteredAccounts = data.accounts.filter((account) => {
            return account.account === accountID;
        });
        if (filteredAccounts.length < 1)
            throw new Error("Invalid account ID");
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
    getPayloadToSign(data) {
        const payload = {
            url: this.domainUrl,
            data: data,
        };
        const serverSig = Buffer.from(this.privateKey.sign(this.getDeterministicObjBuffer(payload))).toString("base64");
        return {
            payload,
            serverSig,
        };
    }
    getDeterministicObjBuffer(payload) {
        let payloadForServerSig = Buffer.from(JSON.stringify(payload));
        return payloadForServerSig;
    }
    /**
     * @param userPubKey as received from mirror node
     * @param signedPayload Signed Object as returned from hashconnect.authenticate method
     * @param userSignature base64 formatted sig as provided by liblogin-client
     * @returns If user signed the payload
     */
    verifyPayloadSig(userPubKey, signedPayload, userSignature) {
        if (!userPubKey || !signedPayload || !userSignature)
            throw new Error("invalid params");
        const hasServerSigned = this.publicKey.verify(this.getDeterministicObjBuffer(signedPayload.originalPayload), Buffer.from(signedPayload.serverSignature, "base64"));
        console.log({ hasServerSigned });
        if (!hasServerSigned)
            throw new Error("Unauthorized payload submitted");
        const hasUserSigned = PublicKey.fromString(userPubKey).verify(this.getDeterministicObjBuffer(signedPayload), Buffer.from(userSignature, "base64"));
        console.log({ hasUserSigned, userPubKey });
        return hasUserSigned;
    }
}
