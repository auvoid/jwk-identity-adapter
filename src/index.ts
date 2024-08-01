import {
    CreateCredentialProps,
    CreateBadgeProps,
    CreateDidProps,
    CredentialsManager,
    DidCreationResult,
    IVerificationResult,
    IdentityAccount,
    IdentityAccountProps,
    IdentityConfig,
    NetworkAdapter,
    NetworkAdapterOptions,
    StorageSpec,
    bytesToString,
} from "@tanglelabs/ssimon";
import EC from "elliptic";
// @ts-ignore
import eckey from "eckey-utils";
import base64url from "base64url";
import {
    JwtCredentialPayload,
    createVerifiableCredentialJwt,
    JwtPresentationPayload,
    createVerifiablePresentationJwt,
    verifyCredential,
} from "did-jwt-vc";
import * as jose from "jose";
import * as didJWT from "did-jwt";
import * as KeyResolver from "key-did-resolver";
import { Resolver } from "did-resolver";
import { Validator } from "jsonschema";
import { OpenBadgeSchema } from "./ob-schema";
import crypto from "crypto";
import { stringToBytes } from "did-jwt/lib/util";

const ec = new EC.ec("p256");
export class DidJwkAdapter implements NetworkAdapter {
    store: StorageSpec<any, any>;
    private constructor() {}

    /**
     * Create a new instance of network adapter
     *
     * @param {NetworkAdapterOptions} options
     * @returns {Promise<DidJwkAdapter>}
     */

    public static async build(
        options: NetworkAdapterOptions
    ): Promise<DidJwkAdapter> {
        const adapter = new DidJwkAdapter();
        adapter.store = options.driver;
        return adapter;
    }

    getMethodIdentifier() {
        return "jwk";
    }

    /**
     * Create a new DID and store in the store defined with the adapter
     *
     * @param {CreateDidProps} props
     * @returns {Promise<DidCreationResult>}
     */
    async createDid<T extends StorageSpec<Record<string, any>, any>>(
        props: CreateDidProps<T>
    ): Promise<DidCreationResult> {
        const { seed, alias, store } = props;

        const keyPair = ec.genKeyPair();

        const seedBuffer = keyPair.getPrivate().toBuffer();
        const generatedSeed = bytesToString(seedBuffer);

        const identity = await DidJwkAccount.build({
            seed: seed ?? generatedSeed,
            isOld: !!seed,
            alias,
            store,
        });

        return { identity, seed: seed ?? generatedSeed };
    }

    /**
     * Deserialize a DID and return the DID config result
     *
     * @param {IdentityConfig} config
     * @param {T} store
     * @returns {Promise<DidCreationResult>}
     */
    async deserializeDid<T extends StorageSpec<Record<string, any>, any>>(
        config: IdentityConfig,
        store: T
    ): Promise<DidCreationResult> {
        const identity = await DidJwkAccount.build({
            seed: config.seed as string,
            isOld: true,
            alias: config.alias,
            store: store,
        });
        return { identity, seed: config.seed as string };
    }
}

export class DidJwkAccount implements IdentityAccount {
    credentials: CredentialsManager<StorageSpec<Record<string, any>, any>>;
    keyPair: EC.ec.KeyPair;
    document: Record<string, any>;

    /**
     * Create a new DID Account class
     *
     * @param {IdentityAccountProps} props
     * @returns {Promise<DidJwkAccount>}
     */
    public static async build(
        props: IdentityAccountProps<any>
    ): Promise<DidJwkAccount> {
        const { seed, store } = props;

        const keyPair = ec.keyFromPrivate(seed);
        const pkcs8 = await this.getPKCS8FromKeyPair(keyPair);
        console.log("seed", seed);

        const joseJwk = await jose.importPKCS8(pkcs8, "ES256");
        const jwk = await jose.exportJWK(joseJwk);

        const account = new DidJwkAccount();
        account.document = await this.buildDidDocumentFromJWK(jwk);

        const credentials = await DidJwkCredentialsManager.build(
            store,
            account
        );
        account.keyPair = keyPair;

        account.credentials = credentials;

        return account;
    }

    private static async buildDidDocumentFromJWK(jwk: jose.JWK) {
        delete jwk.d;

        const jwkString = JSON.stringify(jwk);
        const jwkBase64Url = base64url(jwkString);
        console.log(jwkBase64Url);
        const didUrl = "did:jwk:" + jwkBase64Url;
        const document = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
            ],
            id: didUrl,
            verificationMethod: [
                {
                    id: `${didUrl}#0`,
                    type: "JsonWebKey2020",
                    controller: didUrl,
                    publicKeyJwk: jwk,
                },
            ],
            assertionMethod: [`${didUrl}#0"`],
            authentication: [`${didUrl}#0"`],
            capabilityInvocation: [`${didUrl}#0"`],
            capabilityDelegation: [`${didUrl}#0"`],
            keyAgreement: [`${didUrl}#0"`],
        };

        return document;
    }

    private static async getPKCS8FromKeyPair(keyPair: EC.ec.KeyPair) {
        const curveName = "prime256v1";
        const pems = eckey.generatePem({
            curveName,
            privateKey: keyPair.getPrivate().toBuffer(),
        });
        const sec1Pem = pems.privateKey;
        const pkcs8PemFromSec1 = crypto
            .createPrivateKey({ key: sec1Pem, format: "pem", type: "sec1" })
            .export({ type: "pkcs8", format: "pem" })
            .toString();

        return pkcs8PemFromSec1;
    }

    /**
     * Get back the did string
     *
     * @returns {string}
     */
    getDid(): string {
        return this.document.id;
    }

    /**
     * Get back the did document
     *
     * @returns {Record<string, any>}
     */
    async getDocument(): Promise<Record<string, any>> {
        return this.document;
    }

    /**
     * Create a verifiable presentation
     *
     * @param {string[]} credentials
     * @returns {Promise<{ vpPayload: Record<string, any>; presentationJwt: string }>}
     */
    async createPresentation(
        credentials: string[]
    ): Promise<{ vpPayload: Record<string, any>; presentationJwt: string }> {
        const signer = didJWT.ES256Signer(this.keyPair.getPrivate().toBuffer());
        const vpIssuer = {
            did: this.getDid(),
            signer,
            alg: "ES256",
            kid: this.getDid() + "#0",
        };

        const vpPayload: JwtPresentationPayload = {
            vp: {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                type: ["VerifiablePresentation"],
                verifiableCredential: credentials,
            },
        };

        const presentationJwt = await createVerifiablePresentationJwt(
            vpPayload,
            vpIssuer
        );

        return { vpPayload, presentationJwt };
    }
}

export class DidJwkCredentialsManager<
    T extends StorageSpec<Record<string, any>, any>
> implements CredentialsManager<T>
{
    store: T;
    account: DidJwkAccount;

    private constructor() {}

    /**
     * Create a new instance o DidJwkCredentialsManager
     *
     * @param {T} store
     * @param {DidJwkAccount} account
     * @returns
     */
    public static async build<T extends StorageSpec<Record<string, any>, any>>(
        store: T,
        account: DidJwkAccount
    ) {
        const credentialsManager = new DidJwkCredentialsManager();
        credentialsManager.store = store;
        credentialsManager.account = account;
        return credentialsManager;
    }

    /**
     * Check if the credential is valid, sans DVID Proof
     *
     * @param {{ cred: string }} credential
     * @returns {Promise<boolean>}
     */
    async isCredentialValid(
        credential: Record<string, unknown>
    ): Promise<boolean> {
        const result = await this.verify(credential);
        return result.vc;
    }

    /**
     * Check if the credential is valid
     *
     * @param {{ cred: string }} credential
     * @returns {Promise<IVerificationResult>}
     */
    async verify(
        credential: Record<string, unknown>
    ): Promise<IVerificationResult> {
        const { cred } = credential;
        const keyDIDResolver = KeyResolver.getResolver();
        const didResolver = new Resolver(keyDIDResolver);
        await verifyCredential(cred as string, didResolver);
        return { vc: true, dvid: true };
    }

    /**
     * Create a new credential to issue
     *
     * @param {CreateCredentialProps} options
     * @returns {Promise<Record<string, any>>}
     */
    async create(options: CreateCredentialProps): Promise<Record<string, any>> {
        const { id, recipientDid, body, type } = options;

        const signer = didJWT.ES256Signer(
            this.account.keyPair.getPrivate().toBuffer()
        );
        const vcIssuer = {
            did: this.account.getDid(),
            signer,
            alg: "ES256",
            kid: this.account.getDid() + "#0",
        };
        const types = Array.isArray(type) ? [...type] : [type];

        const credential: JwtCredentialPayload = {
            sub: recipientDid,
            nbf: Math.floor(Date.now() / 1000),
            id,
            vc: {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                type: ["VerifiableCredential", ...types],
                id,
                credentialSubject: {
                    ...body,
                },
            },
        };
        if (options.expiryDate) credential.exp = options.expiryDate;

        const jwt = await createVerifiableCredentialJwt(credential, vcIssuer);

        return { cred: jwt };
    }

    async createBadge(options: CreateBadgeProps) {
        const {
            id,
            recipientDid,
            body,
            type,
            image,
            issuerName,
            criteria,
            description,
        } = options;

        const signer = didJWT.ES256Signer(
            this.account.keyPair.getPrivate().toBuffer()
        );
        const didId =
            this.account.getDid() +
            "#" +
            this.account.getDid().split("did:key:")[1];
        const vcIssuer = {
            did: didId,
            signer,
            alg: "ES256",
            kid: this.account.getDid() + "#0",
        };
        const types = Array.isArray(type) ? [...type] : [type];
        const credential: JwtCredentialPayload = {
            sub: recipientDid,
            nbf: Math.floor(Date.now() / 1000),
            id,
            vc: {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json",
                ],
                type: ["VerifiableCredential", "OpenBadgeCredential"],
                id,
                name: type,
                issuer: {
                    id: new URL("/", id).toString(),
                    type: ["Profile"],
                    name: issuerName,
                },
                issuanceDate: new Date(Date.now()).toISOString(),
                credentialSubject: {
                    type: ["AchievementSubject"],
                    achievement: {
                        id: id,
                        type: "",
                        criteria: {
                            narrative: criteria,
                        },
                        name: type,
                        description: description,
                        image: {
                            id: image,
                            type: "Image",
                        },
                        ...body,
                    },
                },
            },
        };

        if (options.expiryDate) credential.exp = options.expiryDate;

        const validator = new Validator();
        const result = validator.validate(credential.vc, OpenBadgeSchema);
        if (result.errors.length > 0)
            throw new Error("Schema Validation Failed");
        const jwt = await createVerifiableCredentialJwt(credential, vcIssuer);

        return { cred: jwt };
    }

    revoke(keyIndex: number): Promise<void> {
        throw new Error("Method not implemented.");
    }
}
