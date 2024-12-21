import {
  CreateDidProps,
  CredentialsManager,
  DidCreationResult,
  IdentityAccount,
  IdentityAccountProps,
  IdentityConfig,
  NetworkAdapter,
  NetworkAdapterOptions,
  StorageSpec,
  bytesToString,
  DidSigner,
} from "@tanglelabs/ssimon";
import EC from "elliptic";
// @ts-ignore
import eckey from "eckey-utils";
import base64url from "base64url";
import crypto from "crypto";
import * as jose from "jose";
import * as didJWT from "did-jwt";
import { Resolver } from "did-resolver";

const ec = new EC.ec("p256");
export class DidJwkAdapter implements NetworkAdapter {
  store: StorageSpec<any, any>;
  resolver: Resolver;

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
    adapter.resolver = options.resolver;
    return adapter;
  }

  /**
   * Create a new DID Account class
   *
   * @param {IdentityAccountProps} props
   * @returns {Promise<DidJwkAccount>}
   */
  public async buildIdentityAccount(
    props: IdentityAccountProps<any>
  ): Promise<IdentityAccount> {
    const { seed, store } = props;

    const keyPair = ec.keyFromPrivate(seed);
    const pkcs8 = await this.getPKCS8FromKeyPair(keyPair);

    const joseJwk = await jose.importPKCS8(pkcs8, "ES256");
    const jwk = await jose.exportJWK(joseJwk);

    const account = new IdentityAccount();
    account.document = await this.buildDidDocumentFromJWK(jwk);
    const signer = didJWT.ES256Signer(
      keyPair.getPrivate().toBuffer() as unknown as Uint8Array<ArrayBufferLike>
    );

    const didSigner: DidSigner = {
      did: account.document.id,
      kid: `${account.document.id}#0` as `did:${string}`,
      signer,
      alg: "ES256",
    };

    const credentials = CredentialsManager.build(
      store,
      didSigner,
      this.resolver
    );

    account.credentials = credentials;
    account.signer = didSigner;

    return account;
  }

  private async buildDidDocumentFromJWK(jwk: jose.JWK) {
    delete jwk.d;

    const jwkString = JSON.stringify(jwk);
    const jwkBase64Url = base64url(jwkString);
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

  private async getPKCS8FromKeyPair(keyPair: EC.ec.KeyPair) {
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

  getMethodIdentifier() {
    return "jwk";
  }

  /**
   * Create a new DID and store in the store defined with the adapter
   *
   * @param {CreateDidProps} props
   * @returns {Promise<DidCreationResult>}
   */
  async createDid(props: CreateDidProps): Promise<DidCreationResult> {
    const { seed, alias, store } = props;

    const keyPair = ec.genKeyPair();

    const seedBuffer = keyPair.getPrivate().toBuffer();
    const generatedSeed = bytesToString(seedBuffer as unknown as Uint8Array);

    const identity = await this.buildIdentityAccount({
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
    const identity = await this.buildIdentityAccount({
      seed: config.seed as string,
      isOld: true,
      alias: config.alias,
      store: store,
    });
    return { identity, seed: config.seed as string };
  }
}
