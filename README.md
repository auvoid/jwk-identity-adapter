# DID JWK Adapter

`did:jwk` adapter for `@tanglelabs/ssimon`

## Installation

### 1. npm

```sh
$ npm install @tanglelabs/ssimon @tanglelabs/jwk-identity-adapter
```

### 2. yarn

```sh
$ yarn add @tanglelabs/ssimon @tanglelabs/jwk-identity-adapter
```

## Usage

```ts
(async () => {
    const manager = await IdentityManager.build({
        adapters: [DidJwkAdapter],
        storage,
    });

    const did = await manager.createDid({
        alias: "asdf",
        store,
        method: "jwk",
    });

    console.log(did.getDid());
})();
```

### Result

```
did:jwk:eyJrdHkiOiJFQyIsIngiOiJ2NWItdkVHVDdEbmNRbDBDS21xSm1rWDZCNVhDU3ZfbWt4RjVzQV9VWko4IiwieSI6IktZLTdJOGI5SXV5c0Ixb0I0cWRtQkN1bzlUWHo4M0QzUUxTcFZJTG5nMlUiLCJjcnYiOiJQLTI1NiJ9
```
