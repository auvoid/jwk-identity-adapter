# DID Key Adapter

`did:key` adapter for `@tanglelabs/ssimon`

## Installation

### 1. npm

```sh
$ npm install @tanglelabs/ssimon @tanglelabs/key-identity-adapter
```

### 2. yarn

```sh
$ yarn add @tanglelabs/ssimon @tanglelabs/key-identity-adapter
```

## Usage

```ts
(async () => {
    const manager = await IdentityManager.build({
        adapter: DidKeyAdapter,
        storage,
    });

    const did = await manager.createDid({
        alias: "asdf",
        store,
    });

    console.log(did.getDid());
})();
```

### Result

```
did:key:z6MkgMrYL9gZDeDq9d4ZRQquiE83cuwN6BUzHDVLNz1CpAmG
```
