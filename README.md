# **krypt-web**

Web crypto library Vivy GmbH is using got encryption/decription on the Browsers. description goes here

## How to use

####Install it

```
npm i krypt-web
```

####Import it into your module

- EHREncryption example

```
import create from 'krypt-web/factory.js'
import { encrypt, decrypt, accessSignature, deriveKey } from 'krypt-web/EHREncryption.js'

async function myEncryptionModule(publicKey, bytesToEncrypt){
    return await encrypt(publicKey, bytesToEncrypt);
}

....

async function myDecryptionModule(privateKey, data){
    return await decrypt(privateKey, data)
}
```

- MedStickerEncryption.js example

```
import create from 'krypt-web/factory.js'
import { encrypt, decrypt, deriveKey } from 'krypt-web/MedStickerEncryption.js'

async function myEncryptionModule(code, pin, bytesToEncrypt){
    const { key, iv } = deriveKey(code, pin);

    const { data } = await encrypt(code, pin, bytesToEncrypt);
    return { encryptedData: data }
}

....

async function myDecryptionModule(code, pin, data){
    const { key, iv, version } = deriveKey(code, pin, 'britney');

    return await decrypt({ key, iv, version }, data);
}
```

todo Add with an example of actual using a function that is being imported.

## Deploy process

We deploy the minifed version of the code in a separate branch to keep our `master` branch clean from code that is not needed.
To deploy use `npm run deploy` this will trigger a build and push the minified files to `minified-source` branch.

## Running the tests

#### Single test tun

```
npm run test
```

#### Watch changes

```
npm run test:watch
```

## Contributing

Please read [CONTRIBUTING.md](https://github.com/UvitaTeam/krypt-web/blob/master/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags).

## Authors

- Christos Paschalidis

See also the list of [contributors](https://github.com/UvitaTeam/krypt-web/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/UvitaTeam/krypt-web/blob/master/LICENSE.md) file for details

## Acknowledgments

- [Lanwen](https://github.com/lanwen) for his guidance and onto the point feeback.

- [Herman Rogers](https://github.com/herman-rogers) for his initial work on the project.
