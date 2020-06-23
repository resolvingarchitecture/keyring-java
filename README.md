# Key Ring Service
Manages keys for the bus and its user. 
Multiple users are not supported for identities (this is client-to-client software not server based).
Creates, persists, and deletes identity keys (OpenPGP). 
Encrypts (AES) them for persisting to drives - TODO.
Provides identity keys for DID Service.
Storage currently local hard drive but slated to support external usb drives.

## Policies
 
### Confidentiality
No certificate authorities will be used in 1M5 as it would require divulging an identity to an untrusted 3rd party.
 
### Availability
Cipher flexibility is important as 1M5 is a platform for integrating service providers and sensors.
As of 0.5.2, it is only supporting:

* RSA 2048, 3072, 4096 for asymmetric identities
* AES 128, 192, 256 for secret symmetric keys
* SHA1, SHA256, SHA512 for signatures and integrity

### Implementations

#### OpenPGP Key Ring

#### Smart PGP Key Ring

#### Shamir Secret Sharing
https://en.wikipedia.org/wiki/Shamir's_Secret_Sharing

##### Purism
https://docs.puri.sm/Librem_Key.html

## TODO
* Key Revocation
* Support Android 8 Password Manager