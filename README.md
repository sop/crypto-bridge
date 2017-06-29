# CryptoBridge

A PHP library providing cryptography support for various PKCS applications.

Defines an interface with encrypt / decrypt and
signature signing / verification methods.
Currently only OpenSSL backend is supported.

Key and algorithm information is passed in ASN.1 types implemented in
[`sop/crypto-types`](https://packagist.org/packages/sop/crypto-types) package.

## Installation

This library is available on
[Packagist](https://packagist.org/packages/sop/crypto-bridge).

    composer require sop/crypto-bridge

## License

This project is licensed under the MIT License.
