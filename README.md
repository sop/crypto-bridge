# CryptoBridge

[![Build Status](https://travis-ci.org/sop/crypto-bridge.svg?branch=master)](https://travis-ci.org/sop/crypto-bridge)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/sop/crypto-bridge/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/sop/crypto-bridge/?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/sop/crypto-bridge/badge.svg?branch=master)](https://coveralls.io/github/sop/crypto-bridge?branch=master)
[![License](https://poser.pugx.org/sop/crypto-bridge/license)](https://github.com/sop/crypto-bridge/blob/master/LICENSE)

A PHP library providing cryptography support for various PKCS applications.

Defines an interface with encrypt / decrypt and signature
signing / verification methods.
Currently only OpenSSL backend is supported.

Key and algorithm information is passed in ASN.1 types implemented in
[`sop/crypto-types`](https://packagist.org/packages/sop/crypto-types) package.

## Requirements

- PHP >=7.2
- openssl
- [sop/crypto-types](https://github.com/sop/crypto-types)

## Installation

This library is available on
[Packagist](https://packagist.org/packages/sop/crypto-bridge).

    composer require sop/crypto-bridge

## License

This project is licensed under the MIT License.
