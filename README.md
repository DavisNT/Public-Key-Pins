JavaScript Public-Key-Pins calculator
===============

## Introduction

[Public Key Pinning Extension for HTTP](http://tools.ietf.org/html/draft-ietf-websec-key-pinning) is an internet 
draft for instructing HTTP clients to associate servers with specific SSL certificates. Such associations should 
be able to mitigate most [MITM attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack).

JavaScript Public-Key-Pins calculator allows easy calculation of Public-Key-Pins HTTP header value for specified 
[X.509][] certificates or certificate signing requests. It can be used as offline HTML/JavaScript form or embeded 
into web site (using API provided by `pkps.js`).

## Notices

This project uses [Forge](https://github.com/digitalbazaar/forge) library which is distributed under the 
terms of [either the BSD License or the GNU General Public License (GPL) Version 2](https://github.com/digitalbazaar/forge/blob/master/LICENSE).
The file `forge.min.js` was generated on CentOS by:
    wget https://github.com/digitalbazaar/forge/archive/0.5.5.zip
    unzip 0.5.5.zip
    cd forge-0.5.5
    npm install
    npm run minify


