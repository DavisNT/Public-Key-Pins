JavaScript Public-Key-Pins calculator
===============
JavaScript Public-Key-Pins calculator - JavaScript library for easy calculation of public key hashes for use in 
Public Key Pinning Extension for HTTP.

Copyright (C) 2014 Davis Mosenkovs

## Introduction

[Public Key Pinning Extension for HTTP](http://tools.ietf.org/html/draft-ietf-websec-key-pinning) is an internet 
draft for instructing HTTP clients to associate servers with specific SSL certificates. Such associations should 
be able to mitigate most [MITM attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) on HTTP over 
SSL/TLS connections.

JavaScript Public-Key-Pins calculator allows easy calculation of Public-Key-Pins HTTP header value for specified 
[X.509](https://en.wikipedia.org/wiki/X.509) certificates or [certificate signing requests](https://en.wikipedia.org/wiki/Certificate_signing_request). 
It can be used as offline HTML/JavaScript form or embeded into web site (using API provided by `pkps.js`).

## Notices

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
http://www.gnu.org/copyleft/gpl.html

This project uses [Forge](https://github.com/digitalbazaar/forge) library which is distributed under the 
terms of [either the BSD License or the GNU General Public License (GPL) Version 2](https://github.com/digitalbazaar/forge/blob/master/LICENSE).
The file `forge.min.js` was generated on CentOS by:

    wget https://github.com/digitalbazaar/forge/archive/0.5.5.zip
    unzip 0.5.5.zip
    cd forge-0.5.5
    npm install
    npm run minify


