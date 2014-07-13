JavaScript Public-Key-Pins (HPKP) calculator
===============
JavaScript Public-Key-Pins (HPKP) calculator - JavaScript library for easy calculation of public key hashes for use in 
[Public Key Pinning Extension for HTTP](https://tools.ietf.org/html/draft-ietf-websec-key-pinning). 
Ready to use HTML form is provided along with the library.

Version 1.0.2

Copyright (C) 2014 Davis Mosenkovs

## Introduction

[Public Key Pinning Extension for HTTP](https://tools.ietf.org/html/draft-ietf-websec-key-pinning) is an internet standards 
draft for instructing HTTP clients to associate servers with specific SSL certificates. Such associations should 
be able to mitigate most [MITM attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) on HTTP over 
SSL/TLS connections.

JavaScript Public-Key-Pins (HPKP) calculator allows easy calculation of Public-Key-Pins HTTP header value for specified 
[X.509](https://en.wikipedia.org/wiki/X.509) certificates or [certificate signing requests](https://en.wikipedia.org/wiki/Certificate_signing_request). 
It can be used as offline HTML/JavaScript form or embedded into web site or other JavaScript application (using API provided by `pkps.js`).

## End-user usage

Before using this program (tool) user should be familiar with [Public Key Pinning Extension for HTTP](https://tools.ietf.org/html/draft-ietf-websec-key-pinning) 
and [HTTP Strict Transport Security (HSTS)](https://tools.ietf.org/html/rfc6797)! Incorrect usage (or malfunction) 
of this program (tool) may lock users out of HTTPS server for time (in seconds) specified in max-age directive of 
HTTP header _Public-Key-Pins_. For use on production systems special precautions (e.g. result verification by 
[other calculators](https://projects.dm.id.lv/Public-Key-Pins_calculator#Other_HPKP_calculators)) are recommended. 

All files contained in this repository can be downloaded (after reading and accepting `LICENSE`) for off-line use of `calculator.html` in web browser. 
File `forge.min.js` can be re-created as specified below (ensuring its integrity), other files are clearly readable and simple enough to be easily audited. 
Additionally all files are signed by OpenPGP key (fingerprint: ED9F BB77 211D 142E AAF8 E9C1 FA00 7FA5 D26E 2AE4) that must be mentioned on https://projects.dm.id.lv/ 
and GnuPG/PGP keyservers. All files (including signatures) and Git commit SHA1 of releases are timestamped on BitCoin network (see 
[project website](https://projects.dm.id.lv/Public-Key-Pins_calculator) for details). 
Download of ZIP file is suggested for signature verification, because Git clients may break signatures by converting newlines in signed files.

It is suggested to use a secure off-line computer for generation of RSA key-pairs, Certificate Signing Requests (CSRs) and Public-Key-Pins.
It is highly recommended to store backup keys (along with CSRs) in **safe and secure** off-line storage. 
It is a good practice to create several backup keys.

It must be taken in mind that during next _max-age_ seconds only keys used in Public-Key-Pins generation can be used on HTTPS address (and optionally 
all subdomains) that sends generated _Public-Key-Pins_ HTTP header. Thus several backup keys are recommended (one required by the standard).
During key change one of backup keys must be used as the new key, a new backup key should/must (one backup key is required by the standard) 
be created, and new Public-Key-Pins value (containing pin of new backup key and **not** containing pin of old key) must be created and set up.

Key generation/storage on server is highly discouraged, because in case of server compromise attacker could gain access to private keys 
of all pinned keys and there would be no way to change key to uncompromised one (without locking users out of server or changing website address).

Also special precautions must be taken when pinning keys to all subdomains (using _includeSubDomains_ directive). 
For example, if company's main website https://example.com sends _Public-Key-Pins_ header containing _includeSubDomains_ directive and 
customer self-service portal https://my.example.com uses key not pinned in _Public-Key-Pins_ header, then users will be locked out of https://my.example.com

## Developer usage

API is documented in main script file `pkps.js`. Usage example can be found in `calculator.html` (it covers main functionality of this library).

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

