#!/usr/bin/env python3
#    Copyright (C) 2019 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License.

# add/remove entries from the dictionaries below to enable/disable
# the reporting of the selected entries - case-sensitive
certificates = {
    "cert_chain_of_trust": {
        "name": "Chain of Trust"
    },
    "cert_expirationStatus": {
        "name": "Expired"
    },
    "cert_signatureAlgorithm": {
        "name": "Weak Hashing Algorithm"
    },
    "cert_trust": {
        "name": "Trust"
    }
}

protocols = [
    "SSLv2",
    "SSLv3",
    "TLS1",
    "TLS1_1",
    "TLS1_2",
    "TLS1_3"
]

vulnerabilities = {
    "heartbleed": {
        "name": "Heartbleed"
    },
    "RC4": {
        "name": "RC4"
    },
    "winshock": {
        "name": "WinShock"
    },
    "CRIME_TLS": {
        "name": "CRIME"
    },
    "POODLE_SSL": {
        "name": "POODLE"
    },
    "DROWN": {
        "name": "DROWN"
    },
    "secure_client_renego": {
        "name": "Secure Client Renegotiation"
    },
    "secure_renego": {
        "name": "Secure Renegotiation"
    },
    "LOGJAM": {
        "name": "Logjam with Export Ciphers"
    },
    "LOGJAM-common_primes": {
        "name": "Logjam Common Primes"
    },
    "ROBOT": {
        "name": "ROBOT"
    },
    "ticketbleed": {
        "name": "Ticketbleed"
    },
    "FREAK": {
        "name": "FREAK"
    },
    "CCS": {
        "name": "ChangeCipherSpec Injection"
    },
    "fallback_SCSV": {
         "name": "Fallback SCSV"
    },
    "BREACH": {
        "name": "BREACH"
    },
    "BEAST": {
        "name": "BEAST"
    },
    "LUCKY13": {
        "name": "Lucky13"
    },
    "SWEET32": {
        "name": "Sweet32"
    },
    "cipherlist_NULL": {
        "name": "Null Ciphers Support"
    },
    "cipherlist_aNULL": {
        "name": "Anonymous Null Ciphers Support"
    },
    "cipherlist_EXPORT": {
        "name": "Export Ciphers Support"
    },
    "cipherlist_LOW": {
        "name": "Low Ciphers Support (e.g. RC4)"
    }, 
    "cipherlist_3DES_IDEA": {
        "name": "Weak Ciphers Support (e.g. 3DES/IDEA)"
    },
    "cipherlist_OBSOLETED": {
        "name": "Obsolete Ciphers Support (e.g. CBC)"
    },     
    "cipherlist_STRONG_NOFS": {
        "name": "Strong NOFS Ciphers"
    },    
    "cipherlist_STRONG_FS": {
        "name": "Strong FS Ciphers"
    },    
}
