# spps-jbc

Simple Password Protection Solution for Java with Bouncy Castle

---

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://img.shields.io/travis/com/elomagic/spps-jbc)](https://travis-ci.com/github/elomagic/spps-jbc)
[![Coverage Status](https://coveralls.io/repos/github/elomagic/spps-jbc/badge.svg)](https://coveralls.io/github/elomagic/spps-jbc)
[![GitHub issues](https://img.shields.io/github/issues-raw/elomagic/spps-jbc)](https://github.com/elomagic/spps-jbc/issues)

The SPPS is a lightweight solution to protect / hide your password or anything else from your code.

## Features

* AES 256 CGM en-/decryption
* Cross programming languages support ([Java](https://github.com/elomagic/spps-jshiro), [Python](https://github.com/elomagic/spps-py), [Node.js](https://github.com/elomagic/spps-npm))

## Concept

This solution helps one to accidentally publish secrets unintentionally by splitting the secret into an encrypted part and a private key.
The private key is kept separately from the rest, in a secure location for the authorized user only.

The private key is randomized for each user on each system and is therefore unique. This means that if someone has the encrypted secret,
they can only read it if they also have the private key. You can check this by trying to decrypt the encrypted secret with another user or another system. You will not succeed.

A symmetrical encryption based on the AES-GCM 256 method is used. See also https://en.wikipedia.org/wiki/Galois/Counter_Mode

By default, the private key is stored in a file "/.sbbs/masterkey" of the user home folder.

Keep in mind that anyone who has access to the user home or relocation folder also has access to the master key !!!!

## Example

```java
import de.elomagic.spps.bc.SimpleCrypt;

class Sample {

    void testEncryptDecryptWithString() throws Exception {
        String value = "My Secret";

        String encrypted = SimpleCrypt.encrypt(value);

        System.out.println("My encrypted secret is " + encryptedSecret);

        String decrypted = SimpleCrypt.decryptToString(encrypted);

        System.out.println("...and my secret is " + decrypted);
    }
    
}
```

## How to create a master key

### Create a master in your home folder:

Enter following command in your terminal:

```bash  
java -jar spps-jbs-1.0.0.jar -CreateMasterKey
```

The settings file ```'~/.spps/masterkey'``` in your home folder will look like:

```properties
key=5C/Yi6+hbgRwIBhXT9PQGi83EVw2Oe6uttRSl4/kLzc=
relocation=
```

### Alternative, create a master key on a removable device:

Enter following command in your terminal:

```bash
java -jar spps-jbs-1.0.0.jar -CreateMasterKey -Relocation /Volumes/usb-stick
```

The settings file ```'~/.spps/masterkey'``` in your home folder will look like:

```properties
key=
relocation=/Volumes/usb-stick
```

...and in the relocation folder look like:

```properties
key=5C/Yi6+hbgRwIBhXT9PQGi83EVw2Oe6uttRSl4/kLzc=
relocation=
```

## How to create an encrypted password

Enter following command in your terminal:

```bash 
java -jar spps-jbs-1.0.0.jar -Secret YourSecret 
```

Output should look like:
```
{MLaFzwpNyKJbJSCg4xY5g70WDAKnOhVe3oaaDAGWtH4KXR4=}
```

##
