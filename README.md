# Java-based Time-based One Time Password (TOTP) generator

## Installation

The compiled libraries are deployed to Maven Central.

With maven:

```xml
<dependency>
    <groupId>io.github.kamilszewc</groupId>
    <artifactId>totp</artifactId>
    <version>6.1</version>
</dependency>
```

With gradle:

```groovy
implementation 'io.github.kamilszewc:totp:6.1'
```

It requires Java 8.

## Basic usage

Getting totp code (defult settings):
```java
String code = Totp.getCode(secret);
```

Getting the ramaining validity time of totp code (default settings):
```java
long remainingValidityTime = Totp.getRemainingValidityTime();
```

There is also an option to generate custom codes:
```java
String code = Totp.getCode(
                    secret,         // Secret password
                    epoch,          // Epoch (default 0)
                    timeStep,       // Length of password validity in seconds (default 30)
                    timeStamp,      // Time stamp (Unix time) (default now)
                    codeLength,     // Length of returned code (between 1 and 9, default 6)
                    hashFunction);  // Hash function (default sha1)
```
