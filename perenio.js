'use strict';

function logging(state) {
    console.log(JSON.stringify(state, null, 2));
}

function currentThreadId(Thread) {
    return Thread.currentThread().getId().toString();
}

function describeOpmode(opmode) {
    if (opmode === 1) {
        return "ENCRYPT";
    } else if (opmode === 2) {
        return "DECRYPT";
    } else if (opmode === 3) {
        return "WRAP";
    } else if (opmode === 4) {
        return "UNWRAP";
    } else {
        return "UNKNOWN";
    }
}

function bytesToString(bytes) {
    if (bytes === null || bytes === undefined) return "<null>";

    let result = "";

    for (let i = 0; i < bytes.length; ++i) {
        // Only convert printable ASCII characters (32-126); otherwise, use a placeholder dot (.)
        let val = bytes[i] & 0xFF;  // Get unsigned byte value

        if (val === 10) {
            result += "\\n";
        } else if (val === 13) {
            result += "\\r";
        } else if (val === 9) {
            result += "\\t";
        } else if (val >= 32 && val <= 126) {
            result += String.fromCharCode(val);
        } else {
            result += '.';
        }
    }

    return result;
}

function bytesToHex(bytes, maxLength, bufferOffset, bufferLength) {
    if (bytes === null || bytes === undefined) return "<null>";

    let result = "";

    const start = (bufferOffset === undefined || bufferLength === undefined) ? 0 : bufferOffset;
    const end = (bufferOffset === undefined || bufferLength === undefined) ? bytes.length : bufferOffset + bufferLength;
    const length = end - start;
    const hasLimit = typeof maxLength === "number" && maxLength > 0; // If maxLength === 0, parse whole byte array
    const len = hasLimit ? Math.min(maxLength, length) : length; // Truncate the log entry if maxLength < bytes.length

    for (let i = start; i < (start + len); i++) {
        let v = bytes[i];
        if (v < 0) v += 256;
        result += ("0" + v.toString(16)).slice(-2);
    }

    if (hasLimit && length > len) result += ` ... [${length - len} more bytes]`;

    return result;
}

Java.perform(function () {
    // Overloaded Java classes
    const Thread = Java.use("java.lang.Thread");
    const simbioEncryption = Java.use("se.simbio.encryption.Encryption");
    const simbioBuilder = Java.use("se.simbio.encryption.Encryption$Builder");
    const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    const Cipher = Java.use("javax.crypto.Cipher");
    const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
    const SecretKeyFactory = Java.use("javax.crypto.SecretKeyFactory");
    const SecretKey = Java.use("java.security.Key");
    const PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec');

    const cipherThreads = new Map();

    try {
        const getInstance = SecretKeyFactory.getInstance.overload(
            "java.lang.String"
        );

        getInstance.implementation = function (algorithm) {
            const ThreadId = currentThreadId(Thread);
            let state = cipherThreads.get(ThreadId);

            const skfGetInstance = {
                secretKeyType: algorithm
            }

            state.SKFGetInstance = skfGetInstance;

            const result = getInstance.call(this, algorithm);

            state.SKFGetInstance.providerName = result.getProvider().getName();
            state.SKFGetInstance.providerVersion = result.getProvider().getVersion();
            state.SKFGetInstance.providerInfo = result.getProvider().getInfo();

            return result;
        };
    } catch (e) {
        console.log("Generic error with SecretKeyFactory.getInstance() method: " + e.message);
    }

    try {
        const generateSecret = SecretKeyFactory.generateSecret.overload(
            "java.security.spec.KeySpec"
        );

        generateSecret.implementation = function (spec) {
            const result = generateSecret.call(this, spec);
            const secretKey = Java.cast(result, SecretKey);
            const ThreadId = currentThreadId(Thread);

            let state = cipherThreads.get(ThreadId);

            const SKFGenerateSecret = {
                algorithm: secretKey.getAlgorithm(),
            };

            state.SKFGenerateSecret = SKFGenerateSecret;

            if (Java.cast(spec, PBEKeySpec)) {
                const pbeKeySpec = Java.cast(spec, PBEKeySpec);
                const PBEKeySpecInfo = {
                    iterationCount: pbeKeySpec.getIterationCount(),
                    keyLength: pbeKeySpec.getKeyLength(),
                    password: Array.from(pbeKeySpec.getPassword()).join(''),
                    salt: bytesToString(pbeKeySpec.getSalt())
                };

                state.SKFGenerateSecret.PBEKeySpecInfo = PBEKeySpecInfo;
            }

            state.SKFGenerateSecret.secretKey = bytesToHex(secretKey.getEncoded());

            return result;
        };
    } catch (e) {
        console.log("Generic error with SecretKeyFactory.generateSecret() method: " + e.message);
    }

    try {
        const getDefault = simbioEncryption.getDefault.overload(
            "java.lang.String",
            "java.lang.String",
            "[B"
        );

        getDefault.implementation = function (key, salt, newArray) {
            const result = getDefault.call(this, key, salt, newArray);
            const ThreadId = currentThreadId(Thread);

            let state = cipherThreads.get(ThreadId);

            if (state === undefined) {
                state = {
                    threadId: ThreadId
                }

                cipherThreads.set(ThreadId, state);
            }

            const getDefaultInfo = {
                key: key,
                salt: salt,
                defaultKey: bytesToHex(newArray)
            };

            state.getDefaultInfo = getDefaultInfo;

            return result;
        };
    } catch (e) {
        console.log("Generic error with Encryption.getDefault() method: " + e.message);
    }

    try {
        const getDefaultBuilder = simbioBuilder.getDefaultBuilder.overload(
            "java.lang.String",
            "java.lang.String",
            "[B"
        );

        getDefaultBuilder.implementation = function (key, salt, newArray) {
            const result = getDefaultBuilder.call(this, key, salt, newArray);
            const ThreadId = currentThreadId(Thread);

            const state = {
                threadId: ThreadId
            }; 

            const builder = {
                algorithm: result.getAlgorithm(),
                modeBase64: result.getBase64Mode(),
                charsetName: result.getCharsetName(),
                digestAlgorithm: result.getDigestAlgorithm(),
                iterationCount: result.getIterationCount(),
                iv: bytesToHex(result.getIv()),
                ivParameterSpec: result.getIvParameterSpec(),
                key: result.getKey(),
                keyAlgorithm: result.getKeyAlgorithm(),
                keyLength: result.getKeyLength(),
                salt: result.getSalt(),
                secretKeyType: result.getSecretKeyType(),
                secureRandom: result.getSecureRandom(),
                secureRandomAlgorithm: result.getSecureRandomAlgorithm()
            };

            state.builder = builder;
            
            cipherThreads.set(ThreadId, state);

            return result;
        };
    } catch (e) {
        console.log("Generic error with Builder.getDefaultBuilder() method: " + e.message);
    }

    try {
        const hashTheKey = simbioEncryption.hashTheKey.overload(
            "java.lang.String"
        );

        hashTheKey.implementation = function (key) {
            const result = hashTheKey.call(this, key);
            const ThreadId = currentThreadId(Thread);

            let state = cipherThreads.get(ThreadId);

            const hashTheKeyInfo = {
                keyPlaintext: key,
                keyHashed: Array.from(result).join('')
            };

            state.hashTheKeyInfo = hashTheKeyInfo;

            return result;
        };
    } catch (e) {
        console.log("Generic error with Encryption.hashTheKey() method: " + e.message);
    }

    try {
        const sksInit = SecretKeySpec.$init.overload(
            "[B",
            "java.lang.String"
        );

        sksInit.implementation = function (key, algorithm) {
            sksInit.call(this, key, algorithm);
            const ThreadId = currentThreadId(Thread);

            let state = cipherThreads.get(ThreadId);

            const SKSInit = {
                key: bytesToHex(key),
                Algorithm: algorithm
            }

            state.SKSInit = SKSInit;
        };
    } catch (e) {
        console.log("Generic error with SecretKeySpec.$init() method: " + e.message);
    }

    try {
        const getSecretKey = simbioEncryption.getSecretKey.overload(
            "[C"
        );

        getSecretKey.implementation = function (hashedKey) {
            const result = getSecretKey.call(this, hashedKey);
            const sks = Java.cast(result, SecretKeySpec);
            const ThreadId = currentThreadId(Thread);

            let state = cipherThreads.get(ThreadId);

            const getSecretKeyInfo = {
                algorithm: sks.getAlgorithm(),
                keyMaterial: bytesToHex(sks.getEncoded())
            }

            state.getSecretKeyInfo = getSecretKeyInfo;

            return result;
        };
    } catch (e) {
        console.log("Generic error with Encryption.getSecretKey() method: " + e.message);
    }

    try {
        const initCipher = Cipher.init.overload(
            "int",
            "java.security.Key",
            "java.security.spec.AlgorithmParameterSpec",
            "java.security.SecureRandom"
        );

        initCipher.implementation = function (opmode, key, parameters, random) {
            const ThreadId = currentThreadId(Thread);

            let parameterValue;
            try {
                const ivSpec = Java.cast(parameters, IvParameterSpec);
                parameterValue = bytesToHex(ivSpec.getIV());
            } catch (e) {
                parameterValue = parameters.toString();
            }

            const keyInfo = {
                keyClass: key.$className,
                keyAlgorithm: key.getAlgorithm(),
                keyFormat: key.getFormat(),
                keyEncoded: bytesToHex(key.getEncoded())
            };

            const parameterInfo = {
                parameterClass: parameters.$className,
                parameterValue: parameterValue
            };

            const secureRandomInfo = {
                secureRandomClass: random.getClass().getName(),
                secureRandomAlgorithm: random.getAlgorithm(),
                secureRandomProvider: random.getProvider().toString()
            };

            const result = initCipher.call(this, opmode, key, parameters, random);

            let state = cipherThreads.get(ThreadId);

            const cryptoInitInfo = {
                opmode: opmode,
                opmodeString: describeOpmode(opmode),
                key: keyInfo,
                parameters: parameterInfo,
                secureRandom: secureRandomInfo
            }

            state.cryptoInitInfo = cryptoInitInfo;

            return result;
        };
    } catch (e) {
        console.log("Generic error with Cipher.init() method: " + e.message);
    }

    try {
        const encrypt = simbioEncryption.encrypt.overload(
            "java.lang.String"
        );

        encrypt.implementation = function (input) {
            const ThreadId = currentThreadId(Thread);
            let state = cipherThreads.get(ThreadId);

            if (state === undefined) {
                state = {
                    threadId: ThreadId
                };
                cipherThreads.set(ThreadId, state);
            }

            state.plaintext = JSON.parse(input);
            
            const result = encrypt.call(this, input);
            state.encrypted = result;

            logging(state);

            return result;
        };
    } catch (e) {
        console.log("Generic error with Encryption.encrypt() method: " + e.message);
    }

    try {
        const decrypt = simbioEncryption.decrypt.overload(
            "java.lang.String"
        );

        decrypt.implementation = function (input) {
            const ThreadId = currentThreadId(Thread);
            let state = cipherThreads.get(ThreadId);

            if (state === undefined) {
                state = {
                    threadId: ThreadId
                };
                cipherThreads.set(ThreadId, state);
            }

            state.encrypted = input;

            const result = decrypt.call(this, input);
            state.decrypted = JSON.parse(result);

            logging(state);

            return result;
        };
    } catch (e) {
        console.log("Generic error with Encryption.decrypt() method: " + e.message);
    }
});