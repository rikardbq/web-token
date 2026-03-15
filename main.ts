// deno-lint-ignore-file no-explicit-any
import { crypto } from "@std/crypto";

type TokenType = "id" | "at" | "rt";

export const generateKeyPair = async () => {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "Ed25519",
            namedCurve: "Ed25519",
        },
        true,
        ["sign", "verify"],
    );

    return keyPair;
};

export const exportKeyPair = async (keyPair: CryptoKeyPair) => {
    const publicKeyJwk = await crypto.subtle.exportKey(
        "jwk",
        keyPair.publicKey,
    );
    const privateKeyPkcs8 = await crypto.subtle.exportKey(
        "pkcs8",
        keyPair.privateKey,
    );

    return { publicKeyJwk, privateKeyPkcs8 };
};

class AuthTokenBuilder {
    private tt: TokenType = "at";
    private aid: string | undefined;
    private iss: string | undefined;
    private sub: string | undefined;
    private iat: number | undefined;
    private exp: number | undefined;
    private extra: any;

    withType(tt: TokenType) {
        this.tt = tt;
        return this;
    }

    withAid(aid: string) {
        this.aid = aid;
        return this;
    }

    withIss(iss: string) {
        this.iss = iss;
        return this;
    }

    withSub(sub: string) {
        this.sub = sub;
        return this;
    }

    withIat(iat: number) {
        this.iat = iat;
        return this;
    }

    withExp(exp: number) {
        this.exp = exp;
        return this;
    }

    withExtra(extra: any) {
        this.extra = extra;
        return this;
    }

    async sign(key: CryptoKey): Promise<string> {
        const token = JSON.stringify({
            tt: this.tt,
            aid: this.aid,
            iss: this.iss,
            sub: this.sub,
            iat: this.iat ?? Date.now(),
            exp: this.exp,
            ...this.extra,
        });
        const encoder = new TextEncoder();
        const encodedToken = encoder.encode(token);
        const signature = await crypto.subtle.sign(
            "Ed25519",
            key,
            encodedToken,
        );
        const body = encodedToken.toBase64();
        const footer = new Uint8Array(signature).toBase64();

        return `${body}.${footer}`;
    }
}

const VerifierErrors = {
    invalid_token: "not a valid token",
    expired: "token expired",
    claim_not_present: (claim: string) =>
        `claim [ ${claim} ] not present in token`,
    mismatched_claims_val: (claim: string, expectedVal: any, actualVal: any) =>
        `claim [ ${claim} ] expected value [ ${expectedVal} ] but was [ ${actualVal} ]`,
};

class AuthTokenVerifier {
    private token: string;
    private tt: TokenType | undefined;
    private aid: string | undefined;
    private iss: string | undefined;
    private sub: string | undefined;
    private iat: number | undefined;
    private exp: number | undefined;
    private claims: Map<string, string | number | undefined> = new Map();

    constructor(base64Token: string) {
        this.token = base64Token;
    }

    withType(tt: TokenType) {
        this.tt = tt;
        return this;
    }

    withAid(aid: string) {
        this.aid = aid;
        return this;
    }

    withIss(iss: string) {
        this.iss = iss;
        return this;
    }

    withSub(sub: string) {
        this.sub = sub;
        return this;
    }

    withIat(iat: number) {
        this.iat = iat;
        return this;
    }

    withExp(exp: number) {
        this.exp = exp;
        return this;
    }

    withClaim(
        claimName: string,
        claimVal: string | number | undefined = undefined,
    ) {
        this.claims.set(claimName, claimVal);
        return this;
    }

    verify(key: CryptoKey) {
        const isValid = AuthToken.isValid(this.token, key);
        if (!isValid) {
            throw new Error(VerifierErrors.invalid_token);
        }

        const token = AuthToken.decode(this.token);
        const filtered = Object.entries(this).filter(
            ([k, v]) => typeof v !== "undefined" && k !== "token",
        );
        filtered.forEach(([k, v]) => {
            if (k === "claims") {
                v.entries().forEach(
                    ([cname, cval]: [string, string | number | undefined]) => {
                        if (typeof cval === "undefined") {
                            if (typeof token[cname] === "undefined") {
                                throw new Error(
                                    VerifierErrors.claim_not_present(cname),
                                );
                            }
                        } else {
                            const tokenCval = token[cname];
                            if (tokenCval !== cval) {
                                throw new Error(
                                    VerifierErrors.mismatched_claims_val(
                                        cname,
                                        cval,
                                        tokenCval,
                                    ),
                                );
                            }
                        }
                    },
                );
            } else {
                const tokenVal = token[k];
                if (token[k] !== v) {
                    throw new Error(
                        VerifierErrors.mismatched_claims_val(k, v, tokenVal),
                    );
                }
            }
        });

        if (Date.now() > token.exp) {
            throw new Error(VerifierErrors.expired);
        }

        return token;
    }
}

export class AuthToken {
    // private static async makeKey(raw: string) {
    //     return await crypto.subtle.importKey(
    //         "raw",
    //         new TextEncoder().encode(raw),
    //         { name: "HMAC", hash: "SHA-256" },
    //         false,
    //         ["sign", "verify"],
    //     );
    // }

    static async importKey({
        key,
        type,
    }: {
        key: JsonWebKey | ArrayBuffer;
        type: "public" | "private";
    }): Promise<CryptoKey | undefined> {
        if (type === "public") {
            return await crypto.subtle.importKey(
                "jwk",
                key as JsonWebKey,
                {
                    name: "Ed25519",
                    namedCurve: "Ed25519",
                },
                true,
                ["verify"],
            );
        }

        if (type === "private") {
            return await crypto.subtle.importKey(
                "pkcs8",
                key as ArrayBuffer,
                {
                    name: "Ed25519",
                    namedCurve: "Ed25519",
                },
                true,
                ["sign"],
            );
        }
    }

    static async isValid(
        base64Token: string,
        key: CryptoKey,
    ): Promise<boolean> {
        const splitToken = base64Token.split(".");
        if (splitToken.length !== 2) {
            return false;
        }
        const body = Uint8Array.fromBase64(splitToken[0]);
        const footer = Uint8Array.fromBase64(splitToken[1]);
        const isValid = await crypto.subtle.verify(
            "Ed25519",
            key,
            body,
            footer,
        );

        return isValid;
    }

    static decode(base64Token: string) {
        const token = JSON.parse(
            new TextDecoder().decode(
                Uint8Array.fromBase64(base64Token.split(".")[0]),
            ),
        );

        return token;
    }

    static AuthTokenVerifier(base64Token: string) {
        return new AuthTokenVerifier(base64Token);
    }

    static AuthTokenBuilder() {
        return new AuthTokenBuilder();
    }
}
