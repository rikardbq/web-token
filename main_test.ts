// deno-lint-ignore-file no-explicit-any
import { assertEquals, assert } from "@std/assert";
import { AuthToken, exportKeyPair, generateKeyPair } from "./main.ts";

const { publicKeyJwk, privateKeyPkcs8 } = await exportKeyPair(
    await generateKeyPair(),
);
const iat = Date.now();
const exp = iat + 30000;

const encodeToken = async (
    type: "id" | "at" | "rt",
    aid: string,
    sub: string,
    extra: any = {},
) => {
    const token = AuthToken.AuthTokenBuilder()
        .withType(type)
        .withAid(aid)
        .withIss("test_issuer")
        .withSub(sub)
        .withIat(iat)
        .withExp(exp)
        .withExtra(extra);

    return await token.sign(
        (await AuthToken.importKey({
            key: privateKeyPkcs8,
            type: "private",
        }))!,
    );
};

const decodeToken = async (
    b64Token: string,
    type: "id" | "at" | "rt",
    iss: string,
    sub: string,
    ...claims: (string | string[] | number | number[] | undefined)[][]
) => {
    const token = AuthToken.AuthTokenVerifier(b64Token)
        .withType(type)
        .withAid("test")
        .withIss(iss)
        .withIat(iat)
        .withExp(exp)
        .withSub(sub);

    claims.forEach(([k, v]) => {
        token.withClaim(k as string, v);
    });

    return await token.verify(
        (await AuthToken.importKey({
            key: publicKeyJwk,
            type: "public",
        }))!,
    );
};

Deno.test("should do it ", async () => {
    const encoded = await encodeToken("id", "test", "ident", {
        test_claim: "tester",
    });
    const decoded = await decodeToken(encoded, "id", "test_issuer", "ident", [
        "test_claim",
        ["tester", "tester2"],
    ]);

    console.log(decoded);
});

Deno.test(
    "should encode token - produce valid base64 body and footer",
    async () => {
        const expectedTokenJson = JSON.stringify({
            tt: "id",
            aid: "test",
            iss: "test_issuer",
            sub: "ident",
            iat: iat,
            exp: exp,
            test_claim: "tester",
        });
        const token = await encodeToken("id", "test", "ident", {
            test_claim: "tester",
        });
        const splitToken = token.split(".");
        const decoder = new TextDecoder();

        assert(splitToken.length === 2);
        assertEquals(
            decoder.decode(Uint8Array.fromBase64(splitToken[0])),
            expectedTokenJson,
        );
        assert(
            await crypto.subtle.verify(
                "Ed25519",
                (await AuthToken.importKey({
                    key: publicKeyJwk,
                    type: "public",
                }))!,
                Uint8Array.fromBase64(splitToken[1]),
                Uint8Array.fromBase64(splitToken[0]),
            ),
        );
    },
);
