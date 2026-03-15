// deno-lint-ignore-file no-explicit-any
import { assertEquals } from "@std/assert";
import { AuthToken, exportKeyPair, generateKeyPair } from "./main.ts";
// import { add } from "./main.ts";

// Deno.test(function addTest() {
//   assertEquals(add(2, 3), 5);
// });

const keyPair = await generateKeyPair();
const { publicKeyJwk, privateKeyPkcs8 } = await exportKeyPair(keyPair);
export const encodeToken = async (
    type: "id" | "at" | "rt",
    aid: string,
    sub: string,
    extra: any = {},
) => {
    const exp = () => {
        const now = Date.now();
        if (type === "at") return now + 1800 * 1000;
        if (type === "rt") return now + 3600 * 1000 * 24 * 30;

        return now + 30 * 1000;
    };

    const token = AuthToken.AuthTokenBuilder()
        .withType(type)
        .withAid(aid)
        .withIss("issuer")
        .withSub(sub)
        .withExp(exp())
        .withExtra(extra);

    return await token.sign(
        (await AuthToken.importKey({
            key: privateKeyPkcs8,
            type: "private",
        }))!,
    );
};

export const decodeToken = async (
    b64Token: string,
    type: "id" | "at" | "rt",
    sub: string,
    ...claims: (string | number | undefined)[][]
) => {
    const token = AuthToken.AuthTokenVerifier(b64Token)
        .withType(type)
        .withAid("test")
        .withIss("issuer")
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

const token = await encodeToken("id", "test", "ident", {
    something: "some",
    something2: "some2",
    tee: "tester",
});

const verify = await decodeToken(token, "id", "ident", ["something"], ["something2", "some2"], ["tee", "tester"]);

console.log(verify);
