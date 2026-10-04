/** AWS secret must be 40-char base64 — not reCAPTCHA / Stripe / encoded jokes. */
export function isValidAwsSecretKey(s) {
    const v = s.trim();
    if (v.length !== 40)
        return false;
    if (/[\s?!,;:"'()[\]{}<>._~`@#$%^&*|\\-]/.test(v))
        return false;
    if (!/^[A-Za-z0-9/+=]+$/.test(v))
        return false;
    if (/EXAMPLE/i.test(v))
        return false;
    if (/^6[LlPpIiQqFf]/.test(v))
        return false;
    if (/AAAAA/i.test(v))
        return false;
    if (/^(AKIA|ASIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)/i.test(v))
        return false;
    if (/^(pk_|sk_|rk_|SG\.|ghp_|gho_|github_pat)/.test(v))
        return false;
    if (new Set(v.replace(/=+$/, "")).size < 10)
        return false;
    if (looksLikeEncodedJoke(v))
        return false;
    return true;
}
function looksLikeEncodedJoke(v) {
    let text;
    try {
        text = Buffer.from(v, "base64").toString("utf8");
    }
    catch {
        return false;
    }
    if (!text || text.includes("\uFFFD"))
        return false;
    if (/this_is_fake|fake[_-]|example|dummy|placeholder|donkey|not_a_real|sample_key|your_secret|absolute/i.test(text)) {
        return true;
    }
    const letters = (text.match(/[A-Za-z]/g) ?? []).length;
    const words = (text.match(/[A-Za-z]{4,}/g) ?? []).length;
    return letters / text.length >= 0.7 && words >= 3;
}
export function isAwsAccessKey(s) {
    return /^A[KS]IA[A-Z0-9]{16}$/.test(s.trim());
}
export function isVendorSecretPath(path) {
    return /node_modules|bower_components/i.test(path ?? "");
}
