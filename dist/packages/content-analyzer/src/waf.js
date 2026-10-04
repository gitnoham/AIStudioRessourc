const WAF_MARKERS = [
    /attention required/i,
    /cloudflare/i,
    /cf-ray/i,
    /checking your browser/i,
    /just a moment/i,
    /akamai/i,
    /access denied/i,
    /incapsula/i,
    /imperva/i,
    /sucuri/i,
    /request blocked/i,
    /why_captcha/i,
    /_incapsula_resource/i,
    /pardon our interruption/i,
    /bot detection/i,
    /ddos-guard/i,
];
export function isWAFPage(content) {
    if (!content)
        return false;
    const head = content.slice(0, 4000);
    let hits = 0;
    for (const re of WAF_MARKERS) {
        if (re.test(head))
            hits++;
        if (hits >= 2)
            return true;
    }
    if (/<title>\s*(access denied|access to this page has been denied|attention required)/i.test(head)) {
        return true;
    }
    return false;
}
