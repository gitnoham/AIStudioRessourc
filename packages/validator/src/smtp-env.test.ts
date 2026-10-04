import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { PatternMatch, RawHit } from "@scanner/core";
import {
  collectMailEnv,
  credentialFingerprints,
  formatMailBlock,
  isFullSendGridKey,
  isUsableSmtp,
  isTutorialSmtpHit,
  isStripeSecret,
  parseMailAssignments,
  smtpAccountKey,
  shouldHoldSmtpInvalid,
  smtpApiRoute,
  smtpBrand,
} from "./smtp-env.js";

const blob = [
  "MAIL_HOST=smtp.nossl.sh MAIL_PORT=587 MAIL_USERNAME=apikey MAIL_PASSWORD=SG.mA0aAEv22P44yWic7KL2Pn.p1XvUvGcyXPDCDok-1sWprId MAIL_ENCRYPTION=tls MAIL_FROM_ADDRESS=noreply@acme.example MAIL_FROM_NAME=",
  "MAIL_FROM_NAME=Acme Portal",
].join("\n");

function hit(matches: PatternMatch[], snippet = blob): RawHit {
  return {
    source: "path",
    url: "http://178.62.205.166/.env.old",
    origin: "http://178.62.205.166",
    path: "/.env.old",
    matches,
    contentSnippet: snippet,
  };
}

describe("parseMailAssignments", () => {
  it("splits concatenated MAIL_* tokens onto their own fields", () => {
    const env = parseMailAssignments(blob);
    assert.equal(env.MAIL_HOST, "smtp.nossl.sh");
    assert.equal(env.MAIL_PORT, "587");
    assert.equal(env.MAIL_USERNAME, "apikey");
    assert.equal(env.MAIL_PASSWORD, "SG.mA0aAEv22P44yWic7KL2Pn.p1XvUvGcyXPDCDok-1sWprId");
    assert.equal(env.MAIL_ENCRYPTION, "tls");
    assert.equal(env.MAIL_FROM_ADDRESS, "noreply@acme.example");
    assert.equal(env.MAIL_FROM_NAME, "Acme Portal");
  });

  it("maps MAIL_FROM_ADDR and other from-keys onto MAIL_FROM_ADDRESS", () => {
    const addr = parseMailAssignments(
      "MAIL_HOST=mail.acme.com MAIL_USERNAME=ops@acme.com MAIL_PASSWORD=secret12 MAIL_FROM_ADDR=noreply@acme.com",
    );
    assert.equal(addr.MAIL_FROM_ADDRESS, "noreply@acme.com");
    const emailKey = parseMailAssignments("MAIL_FROM_EMAIL=alerts@shop.io MAIL_HOST=smtp.acme.com");
    assert.equal(emailKey.MAIL_FROM_ADDRESS, "alerts@shop.io");
    const def = parseMailAssignments("DEFAULT_FROM_EMAIL=hello@brand.com MAIL_HOST=smtp.acme.com");
    assert.equal(def.MAIL_FROM_ADDRESS, "hello@brand.com");
    const viaUser = collectMailEnv(
      hit(
        [{ service: "smtp", value: "mail.acme.com", context: "", lineNumber: 1, patternName: "MAIL_HOST" }],
        "MAIL_HOST=mail.acme.com MAIL_USERNAME=ops@acme.com MAIL_PASSWORD=a1b2c3d4e5f6",
      ),
      { service: "smtp", value: "mail.acme.com", context: "", lineNumber: 1, patternName: "MAIL_HOST" },
      [],
    );
    assert.equal(viaUser.MAIL_FROM_ADDRESS, "ops@acme.com");
  });

  it("formats one MAIL_* field per line", () => {
    const text = formatMailBlock(parseMailAssignments(blob));
    assert.equal(
      text,
      [
        "MAIL_HOST=smtp.nossl.sh",
        "MAIL_PORT=587",
        "MAIL_USERNAME=apikey",
        "MAIL_PASSWORD=SG.mA0aAEv22P44yWic7KL2Pn.p1XvUvGcyXPDCDok-1sWprId",
        "MAIL_ENCRYPTION=tls",
        "MAIL_FROM_ADDRESS=noreply@acme.example",
        "MAIL_FROM_NAME=Acme Portal",
      ].join("\n"),
    );
    assert.doesNotMatch(text, /MAIL_HOST=smtp\.nossl\.sh MAIL_PORT/);
  });
});

describe("sendgrid routing", () => {
  it("requires a 69-char SG. key like the old scanner", () => {
    assert.equal(isFullSendGridKey("SG.mA0aAEv22P44yWic7KL2Pn.p1XvUvGcyXPDCDok-1sWprId"), false);
    const full = `SG.${"a".repeat(22)}.${"b".repeat(43)}`;
    assert.equal(full.length, 69);
    assert.equal(isFullSendGridKey(full), true);
  });

  it("routes SMTP with SG. password to SendGrid and drops truncated keys", () => {
    const smtp: PatternMatch = {
      service: "smtp",
      value: "smtp.nossl.sh",
      context: blob,
      lineNumber: 1,
      patternName: "MAIL_HOST",
    };
    const env = collectMailEnv(hit([smtp]), smtp, [smtp]);
    assert.equal(smtpApiRoute(env), "sendgrid");
    assert.deepEqual(credentialFingerprints(hit([smtp])), []);
  });

  it("does not notify SMTP without user/password or with Laravel placeholders", () => {
    const gmail = parseMailAssignments("MAIL_HOST=smtp.gmail.com MAIL_PORT=587 MAIL_ENCRYPTION=tls");
    assert.equal(isUsableSmtp(gmail), false);
    const laravel = parseMailAssignments(
      "MAIL_HOST=mail.mailers.smtp.host MAIL_PORT=587 MAIL_ENCRYPTION=tls MAIL_USERNAME=null MAIL_PASSWORD=null",
    );
    assert.equal(isUsableSmtp(laravel), false);
    const provider = parseMailAssignments(
      "MAIL_HOST=smtp.provider.com MAIL_PORT=587 MAIL_USERNAME=COMMON_ MAIL_PASSWORD=COMMON_MAIL_FROM= MAIL_ENCRYPTION=tls MAIL_FROM_ADDRESS=COMMON_LOG_EMAIL_TO=webmaster@flexauction.com.br",
    );
    assert.equal(provider.MAIL_PASSWORD, "COMMON_");
    assert.equal(isUsableSmtp(provider), false);
    const gluedPass = parseMailAssignments("MAIL_HOST=mail.acme.com MAIL_USERNAME=ops@acme.com MAIL_PASSWORD=COMMON_MAIL_FROM=noreply@acme.com");
    assert.equal(gluedPass.MAIL_PASSWORD, "COMMON_");
    assert.equal(isUsableSmtp(gluedPass), false);
    const gmailDocs = parseMailAssignments(
      "MAIL_HOST=smtp.gmail.com MAIL_PORT=587 MAIL_USERNAME=yourGmailEmail MAIL_PASSWORD=yourAppPasswordGeneratedFromGmail MAIL_ENCRYPTION=tls",
    );
    assert.equal(isUsableSmtp(gmailDocs), false);
    const gmailApp = parseMailAssignments(
      "MAIL_HOST=smtp.gmail.com MAIL_PORT=587 MAIL_USERNAME=ops@acme.com MAIL_PASSWORD=dmyf awlv gwpx yvbt MAIL_ENCRYPTION=tls",
    );
    assert.equal(gmailApp.MAIL_PASSWORD, "dmyf awlv gwpx yvbt");
    assert.equal(isUsableSmtp(gmailApp), true);
    assert.deepEqual(
      credentialFingerprints(
        hit(
          [{ service: "smtp", value: "smtp.gmail.com", context: "MAIL_HOST=smtp.gmail.com", lineNumber: 1, patternName: "MAIL_HOST" }],
          "MAIL_HOST=smtp.gmail.com MAIL_PORT=587 MAIL_ENCRYPTION=tls",
        ),
      ),
      [],
    );
    const tutorialHit: RawHit = {
      source: "recon",
      url: "https://bryceandy.com/posts/send-an-email-in-laravel-5-using-gmail-smtp",
      origin: "https://bryceandy.com",
      path: "/posts/send-an-email-in-laravel-5-using-gmail-smtp",
      matches: [
        {
          service: "smtp",
          value: "smtp.gmail.com",
          context:
            "MAIL_HOST=smtp.gmail.com MAIL_PORT=587 MAIL_USERNAME=yourGmailEmail MAIL_PASSWORD=yourAppPasswordGeneratedFromGmail MAIL_ENCRYPTION=tls",
          lineNumber: 1,
          patternName: "MAIL_HOST",
        },
      ],
      contentSnippet:
        "MAIL_HOST=smtp.gmail.com MAIL_PORT=587 MAIL_USERNAME=yourGmailEmail MAIL_PASSWORD=yourAppPasswordGeneratedFromGmail MAIL_ENCRYPTION=tls",
    };
    assert.equal(isTutorialSmtpHit(tutorialHit), true);
    assert.deepEqual(credentialFingerprints(tutorialHit), []);
    const real = parseMailAssignments(
      "MAIL_HOST=mail.acme-corp.com MAIL_PORT=587 MAIL_USERNAME=ops@acme-corp.com MAIL_PASSWORD=a1b2c3d4e5f6 MAIL_ENCRYPTION=tls",
    );
    assert.equal(isUsableSmtp(real), true);
    const nextZod = parseMailAssignments(
      "MAIL_HOST=n.env.SMTP MAIL_PORT=587 MAIL_USERNAME=o(a.Yj().min(1).optional()),SMTP_PASSWORD:o(a.Yj().min(1).optional()) MAIL_PASSWORD=o(a.Yj().min(1).optional()),SMTP_FROM_EMAIL:o(a.Yj().email().optional()) MAIL_ENCRYPTION=tls",
    );
    assert.equal(isUsableSmtp(nextZod), false);
    const nextEnvRef = parseMailAssignments(
      "MAIL_HOST=r.default.env.SMTP MAIL_PORT=587 MAIL_USERNAME=r.default.env.SMTP_USER MAIL_PASSWORD=r.default.env.SMTP_PASS MAIL_ENCRYPTION=tls",
    );
    assert.equal(isUsableSmtp(nextEnvRef), false);
    const nextZString = parseMailAssignments(
      "MAIL_HOST=e.z.string MAIL_PORT=587 MAIL_USERNAME=e.z.string().optional(),SMTP_PASSWORD:e.z.string().optional() MAIL_PASSWORD=e.z.string().optional(),SMTP_FROM:e.z.string().optional() MAIL_ENCRYPTION=tls",
    );
    assert.equal(isUsableSmtp(nextZString), false);
    const gmailVoid = parseMailAssignments(
      "MAIL_HOST=smtp.gmail.com MAIL_PORT=587 MAIL_USERNAME=(n==null?void MAIL_PASSWORD=(n==null?void MAIL_ENCRYPTION=tls",
    );
    assert.equal(isUsableSmtp(gmailVoid), false);
    const djangoEnv = parseMailAssignments(
      "MAIL_HOST=smtp.gmail.com MAIL_PORT=587 MAIL_USERNAME=os.environ.get('AEF_EMAIL_USER') MAIL_PASSWORD=os.environ.get('AEF_EM MAIL_ENCRYPTION=tls",
    );
    assert.equal(isUsableSmtp(djangoEnv), false);
    const jsFormField = parseMailAssignments(
      "MAIL_HOST=P.target.value MAIL_PORT=587 MAIL_USERNAME=m.email,smtp_pass:m.password,poll_interval:String((parseInt(m.poll_interval_seconds)||60)*1e3)}),P.type=== MAIL_PASSWORD=m.password,poll_interval:String((parseInt(m.poll_interval_seconds)||60)*1e3)}),P.type=== MAIL_ENCRYPTION=tls",
    );
    assert.equal(jsFormField.MAIL_HOST, "P.target.value");
    assert.equal(isUsableSmtp(jsFormField), false);
    const zepto = parseMailAssignments(
      [
        'SMTP_HOST=smtp.zeptomail.com',
        "SMTP_PORT=465",
        'SMTP_USER="emailapikey"',
        'SMTP_PASS="wSsVR611/BT4WK51mmCkIL08kF0AAAj3HUl/3FCl7iT8HvHF/Mc+nkebU1f0GKVLFDZvHTcW8L99mRwH2jYHhtV+yVsGWSiF9mqRe1U4J3x17qnvhDzDWmhZlBOOLIgLxQhsn2hnE8wj+g=="',
        'SMTP_FROM_NAME="Zentric Plataforma"',
        'SMTP_FROM_EMAIL="app@zentric.com.co"',
      ].join("\n"),
    );
    assert.equal(zepto.MAIL_USERNAME, "emailapikey");
    assert.equal(zepto.MAIL_FROM_ADDRESS, "app@zentric.com.co");
    assert.equal(isUsableSmtp(zepto), true);
    assert.equal(smtpBrand(zepto.MAIL_HOST ?? ""), "📧 SMTP ZeptoMail");
  });

  it("splits a vim .env.swp blob so AUTH gets emailapikey not the rest of the file", () => {
    const pass =
      "wSsVR611qRejB6h8yTytLppng4EA1r2HU4r2lel7ySuSrKoccywU3IVgGhFPIYRW8QjMT9bh4zBgF12VciNgtyQsJCCiF9mqRe1U4J3x17qnvhDzKXmhfkRuJJYgKwwxin2hkFMkrg==";
    const swp = [
      "MAIL_HOST=smtp.zeptomail.com",
      "MAIL_PORT=587",
      "MAIL_USERNAME=emailapikey",
      'MAIL_FROM_NAME="${APP_NAME}"',
      "MAIL_FROM_ADDRESS=system@evopolls.com",
      "MAIL_PORT=465",
      "MAIL_ENCRYPTION=SSL",
      "REDIS_HOST=127.0.0.1",
      `MAIL_PASSWORD=${pass}`,
      "MAIL_ENCRYPTION=tls",
    ].join("\x00");
    const env = parseMailAssignments(swp);
    assert.equal(env.MAIL_HOST, "smtp.zeptomail.com");
    assert.equal(env.MAIL_USERNAME, "emailapikey");
    assert.equal(env.MAIL_FROM_ADDRESS, "system@evopolls.com");
    assert.equal(env.MAIL_FROM_NAME, "${APP_NAME}");
    assert.equal(env.MAIL_PASSWORD, pass);
    assert.doesNotMatch(env.MAIL_USERNAME, /REDIS|DB_HOST|MAIL_FROM_NAME/);
    assert.doesNotMatch(env.MAIL_FROM_ADDRESS, /REDIS|MAIL_PORT/);
    assert.equal(isUsableSmtp(env), true);
  });

  it("keeps the full SES SMTP password when a truncated MAIL_HOST context is parsed first", () => {
    const fullPass = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd/EFGH";
    const truncated =
      "MAIL_HOST=email-smtp.eu-west-3.amazonaws.com MAIL_PORT=587 MAIL_USERNAME=AKIATESTEXAMPLE00000 MAIL_PASSWORD=AbCdEfGhIjKlMnOp";
    const passCtx = `MAIL_PASSWORD=${fullPass} MAIL_ENCRYPTION=tls MAIL_FROM_ADDR="info@example.test" MAIL_FROM_NAME="\${APP_NAME}"`;
    const host: PatternMatch = {
      service: "smtp",
      value: "email-smtp.eu-west-3.amazonaws.com",
      context: truncated,
      lineNumber: 1,
      patternName: "MAIL_HOST",
    };
    const pass: PatternMatch = {
      service: "smtp",
      value: fullPass,
      context: passCtx,
      lineNumber: 4,
      patternName: "MAIL_PASSWORD",
    };
    const env = collectMailEnv(hit([host, pass], truncated), host, [pass]);
    assert.equal(env.MAIL_PASSWORD, fullPass);
    assert.equal(env.MAIL_FROM_ADDRESS, "info@example.test");
    assert.equal(env.MAIL_FROM_NAME, "${APP_NAME}");
    assert.equal(
      parseMailAssignments(`${truncated} ${passCtx}`).MAIL_PASSWORD,
      fullPass,
    );
  });

  it("does not fingerprint a Twilio token without Account SID", () => {
    assert.deepEqual(
      credentialFingerprints(
        hit(
          [{ service: "twilio", value: "1679091c5a880faf6fb5e6087eb1b2dc", context: 'authToken="1679091c5a880faf6fb5e6087eb1b2dc"', lineNumber: 1, patternName: "authToken" }],
          'authToken="1679091c5a880faf6fb5e6087eb1b2dc"',
        ),
      ),
      [],
    );
    assert.deepEqual(
      credentialFingerprints(
        hit(
          [{ service: "twilio", value: "c8a7eebcaa43cc55818aa4788e4ae189", context: 'authToken:"c8a7eebcaa43cc55818aa4788e4ae189"', lineNumber: 1, patternName: "authToken" }],
          "/* ts307f.js */ authToken:\"c8a7eebcaa43cc55818aa4788e4ae189\"",
        ),
      ),
      [],
    );
  });

  it("dedups a full SendGrid key once even if SMTP + SG matches coexist", () => {
    const full = `SG.${"a".repeat(22)}.${"b".repeat(43)}`;
    const snippet = `MAIL_HOST=smtp.sendgrid.net MAIL_USERNAME=apikey MAIL_PASSWORD=${full}`;
    const matches: PatternMatch[] = [
      { service: "smtp", value: "smtp.sendgrid.net", context: snippet, lineNumber: 1, patternName: "MAIL_HOST" },
      { service: "sendgrid", value: full, context: snippet, lineNumber: 1, patternName: "sg" },
    ];
    assert.deepEqual(credentialFingerprints(hit(matches, snippet)), [`sg:${full}`]);
  });

  it("requires both AKIA and a real 40-char secret — drops reCAPTCHA pairings", () => {
    const akia = "AKIA3TF4DC3BMTMN4IIP";
    const recaptcha = "6LdMYFoiAAAAABT4bK44uh3FrouPMb9ElGRksUiq";
    const secret = "abcdefghijklmnopqrstuvwxyz0123456789+/AB";
    assert.deepEqual(
      credentialFingerprints(
        hit([
          { service: "aws", value: akia, context: "", lineNumber: 1, patternName: "aws.AKIA" },
          { service: "aws", value: recaptcha, context: "", lineNumber: 2, patternName: "aws.secret.env" },
        ]),
      ),
      [],
    );
    assert.deepEqual(
      credentialFingerprints(
        hit([
          { service: "aws", value: akia, context: "", lineNumber: 1, patternName: "aws.AKIA" },
          { service: "aws", value: secret, context: "", lineNumber: 2, patternName: "aws.secret.env" },
        ]),
      ),
      [`aws:${akia}:${secret}`],
    );
  });

  it("does not notify Stripe publishable keys without a secret", () => {
    const pk = "pk_live_51GbYT4HeTOWDOo0GhA7m8lI8aQ2X39hOtFui4KcJRoy8mgpKqRE29Gx73PT0HIeApmenKItGWu8s68Ywdd5lNEsV00otmDlMiT";
    assert.equal(isStripeSecret(pk), false);
    assert.deepEqual(
      credentialFingerprints(
        hit([{ service: "stripe", value: pk, context: "", lineNumber: 1, patternName: "pk" }]),
      ),
      [],
    );
    const sk = "sk_live_abcdefghijklmnopqrstuvwx";
    assert.equal(isStripeSecret(sk), true);
    assert.deepEqual(
      credentialFingerprints(
        hit([
          { service: "stripe", value: pk, context: "", lineNumber: 1, patternName: "pk" },
          { service: "stripe", value: sk, context: "", lineNumber: 2, patternName: "sk" },
        ]),
      ),
      [`stripe:${sk}`],
    );
  });
});

describe("shouldHoldSmtpInvalid", () => {
  it("defers AUTH-fail while another dump of the same mailbox is pending", () => {
    assert.equal(
      shouldHoldSmtpInvalid({
        alreadyValid: false,
        alreadyNotifiedAccount: false,
        otherPending: 2,
        alreadyDeferred: false,
      }),
      "defer",
    );
    assert.equal(
      smtpAccountKey({ MAIL_HOST: "smtp.zeptomail.com", MAIL_USERNAME: "emailapikey" }),
      "smtp.zeptomail.com:emailapikey",
    );
  });

  it("skips AUTH-fail once the mailbox AUTH'd OK", () => {
    assert.equal(
      shouldHoldSmtpInvalid({
        alreadyValid: true,
        alreadyNotifiedAccount: false,
        otherPending: 1,
        alreadyDeferred: true,
      }),
      "skip",
    );
  });

  it("emits a lone AUTH-fail", () => {
    assert.equal(
      shouldHoldSmtpInvalid({
        alreadyValid: false,
        alreadyNotifiedAccount: false,
        otherPending: 1,
        alreadyDeferred: false,
      }),
      "emit",
    );
  });
});
