"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require("fs");
function parseHeaders(raw) {
    const map = new Map();
    raw
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.length > 0)
        .forEach((line) => {
        const idx = line.indexOf(":");
        if (idx === -1)
            return;
        const key = line.slice(0, idx).trim().toLowerCase();
        const value = line.slice(idx + 1).trim();
        map.set(key, value);
    });
    return map;
}
function flagHeader(headers, key, missingNote, check) {
    const value = headers.get(key);
    if (!value) {
        return { key, status: "missing", note: missingNote };
    }
    if (!check) {
        return { key, status: "ok", note: value };
    }
    return check(value);
}
function evaluate(headers) {
    const findings = [];
    findings.push(flagHeader(headers, "strict-transport-security", "Enable HSTS with a long max-age (6+ months).", (value) => {
        const match = /max-age=(\d+)/i.exec(value);
        const maxAge = match ? Number(match[1]) : 0;
        if (maxAge < 15552000) {
            return {
                key: "strict-transport-security",
                status: "warn",
                note: `max-age too low (${maxAge}). Recommended >= 15552000.`,
            };
        }
        return { key: "strict-transport-security", status: "ok", note: value };
    }));
    findings.push(flagHeader(headers, "content-security-policy", "Add a CSP to reduce XSS risk.", (value) => {
        const issues = [];
        if (value.includes("unsafe-inline"))
            issues.push("unsafe-inline");
        if (value.includes("unsafe-eval"))
            issues.push("unsafe-eval");
        if (value.includes("*"))
            issues.push("wildcard source");
        if (issues.length > 0) {
            return {
                key: "content-security-policy",
                status: "warn",
                note: `Risky directives: ${issues.join(", ")}.`,
            };
        }
        return { key: "content-security-policy", status: "ok", note: value };
    }));
    findings.push(flagHeader(headers, "x-frame-options", "Set X-Frame-Options to DENY or SAMEORIGIN.", (value) => {
        const normalized = value.toUpperCase();
        if (normalized !== "DENY" && normalized !== "SAMEORIGIN") {
            return {
                key: "x-frame-options",
                status: "warn",
                note: `Unexpected value: ${value}`,
            };
        }
        return { key: "x-frame-options", status: "ok", note: value };
    }));
    findings.push(flagHeader(headers, "x-content-type-options", "Add X-Content-Type-Options: nosniff.", (value) => {
        if (value.toLowerCase() !== "nosniff") {
            return {
                key: "x-content-type-options",
                status: "warn",
                note: `Unexpected value: ${value}`,
            };
        }
        return { key: "x-content-type-options", status: "ok", note: value };
    }));
    findings.push(flagHeader(headers, "referrer-policy", "Set Referrer-Policy to reduce referer leakage.", (value) => ({ key: "referrer-policy", status: "ok", note: value })));
    findings.push(flagHeader(headers, "permissions-policy", "Add Permissions-Policy to restrict browser features.", (value) => ({ key: "permissions-policy", status: "ok", note: value })));
    [
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "cross-origin-embedder-policy",
    ].forEach((key) => {
        findings.push(flagHeader(headers, key, "Consider setting this COOP/COEP/CORP header."));
    });
    return findings;
}
function parseArgs(argv) {
    const inputIdx = argv.indexOf("--input");
    if (inputIdx !== -1 && argv[inputIdx + 1]) {
        return { input: argv[inputIdx + 1] };
    }
    return { input: "headers.txt" };
}
function main() {
    const args = parseArgs(process.argv.slice(2));
    const raw = fs.readFileSync(args.input, "utf-8");
    const headers = parseHeaders(raw);
    const findings = evaluate(headers);
    const summary = { ok: 0, warn: 0, missing: 0 };
    for (const finding of findings) {
        summary[finding.status] += 1;
    }
    console.log(`Headers analyzed: ${headers.size}`);
    console.log(`Findings: ok ${summary.ok}, warn ${summary.warn}, missing ${summary.missing}\n`);
    for (const finding of findings) {
        const label = finding.status.toUpperCase();
        console.log(`[${label}] ${finding.key}`);
        console.log(`  ${finding.note}`);
    }
}
main();
