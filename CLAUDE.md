# Working on this fork

Read README.md, SECURITY_REMEDIATION_PLAN.md and IMPLEMENTATION_PROGRESS.md.
Keep code changes under Git. No hosted release/publish workflow, remote AAR,
process plugin, private-key UI/export, full-tunnel route or implicit scalar
coercion may be reintroduced. Ordinary Android import and QR are public-only;
trusted encrypted OS recovery is a separate boundary.

Use LOCAL_BUILD.md. Build tools must not see owner signing keys or credentials.
Run network/security tests only inside the isolated test namespace, using
synthetic keys. Never apply NAS network/permission/firewall changes as part of
local tests. Report actual hardware tests as pending until performed.
