from pathlib import Path

schedule = Path("pam_schedule_totp_override/schedule.c")
text = schedule.read_text(encoding="utf-8")
old = """            for (size_t i = 0U; i < out->rule_count; i++) {
                if (strcmp(out->rules[i].user, rule.user) == 0) {
                    pso_secure_memzero(&rule, sizeof(rule));
                    goto cleanup;
                }
            }
"""
new = """            for (size_t i = 0U; i < out->rule_count; i++) {
                if (strcmp(out->rules[i].user, rule.user) == 0 ||
                    strcmp(out->rules[i].secret_name, rule.secret_name) == 0) {
                    pso_secure_memzero(&rule, sizeof(rule));
                    goto cleanup;
                }
            }
"""
if old not in text:
    if new not in text:
        raise SystemExit("config uniqueness block not found")
else:
    schedule.write_text(text.replace(old, new, 1), encoding="utf-8")

test = Path("pam_schedule_totp_override/tests/test_schedule.c")
test_text = test.read_text(encoding="utf-8")
anchor = """    {
        static const char invalid_day[] =
"""
addition = """    {
        static const char duplicate_secret[] =
            "version=1\\ndefault=deny\\n"
            "user=A;days=Mo;time=0800-1400;secret=shared.secret\\n"
            "user=B;days=Tu;time=0800-1400;secret=shared.secret\\n";
        check(pso_parse_config(duplicate_secret, sizeof(duplicate_secret) - 1U,
                               &config) != 0,
              "secret reuse across accounts rejected");
    }
"""
if addition not in test_text:
    if anchor not in test_text:
        raise SystemExit("test insertion anchor not found")
    test.write_text(test_text.replace(anchor, addition + anchor, 1),
                    encoding="utf-8")
