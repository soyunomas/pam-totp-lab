#include "../schedule.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *name)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

static struct tm wall_time(int wday, int hour, int minute)
{
    struct tm value;
    memset(&value, 0, sizeof(value));
    value.tm_wday = wday;
    value.tm_hour = hour;
    value.tm_min = minute;
    return value;
}

int main(void)
{
    static const char valid[] =
        "version=1\n"
        "default=ignore\n"
        "user=A;days=Mo-Fr;time=0800-1400;secret=A.secret\n"
        "user=B;days=Mo-Fr;time=1400-2000;secret=B.secret\n"
        "user=C;days=Mo-Fr;time=2000-0200;secret=C.secret\n";
    struct pso_config config;
    const struct pso_rule *rule = NULL;
    struct tm value;

    check(pso_parse_config(valid, sizeof(valid) - 1U, &config) == 0,
          "valid config parses");
    check(config.rule_count == 3U && config.default_policy == PSO_DEFAULT_IGNORE,
          "config metadata");

    value = wall_time(1, 8, 0);
    check(pso_evaluate_schedule(&config, "A", &value, &rule) ==
              PSO_SCHEDULE_INSIDE && rule != NULL &&
              strcmp(rule->secret_name, "A.secret") == 0,
          "A starts Monday morning");
    value = wall_time(1, 13, 59);
    check(pso_evaluate_schedule(&config, "A", &value, NULL) ==
              PSO_SCHEDULE_INSIDE,
          "A end minus one minute");
    value = wall_time(1, 14, 0);
    check(pso_evaluate_schedule(&config, "A", &value, NULL) ==
              PSO_SCHEDULE_OUTSIDE,
          "end is exclusive");
    value = wall_time(1, 9, 0);
    check(pso_evaluate_schedule(&config, "B", &value, NULL) ==
              PSO_SCHEDULE_OUTSIDE,
          "B morning requires override");
    value = wall_time(1, 23, 0);
    check(pso_evaluate_schedule(&config, "C", &value, NULL) ==
              PSO_SCHEDULE_INSIDE,
          "cross-midnight start day");
    value = wall_time(2, 1, 59);
    check(pso_evaluate_schedule(&config, "C", &value, NULL) ==
              PSO_SCHEDULE_INSIDE,
          "cross-midnight following day");
    value = wall_time(2, 2, 0);
    check(pso_evaluate_schedule(&config, "C", &value, NULL) ==
              PSO_SCHEDULE_OUTSIDE,
          "cross-midnight end exclusive");
    value = wall_time(0, 9, 0);
    check(pso_evaluate_schedule(&config, "A", &value, NULL) ==
              PSO_SCHEDULE_OUTSIDE,
          "Sunday outside");
    check(pso_evaluate_schedule(&config, "unmanaged", &value, NULL) ==
              PSO_SCHEDULE_UNMANAGED_IGNORE,
          "explicit unmanaged ignore");

    {
        static const char deny[] =
            "version=1\ndefault=deny\n"
            "user=A;days=Mo;time=0800-1400;secret=A.secret\n";
        check(pso_parse_config(deny, sizeof(deny) - 1U, &config) == 0,
              "deny config parses");
        check(pso_evaluate_schedule(&config, "unmanaged", &value, NULL) ==
                  PSO_SCHEDULE_UNMANAGED_DENY,
              "explicit unmanaged deny");
    }

    {
        static const char duplicate[] =
            "version=1\ndefault=deny\n"
            "user=A;days=Mo;time=0800-1400;secret=A.secret\n"
            "user=A;days=Tu;time=0800-1400;secret=A.secret\n";
        check(pso_parse_config(duplicate, sizeof(duplicate) - 1U, &config) != 0,
              "duplicate user rejected");
    }
    {
        static const char invalid_day[] =
            "version=1\ndefault=deny\n"
            "user=A;days=Fr-Mo;time=0800-1400;secret=A.secret\n";
        check(pso_parse_config(invalid_day, sizeof(invalid_day) - 1U, &config) != 0,
              "ambiguous wrapped day range rejected");
    }
    {
        static const char invalid_time[] =
            "version=1\ndefault=deny\n"
            "user=A;days=Mo;time=2400-1400;secret=A.secret\n";
        check(pso_parse_config(invalid_time, sizeof(invalid_time) - 1U, &config) != 0,
              "invalid time rejected");
    }
    {
        static const char full_day[] =
            "version=1\ndefault=deny\n"
            "user=A;days=Mo;time=0800-0800;secret=A.secret\n";
        check(pso_parse_config(full_day, sizeof(full_day) - 1U, &config) != 0,
              "ambiguous 24-hour interval rejected");
    }
    {
        static const char path_secret[] =
            "version=1\ndefault=deny\n"
            "user=A;days=Mo;time=0800-1400;secret=../A.secret\n";
        check(pso_parse_config(path_secret, sizeof(path_secret) - 1U, &config) != 0,
              "secret path traversal rejected");
    }
    {
        static const char missing_default[] =
            "version=1\nuser=A;days=Mo;time=0800-1400;secret=A.secret\n";
        check(pso_parse_config(missing_default, sizeof(missing_default) - 1U,
                               &config) != 0,
              "missing default rejected");
    }
    {
        char nul_config[] = "version=1\ndefault=deny\n\0user=A";
        check(pso_parse_config(nul_config, sizeof(nul_config) - 1U, &config) != 0,
              "embedded NUL rejected");
    }

    if (failures != 0) return EXIT_FAILURE;
    puts("schedule policy tests passed");
    return EXIT_SUCCESS;
}
