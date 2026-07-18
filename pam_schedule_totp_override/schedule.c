#define _GNU_SOURCE

#include "schedule.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define PSO_MAX_LINE_LEN 256U

static int copy_bounded(char *out, size_t capacity, const char *input,
                        size_t length)
{
    if (out == NULL || input == NULL || length == 0U || length >= capacity) {
        return -1;
    }
    memcpy(out, input, length);
    out[length] = '\0';
    return 0;
}

void pso_secure_memzero(void *buffer, size_t length)
{
    volatile unsigned char *cursor = (volatile unsigned char *)buffer;

    if (buffer == NULL) return;
    while (length > 0U) {
        *cursor++ = 0U;
        length--;
    }
}

int pso_validate_username(const char *username)
{
    size_t length;

    if (username == NULL) return -1;
    length = strnlen(username, PSO_MAX_USER_LEN + 1U);
    if (length == 0U || length > PSO_MAX_USER_LEN) return -1;

    for (size_t i = 0U; i < length; i++) {
        unsigned char ch = (unsigned char)username[i];
        if (!((ch >= (unsigned char)'A' && ch <= (unsigned char)'Z') ||
              (ch >= (unsigned char)'a' && ch <= (unsigned char)'z') ||
              (ch >= (unsigned char)'0' && ch <= (unsigned char)'9') ||
              ch == (unsigned char)'_' || ch == (unsigned char)'-' ||
              ch == (unsigned char)'.')) {
            return -1;
        }
    }
    if (strcmp(username, ".") == 0 || strcmp(username, "..") == 0) return -1;
    return 0;
}

int pso_validate_secret_name(const char *name)
{
    size_t length;

    if (name == NULL) return -1;
    length = strnlen(name, PSO_MAX_SECRET_NAME_LEN + 1U);
    if (length == 0U || length > PSO_MAX_SECRET_NAME_LEN || name[0] == '.') {
        return -1;
    }
    if (strstr(name, "..") != NULL) return -1;

    for (size_t i = 0U; i < length; i++) {
        unsigned char ch = (unsigned char)name[i];
        if (!((ch >= (unsigned char)'A' && ch <= (unsigned char)'Z') ||
              (ch >= (unsigned char)'a' && ch <= (unsigned char)'z') ||
              (ch >= (unsigned char)'0' && ch <= (unsigned char)'9') ||
              ch == (unsigned char)'_' || ch == (unsigned char)'-' ||
              ch == (unsigned char)'.')) {
            return -1;
        }
    }
    if (length < 8U || strcmp(name + length - 7U, ".secret") != 0) return -1;
    return 0;
}

static int day_index(const char *token)
{
    static const char *const days[] = {"Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"};

    if (token == NULL || token[0] == '\0' || token[1] == '\0' || token[2] != '\0') {
        return -1;
    }
    for (int i = 0; i < 7; i++) {
        if (strcmp(token, days[i]) == 0) return i;
    }
    return -1;
}

static uint8_t day_bit_from_index(int index)
{
    int tm_day = index == 6 ? 0 : index + 1;
    return (uint8_t)(1U << (unsigned int)tm_day);
}

static int parse_days(const char *text, uint8_t *mask_out)
{
    char copy[64];
    char *cursor;
    char *saveptr = NULL;
    uint8_t mask = 0U;
    size_t length;

    if (text == NULL || mask_out == NULL) return -1;
    length = strnlen(text, sizeof(copy));
    if (length == 0U || length >= sizeof(copy)) return -1;
    memcpy(copy, text, length + 1U);

    cursor = strtok_r(copy, ",", &saveptr);
    while (cursor != NULL) {
        size_t token_length = strlen(cursor);
        if (token_length == 2U) {
            int index = day_index(cursor);
            if (index < 0) return -1;
            mask = (uint8_t)(mask | day_bit_from_index(index));
        } else if (token_length == 5U && cursor[2] == '-') {
            char first[3] = {cursor[0], cursor[1], '\0'};
            char last[3] = {cursor[3], cursor[4], '\0'};
            int start = day_index(first);
            int end = day_index(last);
            if (start < 0 || end < 0 || start > end) return -1;
            for (int i = start; i <= end; i++) {
                mask = (uint8_t)(mask | day_bit_from_index(i));
            }
        } else {
            return -1;
        }
        cursor = strtok_r(NULL, ",", &saveptr);
    }
    if (mask == 0U) return -1;
    *mask_out = mask;
    return 0;
}

static int parse_four_digits(const char *text, uint16_t *minutes_out)
{
    unsigned int hour;
    unsigned int minute;

    if (text == NULL || minutes_out == NULL) return -1;
    for (size_t i = 0U; i < 4U; i++) {
        if (!isdigit((unsigned char)text[i])) return -1;
    }
    hour = (unsigned int)(text[0] - '0') * 10U + (unsigned int)(text[1] - '0');
    minute = (unsigned int)(text[2] - '0') * 10U + (unsigned int)(text[3] - '0');
    if (hour > 23U || minute > 59U) return -1;
    *minutes_out = (uint16_t)(hour * 60U + minute);
    return 0;
}

static int parse_time_range(const char *text, uint16_t *start_out,
                            uint16_t *end_out)
{
    uint16_t start;
    uint16_t end;

    if (text == NULL || strlen(text) != 9U || text[4] != '-') return -1;
    if (parse_four_digits(text, &start) != 0 ||
        parse_four_digits(text + 5, &end) != 0 || start == end) {
        return -1;
    }
    *start_out = start;
    *end_out = end;
    return 0;
}

static int parse_rule_line(const char *line, struct pso_rule *rule)
{
    static const char user_prefix[] = "user=";
    static const char days_marker[] = ";days=";
    static const char time_marker[] = ";time=";
    static const char secret_marker[] = ";secret=";
    const char *days;
    const char *time_range;
    const char *secret;
    size_t user_length;
    size_t days_length;
    size_t time_length;

    if (line == NULL || rule == NULL || strncmp(line, user_prefix,
                                                 sizeof(user_prefix) - 1U) != 0) {
        return -1;
    }
    days = strstr(line + sizeof(user_prefix) - 1U, days_marker);
    if (days == NULL) return -1;
    time_range = strstr(days + sizeof(days_marker) - 1U, time_marker);
    if (time_range == NULL) return -1;
    secret = strstr(time_range + sizeof(time_marker) - 1U, secret_marker);
    if (secret == NULL) return -1;

    user_length = (size_t)(days - (line + sizeof(user_prefix) - 1U));
    days += sizeof(days_marker) - 1U;
    days_length = (size_t)(time_range - days);
    time_range += sizeof(time_marker) - 1U;
    time_length = (size_t)(secret - time_range);
    secret += sizeof(secret_marker) - 1U;

    memset(rule, 0, sizeof(*rule));
    if (copy_bounded(rule->user, sizeof(rule->user),
                     line + sizeof(user_prefix) - 1U, user_length) != 0 ||
        copy_bounded(rule->secret_name, sizeof(rule->secret_name), secret,
                     strlen(secret)) != 0 ||
        pso_validate_username(rule->user) != 0 ||
        pso_validate_secret_name(rule->secret_name) != 0) {
        return -1;
    }

    {
        char days_copy[64];
        char time_copy[16];
        if (copy_bounded(days_copy, sizeof(days_copy), days, days_length) != 0 ||
            copy_bounded(time_copy, sizeof(time_copy), time_range, time_length) != 0 ||
            parse_days(days_copy, &rule->days_mask) != 0 ||
            parse_time_range(time_copy, &rule->start_minute,
                             &rule->end_minute) != 0) {
            pso_secure_memzero(days_copy, sizeof(days_copy));
            pso_secure_memzero(time_copy, sizeof(time_copy));
            return -1;
        }
        pso_secure_memzero(days_copy, sizeof(days_copy));
        pso_secure_memzero(time_copy, sizeof(time_copy));
    }
    return 0;
}

int pso_parse_config(const char *text, size_t length, struct pso_config *out)
{
    char *copy = NULL;
    char *line;
    char *saveptr = NULL;
    int version_seen = 0;
    int default_seen = 0;
    int result = -1;

    if (text == NULL || out == NULL || length == 0U ||
        length > PSO_MAX_CONFIG_SIZE || memchr(text, '\0', length) != NULL) {
        return -1;
    }

    copy = calloc(1U, length + 1U);
    if (copy == NULL) return -1;
    memcpy(copy, text, length);
    memset(out, 0, sizeof(*out));
    out->default_policy = PSO_DEFAULT_DENY;

    line = strtok_r(copy, "\n", &saveptr);
    while (line != NULL) {
        size_t line_length = strlen(line);
        if (line_length > 0U && line[line_length - 1U] == '\r') {
            line[--line_length] = '\0';
        }
        if (line_length >= PSO_MAX_LINE_LEN) goto cleanup;
        if (line_length == 0U || line[0] == '#') {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }
        if (strcmp(line, "version=1") == 0) {
            if (version_seen != 0 || out->rule_count != 0U) goto cleanup;
            version_seen = 1;
        } else if (strcmp(line, "default=deny") == 0 ||
                   strcmp(line, "default=ignore") == 0) {
            if (default_seen != 0 || out->rule_count != 0U) goto cleanup;
            out->default_policy = strcmp(line, "default=ignore") == 0
                                      ? PSO_DEFAULT_IGNORE
                                      : PSO_DEFAULT_DENY;
            default_seen = 1;
        } else {
            struct pso_rule rule;
            if (version_seen == 0 || default_seen == 0 ||
                out->rule_count >= PSO_MAX_RULES ||
                parse_rule_line(line, &rule) != 0) {
                goto cleanup;
            }
            for (size_t i = 0U; i < out->rule_count; i++) {
                if (strcmp(out->rules[i].user, rule.user) == 0 ||
                    strcmp(out->rules[i].secret_name, rule.secret_name) == 0) {
                    pso_secure_memzero(&rule, sizeof(rule));
                    goto cleanup;
                }
            }
            out->rules[out->rule_count++] = rule;
            pso_secure_memzero(&rule, sizeof(rule));
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }

    if (version_seen == 0 || default_seen == 0 || out->rule_count == 0U) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (result != 0) pso_secure_memzero(out, sizeof(*out));
    pso_secure_memzero(copy, length + 1U);
    free(copy);
    return result;
}

int pso_evaluate_schedule(const struct pso_config *config, const char *username,
                          const struct tm *local_time,
                          const struct pso_rule **rule_out)
{
    const struct pso_rule *rule = NULL;
    unsigned int minute;
    unsigned int day;
    unsigned int previous_day;
    uint8_t day_bit;
    uint8_t previous_bit;
    int inside = 0;

    if (rule_out != NULL) *rule_out = NULL;
    if (config == NULL || username == NULL || local_time == NULL ||
        local_time->tm_wday < 0 || local_time->tm_wday > 6 ||
        local_time->tm_hour < 0 || local_time->tm_hour > 23 ||
        local_time->tm_min < 0 || local_time->tm_min > 59) {
        return PSO_SCHEDULE_ERROR;
    }

    for (size_t i = 0U; i < config->rule_count; i++) {
        if (strcmp(config->rules[i].user, username) == 0) {
            rule = &config->rules[i];
            break;
        }
    }
    if (rule == NULL) {
        return config->default_policy == PSO_DEFAULT_IGNORE
                   ? PSO_SCHEDULE_UNMANAGED_IGNORE
                   : PSO_SCHEDULE_UNMANAGED_DENY;
    }

    minute = (unsigned int)local_time->tm_hour * 60U +
             (unsigned int)local_time->tm_min;
    day = (unsigned int)local_time->tm_wday;
    previous_day = day == 0U ? 6U : day - 1U;
    day_bit = (uint8_t)(1U << day);
    previous_bit = (uint8_t)(1U << previous_day);

    if (rule->start_minute < rule->end_minute) {
        inside = (rule->days_mask & day_bit) != 0U &&
                 minute >= rule->start_minute && minute < rule->end_minute;
    } else {
        inside = (((rule->days_mask & day_bit) != 0U) &&
                  minute >= rule->start_minute) ||
                 (((rule->days_mask & previous_bit) != 0U) &&
                  minute < rule->end_minute);
    }

    if (rule_out != NULL) *rule_out = rule;
    return inside ? PSO_SCHEDULE_INSIDE : PSO_SCHEDULE_OUTSIDE;
}
