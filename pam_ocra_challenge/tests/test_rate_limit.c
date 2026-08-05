#define _GNU_SOURCE

#include "../rate_limit.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define TEST_UID "1000"
#define TEST_SERVICE "login"
#define TEST_KEY_ID "0123456789abcdef"
#define TEST_STATE_NAME TEST_UID "-" TEST_SERVICE "-" TEST_KEY_ID ".state"
#define TEST_LOCK_NAME TEST_UID "-" TEST_SERVICE "-" TEST_KEY_ID ".lock"
#define TEST_TEMP_NAME TEST_UID "-" TEST_SERVICE "-" TEST_KEY_ID ".tmp"

struct state_fixture {
    char root_path[128];
    int root_fd;
};

struct challenge_script {
    const char *const *values;
    size_t count;
    size_t offset;
    int fail;
};

static time_t fake_now;
static int fake_clock_failure;
static struct challenge_script *active_challenges;

static void require(int condition, const char *message)
{
    if (!condition) {
        (void)fprintf(stderr, "test failure: %s\n", message);
        exit(EXIT_FAILURE);
    }
}

static int fake_clock(clockid_t clock_id, struct timespec *value)
{
    require(clock_id == CLOCK_MONOTONIC,
            "rate limiter must request CLOCK_MONOTONIC");
    require(value != NULL, "clock provider needs an output location");
    if (fake_clock_failure != 0) {
        errno = EIO;
        return -1;
    }
    value->tv_sec = fake_now;
    value->tv_nsec = 0L;
    return 0;
}

static int scripted_challenge(char output[OCRA_CHALLENGE_DIGITS + 1U])
{
    require(output != NULL, "challenge provider needs an output location");
    require(active_challenges != NULL,
            "challenge provider needs an active script");
    if (active_challenges->fail != 0 ||
        active_challenges->offset >= active_challenges->count) {
        errno = EIO;
        return -1;
    }
    (void)memcpy(output, active_challenges->values[active_challenges->offset],
                 OCRA_CHALLENGE_DIGITS + 1U);
    ++active_challenges->offset;
    return 0;
}

static void install_challenges(struct challenge_script *script)
{
    active_challenges = script;
    ocra_rate_limit_set_challenge_provider_for_tests(scripted_challenge);
}

static void reset_providers(void)
{
    ocra_rate_limit_reset_clock_provider_for_tests();
    ocra_rate_limit_reset_challenge_provider_for_tests();
    ocra_rate_limit_reset_expected_owner_for_tests();
    ocra_rate_limit_reset_state_close_provider_for_tests();
    active_challenges = NULL;
    fake_clock_failure = 0;
}

static int use_alternate_group_if_available(int fd, gid_t *alternate)
{
    gid_t current = getegid();
    gid_t *groups;
    int count;
    int index;

    if (geteuid() == (uid_t)0) {
        *alternate = current == (gid_t)1 ? (gid_t)2 : (gid_t)1;
        return fchown(fd, (uid_t)-1, *alternate) == 0;
    }
    count = getgroups(0, NULL);
    require(count >= 0, "supplementary groups must be queryable");
    if (count == 0) {
        return 0;
    }
    groups = calloc((size_t)count, sizeof(*groups));
    require(groups != NULL, "supplementary group storage must allocate");
    require(getgroups(count, groups) == count,
            "supplementary groups must be readable");
    for (index = 0; index < count; ++index) {
        if (groups[index] != current) {
            if (fchown(fd, (uid_t)-1, groups[index]) == 0) {
                *alternate = groups[index];
                free(groups);
                return 1;
            }
        }
    }
    free(groups);
    return 0;
}

static void require_alternate_group_when_requested(int available)
{
    const char *required = getenv("OCRA_TEST_REQUIRE_OWNER_MISMATCH");

    require(required == NULL || strcmp(required, "yes") != 0 ||
                available != 0,
            "owner-normalization run requires a real alternate group");
}

static int close_then_report_failure(int fd)
{
    int result = close(fd);

    require(result == 0, "injected state close must close the real descriptor");
    errno = EIO;
    return -1;
}

static void fixture_create(struct state_fixture *fixture)
{
    char template[] = "/tmp/ocra-rate-limit-XXXXXX";
    char *path = mkdtemp(template);

    require(path != NULL, "temporary state root must be created");
    require(strlen(path) < sizeof(fixture->root_path),
            "temporary state path must fit fixture storage");
    (void)strcpy(fixture->root_path, path);
    require(chmod(path, 0700) == 0, "state root mode must be exact");
    fixture->root_fd =
        open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    require(fixture->root_fd >= 0, "temporary state root must open");
}

static void fixture_remove_entries(struct state_fixture *fixture)
{
    DIR *directory;
    struct dirent *entry;
    int scan_fd = dup(fixture->root_fd);

    require(scan_fd >= 0, "state root descriptor must duplicate");
    directory = fdopendir(scan_fd);
    require(directory != NULL, "state root descriptor must scan");
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            require(unlinkat(fixture->root_fd, entry->d_name, 0) == 0,
                    "state fixture entry must be removed");
        }
        errno = 0;
    }
    require(errno == 0, "state root scan must finish cleanly");
    require(closedir(directory) == 0, "state root scan must close");
}

static void fixture_destroy(struct state_fixture *fixture)
{
    fixture_remove_entries(fixture);
    require(close(fixture->root_fd) == 0,
            "temporary state root descriptor must close");
    require(rmdir(fixture->root_path) == 0,
            "temporary state root must be removed");
    reset_providers();
}

static int reserve_scope(struct state_fixture *fixture, const char *uid,
                         const char *service, const char *key_id,
                         char challenge[OCRA_CHALLENGE_DIGITS + 1U])
{
    return ocra_rate_limit_reserve_at(fixture->root_fd, uid, service, key_id,
                                      challenge);
}

static int reserve(struct state_fixture *fixture,
                   char challenge[OCRA_CHALLENGE_DIGITS + 1U])
{
    return reserve_scope(fixture, TEST_UID, TEST_SERVICE, TEST_KEY_ID,
                         challenge);
}

static int reset(struct state_fixture *fixture)
{
    return ocra_rate_limit_reset_at(fixture->root_fd, TEST_UID, TEST_SERVICE,
                                    TEST_KEY_ID);
}

static void use_real_challenges_at(time_t seconds)
{
    fake_now = seconds;
    ocra_rate_limit_set_clock_provider_for_tests(fake_clock);
    ocra_rate_limit_reset_challenge_provider_for_tests();
}

static void test_first_through_fifth_reserve_and_sixth_is_blocked(void)
{
    struct state_fixture fixture;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    unsigned int attempt;

    fixture_create(&fixture);
    use_real_challenges_at((time_t)100);
    for (attempt = 1U; attempt <= 5U; ++attempt) {
        require(reserve(&fixture, challenge) == 0,
                "attempts one through five must reserve");
        require(strlen(challenge) == OCRA_CHALLENGE_DIGITS,
                "an authorized attempt must return ten digits");
    }
    (void)memset(challenge, 'X', sizeof(challenge));
    require(reserve(&fixture, challenge) != 0,
            "the sixth attempt inside the window must be blocked");
    require(challenge[0] == '\0',
            "a blocked reservation must not expose a stale challenge");
    fixture_destroy(&fixture);
}

static void test_abandoned_reservations_still_consume_attempts(void)
{
    struct state_fixture fixture;
    char ignored[OCRA_CHALLENGE_DIGITS + 1U];
    unsigned int attempt;

    fixture_create(&fixture);
    use_real_challenges_at((time_t)200);
    for (attempt = 0U; attempt < 5U; ++attempt) {
        require(reserve(&fixture, ignored) == 0,
                "a displayed challenge must reserve its attempt");
    }
    require(reserve(&fixture, ignored) != 0,
            "abandoning five prompts must still reach the limit");
    fixture_destroy(&fixture);
}

static void test_window_expiration_starts_a_fresh_count(void)
{
    struct state_fixture fixture;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    unsigned int attempt;

    fixture_create(&fixture);
    use_real_challenges_at((time_t)10);
    for (attempt = 0U; attempt < 4U; ++attempt) {
        require(reserve(&fixture, challenge) == 0,
                "four initial-window reservations must succeed");
    }
    fake_now = (time_t)310;
    for (attempt = 0U; attempt < 5U; ++attempt) {
        require(reserve(&fixture, challenge) == 0,
                "expired window must provide five fresh reservations");
    }
    require(reserve(&fixture, challenge) != 0,
            "fresh window must block its own sixth reservation");
    fixture_destroy(&fixture);
}

static void test_block_expires_after_exactly_300_seconds(void)
{
    struct state_fixture fixture;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    unsigned int attempt;

    fixture_create(&fixture);
    use_real_challenges_at((time_t)100);
    for (attempt = 0U; attempt < 5U; ++attempt) {
        require(reserve(&fixture, challenge) == 0,
                "five reservations must establish the block");
    }
    fake_now = (time_t)399;
    require(reserve(&fixture, challenge) != 0,
            "the block must remain active one second before expiry");
    fake_now = (time_t)400;
    require(reserve(&fixture, challenge) == 0,
            "the block must expire at its 300-second boundary");
    fixture_destroy(&fixture);
}

static void test_clock_rollback_and_clock_errors_fail_closed(void)
{
    struct state_fixture fixture;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];

    fixture_create(&fixture);
    use_real_challenges_at((time_t)1000);
    require(reserve(&fixture, challenge) == 0,
            "state must establish a monotonic timestamp");
    fake_now = (time_t)999;
    require(reserve(&fixture, challenge) != 0,
            "a monotonic timestamp earlier than stored must deny");
    fake_clock_failure = 1;
    require(reserve(&fixture, challenge) != 0,
            "a clock provider error must deny");
    fixture_destroy(&fixture);
}

static void test_deadline_overflow_fails_closed(void)
{
    struct state_fixture fixture;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];

    fixture_create(&fixture);
    use_real_challenges_at((time_t)INT64_MAX);
    require(reserve(&fixture, challenge) != 0,
            "a timestamp that cannot add policy intervals must deny");
    fixture_destroy(&fixture);
}

static void test_truncated_and_corrupt_state_fail_closed(void)
{
    struct state_fixture fixture;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    unsigned char corruption = 0xa5U;
    unsigned char checksum_byte;
    int fd;

    fixture_create(&fixture);
    use_real_challenges_at((time_t)50);
    require(reserve(&fixture, challenge) == 0,
            "valid state must be created before truncation");
    fd = openat(fixture.root_fd, TEST_STATE_NAME,
                O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC);
    require(fd >= 0, "state file must open for truncation fixture");
    require(write(fd, &corruption, sizeof(corruption)) ==
                (ssize_t)sizeof(corruption),
            "corrupt fixture byte must be written");
    require(close(fd) == 0, "corrupt fixture must close");
    require(reserve(&fixture, challenge) != 0,
            "truncated corrupt state must deny");
    fixture_destroy(&fixture);

    fixture_create(&fixture);
    use_real_challenges_at((time_t)50);
    require(reserve(&fixture, challenge) == 0,
            "valid state must be created before checksum corruption");
    fd = openat(fixture.root_fd, TEST_STATE_NAME,
                O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    require(fd >= 0, "state file must open for corruption fixture");
    require(pread(fd, &checksum_byte, sizeof(checksum_byte), (off_t)223) ==
                (ssize_t)sizeof(checksum_byte),
            "stored checksum byte must be read");
    checksum_byte ^= 0xffU;
    require(pwrite(fd, &checksum_byte, sizeof(checksum_byte), (off_t)223) ==
                (ssize_t)sizeof(checksum_byte),
            "stored checksum must be corrupted without truncating state");
    require(close(fd) == 0, "checksum corruption fixture must close");
    require(reserve(&fixture, challenge) != 0,
            "full-size state with invalid checksum must deny");
    fixture_destroy(&fixture);
}

static void test_incorrect_root_and_file_modes_fail_closed(void)
{
    struct state_fixture fixture;
    struct stat status;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];

    fixture_create(&fixture);
    use_real_challenges_at((time_t)50);
    require(chmod(fixture.root_path, 0755) == 0,
            "root fixture mode must be weakened");
    require(reserve(&fixture, challenge) != 0,
            "state root without exact 0700 mode must deny");
    require(chmod(fixture.root_path, 0700) == 0,
            "root fixture mode must be restored");
    require(reserve(&fixture, challenge) == 0,
            "valid metadata must permit initial state creation");
    require(fchmodat(fixture.root_fd, TEST_STATE_NAME, 0644, 0) == 0,
            "state fixture mode must be weakened");
    require(reserve(&fixture, challenge) != 0,
            "state file without exact 0600 mode must deny");
    require(fstatat(fixture.root_fd, TEST_STATE_NAME, &status,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
                (status.st_mode & 07777) == 0644,
            "preexisting insecure state must not be repaired");
    fixture_destroy(&fixture);
}

static void test_new_directories_normalize_mode_and_owner_only_on_creation(void)
{
    struct state_fixture fixture;
    struct stat status;
    mode_t previous_umask;
    gid_t expected_group = getegid();
    int has_alternate_group;
    int result;

    fixture_create(&fixture);
    has_alternate_group = use_alternate_group_if_available(
        fixture.root_fd, &expected_group);
    require_alternate_group_when_requested(has_alternate_group);
    if (has_alternate_group != 0) {
        ocra_rate_limit_set_expected_owner_for_tests(geteuid(),
                                                     expected_group);
    }
    previous_umask = umask(0277);
    result = ocra_rate_limit_prepare_directory_at_for_tests(fixture.root_fd,
                                                            "created");
    (void)umask(previous_umask);
    require(result == 0,
            "new directory must be normalized despite restrictive umask");
    require(fstatat(fixture.root_fd, "created", &status,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
                S_ISDIR(status.st_mode) &&
                (status.st_mode & 07777) == 0700 &&
                status.st_uid == geteuid() &&
                status.st_gid == expected_group,
            "new directory must have exact expected metadata");
    require(unlinkat(fixture.root_fd, "created", AT_REMOVEDIR) == 0,
            "normalized directory fixture must be removed");

    require(mkdirat(fixture.root_fd, "existing", 0755) == 0,
            "preexisting directory fixture must be created");
    require(fchmodat(fixture.root_fd, "existing", 0755, 0) == 0,
            "preexisting directory fixture must have insecure mode");
    require(ocra_rate_limit_prepare_directory_at_for_tests(fixture.root_fd,
                                                           "existing") != 0,
            "preexisting insecure directory must be denied");
    require(fstatat(fixture.root_fd, "existing", &status,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
                (status.st_mode & 07777) == 0755,
            "preexisting insecure directory must not be repaired");
    require(unlinkat(fixture.root_fd, "existing", AT_REMOVEDIR) == 0,
            "preexisting directory fixture must be removed");
    fixture_destroy(&fixture);
}

static void test_new_state_objects_normalize_mode_and_owner(void)
{
    struct state_fixture fixture;
    struct stat status;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    mode_t previous_umask;
    gid_t expected_group = getegid();
    int has_alternate_group;
    int result;

    fixture_create(&fixture);
    has_alternate_group = use_alternate_group_if_available(
        fixture.root_fd, &expected_group);
    require_alternate_group_when_requested(has_alternate_group);
    if (has_alternate_group != 0) {
        ocra_rate_limit_set_expected_owner_for_tests(geteuid(),
                                                     expected_group);
    }
    use_real_challenges_at((time_t)52);
    previous_umask = umask(0277);
    result = reserve(&fixture, challenge);
    (void)umask(previous_umask);
    require(result == 0,
            "new lock and state must normalize restrictive creation metadata");
    require(fstatat(fixture.root_fd, TEST_LOCK_NAME, &status,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
                (status.st_mode & 07777) == 0600 &&
                status.st_uid == geteuid() &&
                status.st_gid == expected_group,
            "new lock must have exact expected metadata");
    require(fstatat(fixture.root_fd, TEST_STATE_NAME, &status,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
                (status.st_mode & 07777) == 0600 &&
                status.st_uid == geteuid() &&
                status.st_gid == expected_group,
            "new state must have exact expected metadata");
    fixture_destroy(&fixture);
}

static void test_symlink_and_hardlink_state_are_rejected(void)
{
    struct state_fixture fixture;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];

    fixture_create(&fixture);
    use_real_challenges_at((time_t)50);
    require(symlinkat("/dev/null", fixture.root_fd, TEST_STATE_NAME) == 0,
            "state symlink fixture must be created");
    require(reserve(&fixture, challenge) != 0,
            "a state symlink must be rejected without following it");
    require(unlinkat(fixture.root_fd, TEST_STATE_NAME, 0) == 0,
            "state symlink fixture must be removed");
    require(reserve(&fixture, challenge) == 0,
            "regular state must be created for hardlink test");
    require(linkat(fixture.root_fd, TEST_STATE_NAME, fixture.root_fd,
                   "alias.state", 0) == 0,
            "state hardlink fixture must be created");
    require(reserve(&fixture, challenge) != 0,
            "a state inode with multiple links must be rejected");
    fixture_destroy(&fixture);
}

static void test_insecure_lock_objects_are_rejected(void)
{
    struct state_fixture fixture;
    struct stat status;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];

    fixture_create(&fixture);
    use_real_challenges_at((time_t)55);
    require(reserve(&fixture, challenge) == 0,
            "valid lock must be created before mode test");
    require(fchmodat(fixture.root_fd, TEST_LOCK_NAME, 0644, 0) == 0,
            "lock fixture mode must be weakened");
    require(reserve(&fixture, challenge) != 0,
            "preexisting lock without exact 0600 mode must deny");
    require(fstatat(fixture.root_fd, TEST_LOCK_NAME, &status,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
                (status.st_mode & 07777) == 0644,
            "preexisting insecure lock must not be repaired");
    fixture_destroy(&fixture);

    fixture_create(&fixture);
    use_real_challenges_at((time_t)55);
    require(symlinkat("/dev/null", fixture.root_fd, TEST_LOCK_NAME) == 0,
            "lock symlink fixture must be created");
    require(reserve(&fixture, challenge) != 0,
            "a lock symlink must be rejected without following it");
    fixture_destroy(&fixture);

    fixture_create(&fixture);
    use_real_challenges_at((time_t)55);
    require(reserve(&fixture, challenge) == 0,
            "valid lock must be created before hardlink test");
    require(linkat(fixture.root_fd, TEST_LOCK_NAME, fixture.root_fd,
                   "alias.lock", 0) == 0,
            "lock hardlink fixture must be created");
    require(reserve(&fixture, challenge) != 0,
            "a lock inode with multiple links must be rejected");
    fixture_destroy(&fixture);
}

static void test_insecure_preexisting_temp_is_denied_without_repair(void)
{
    struct state_fixture fixture;
    struct stat status;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    int fd;

    fixture_create(&fixture);
    use_real_challenges_at((time_t)58);
    fd = openat(fixture.root_fd, TEST_TEMP_NAME,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    require(fd >= 0 && fchmod(fd, 0644) == 0 && close(fd) == 0,
            "preexisting insecure temp fixture must be created");
    require(reserve(&fixture, challenge) != 0,
            "preexisting insecure temp must be denied");
    require(fstatat(fixture.root_fd, TEST_TEMP_NAME, &status,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
                (status.st_mode & 07777) == 0644,
            "preexisting insecure temp must not be repaired or removed");
    fixture_destroy(&fixture);
}

static void test_repeated_challenge_is_regenerated_before_reservation(void)
{
    static const char *const values[] = {"0000000001", "0000000001",
                                         "0000000002"};
    struct challenge_script script = {values, 3U, 0U, 0};
    struct state_fixture fixture;
    char first[OCRA_CHALLENGE_DIGITS + 1U];
    char second[OCRA_CHALLENGE_DIGITS + 1U];

    fixture_create(&fixture);
    fake_now = (time_t)77;
    ocra_rate_limit_set_clock_provider_for_tests(fake_clock);
    install_challenges(&script);
    require(reserve(&fixture, first) == 0,
            "first scripted challenge must reserve");
    require(reserve(&fixture, second) == 0,
            "collision followed by fresh challenge must reserve");
    require(strcmp(first, "0000000001") == 0 &&
                strcmp(second, "0000000002") == 0,
            "recent collision must be skipped in favor of fresh value");
    require(script.offset == 3U,
            "collision regeneration must consume one additional value");
    fixture_destroy(&fixture);
}

static void test_collision_retry_exhaustion_fails_closed(void)
{
    static const char *const first_value[] = {"0000000042"};
    static const char *const repeats[] = {
        "0000000042", "0000000042", "0000000042", "0000000042",
        "0000000042", "0000000042", "0000000042", "0000000042"};
    struct challenge_script first_script = {first_value, 1U, 0U, 0};
    struct challenge_script repeat_script = {repeats, 8U, 0U, 0};
    struct state_fixture fixture;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];

    fixture_create(&fixture);
    fake_now = (time_t)88;
    ocra_rate_limit_set_clock_provider_for_tests(fake_clock);
    install_challenges(&first_script);
    require(reserve(&fixture, challenge) == 0,
            "initial challenge must populate recent history");
    install_challenges(&repeat_script);
    require(reserve(&fixture, challenge) != 0,
            "exhausting the explicit collision budget must deny");
    require(repeat_script.offset == 8U,
            "collision retry limit must be finite and exact");
    fixture_destroy(&fixture);
}

static void test_full_ring_evicts_only_the_oldest_challenge(void)
{
    static const char *const values[] = {
        "0000000001", "0000000002", "0000000003", "0000000004",
        "0000000005", "0000000006", "0000000007", "0000000008",
        "0000000009", "0000000010", "0000000011", "0000000012",
        "0000000013", "0000000014", "0000000015", "0000000016",
        "0000000001", "0000000017", "0000000001"};
    struct challenge_script script = {values, 19U, 0U, 0};
    struct state_fixture fixture;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    size_t index;

    fixture_create(&fixture);
    fake_now = (time_t)90;
    ocra_rate_limit_set_clock_provider_for_tests(fake_clock);
    install_challenges(&script);
    for (index = 0U; index < 16U; ++index) {
        require(reserve(&fixture, challenge) == 0,
                "each unique challenge must fill one ring slot");
        require(reset(&fixture) == 0,
                "success reset must permit filling recent history");
    }
    require(reserve(&fixture, challenge) == 0 &&
                strcmp(challenge, "0000000017") == 0,
            "full ring must reject its oldest member before replacement");
    require(reset(&fixture) == 0,
            "reset after ring replacement must succeed");
    require(reserve(&fixture, challenge) == 0 &&
                strcmp(challenge, "0000000001") == 0,
            "evicted oldest challenge must become eligible again");
    require(script.offset == 19U,
            "bounded ring replacement must consume the expected script");
    fixture_destroy(&fixture);
}

static void test_reset_after_success_clears_attempt_block_only(void)
{
    struct state_fixture fixture;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    unsigned int attempt;

    fixture_create(&fixture);
    use_real_challenges_at((time_t)500);
    for (attempt = 0U; attempt < 5U; ++attempt) {
        require(reserve(&fixture, challenge) == 0,
                "five attempts must reach a block before success reset");
    }
    require(reserve(&fixture, challenge) != 0,
            "scope must be blocked before reset");
    require(reset(&fixture) == 0,
            "successful authentication must reset under lock");
    require(reserve(&fixture, challenge) == 0,
            "reset must permit a new first attempt immediately");
    fixture_destroy(&fixture);
}

static void test_scopes_are_independent_by_uid_service_and_key_id(void)
{
    struct state_fixture fixture;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    unsigned int attempt;

    fixture_create(&fixture);
    use_real_challenges_at((time_t)700);
    for (attempt = 0U; attempt < 5U; ++attempt) {
        require(reserve(&fixture, challenge) == 0,
                "base scope must consume five attempts");
    }
    require(reserve(&fixture, challenge) != 0,
            "base scope must be blocked");
    require(reserve_scope(&fixture, "1001", TEST_SERVICE, TEST_KEY_ID,
                          challenge) == 0,
            "a second UID must have an independent limit");
    require(reserve_scope(&fixture, TEST_UID, "sshd", TEST_KEY_ID,
                          challenge) == 0,
            "a second PAM service must have an independent limit");
    require(reserve_scope(&fixture, TEST_UID, TEST_SERVICE,
                          "fedcba9876543210", challenge) == 0,
            "a second key identifier must have an independent limit");
    fixture_destroy(&fixture);
}

static void test_invalid_scope_and_key_identifier_fail_before_state_creation(void)
{
    struct state_fixture fixture;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];

    fixture_create(&fixture);
    use_real_challenges_at((time_t)800);
    require(reserve_scope(&fixture, "01000", TEST_SERVICE, TEST_KEY_ID,
                          challenge) != 0,
            "noncanonical UID must be rejected by shared scope validation");
    require(reserve_scope(&fixture, TEST_UID, "../login", TEST_KEY_ID,
                          challenge) != 0,
            "unsafe service must be rejected by shared scope validation");
    require(reserve_scope(&fixture, TEST_UID, TEST_SERVICE, "xyz", challenge) !=
                0,
            "non-hex or short key identifier must be rejected");
    fixture_destroy(&fixture);
}

static void test_challenge_generation_error_does_not_reserve_an_attempt(void)
{
    static const char *const value[] = {"0000000099"};
    struct challenge_script failing = {NULL, 0U, 0U, 1};
    struct challenge_script working = {value, 1U, 0U, 0};
    struct state_fixture fixture;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];

    fixture_create(&fixture);
    fake_now = (time_t)900;
    ocra_rate_limit_set_clock_provider_for_tests(fake_clock);
    install_challenges(&failing);
    require(reserve(&fixture, challenge) != 0,
            "challenge provider failure must deny atomically");
    install_challenges(&working);
    require(reserve(&fixture, challenge) == 0 &&
                strcmp(challenge, "0000000099") == 0,
            "a failed challenge generation must not leave partial state");
    fixture_destroy(&fixture);
}

static void test_state_close_error_denies_and_clears_challenge(void)
{
    struct state_fixture fixture;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];

    fixture_create(&fixture);
    use_real_challenges_at((time_t)950);
    require(reserve(&fixture, challenge) == 0,
            "existing state must be created before close error injection");
    ocra_rate_limit_set_state_close_provider_for_tests(
        close_then_report_failure);
    (void)memset(challenge, 'X', sizeof(challenge));
    require(reserve(&fixture, challenge) != 0,
            "state descriptor close failure must deny");
    require(challenge[0] == '\0',
            "state descriptor close failure must clear challenge output");
    ocra_rate_limit_reset_state_close_provider_for_tests();
    fixture_destroy(&fixture);
}

int main(void)
{
    test_first_through_fifth_reserve_and_sixth_is_blocked();
    test_abandoned_reservations_still_consume_attempts();
    test_window_expiration_starts_a_fresh_count();
    test_block_expires_after_exactly_300_seconds();
    test_clock_rollback_and_clock_errors_fail_closed();
    test_deadline_overflow_fails_closed();
    test_truncated_and_corrupt_state_fail_closed();
    test_incorrect_root_and_file_modes_fail_closed();
    test_new_directories_normalize_mode_and_owner_only_on_creation();
    test_new_state_objects_normalize_mode_and_owner();
    test_symlink_and_hardlink_state_are_rejected();
    test_insecure_lock_objects_are_rejected();
    test_insecure_preexisting_temp_is_denied_without_repair();
    test_repeated_challenge_is_regenerated_before_reservation();
    test_collision_retry_exhaustion_fails_closed();
    test_full_ring_evicts_only_the_oldest_challenge();
    test_reset_after_success_clears_attempt_block_only();
    test_scopes_are_independent_by_uid_service_and_key_id();
    test_invalid_scope_and_key_identifier_fail_before_state_creation();
    test_challenge_generation_error_does_not_reserve_an_attempt();
    test_state_close_error_denies_and_clears_challenge();
    return EXIT_SUCCESS;
}
