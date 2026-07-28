// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0
//
// SAR local cargo-fuzz runner.
//
// Intended usage from repository root:
//
//   gcc -std=c11 -Wall -Wextra -O2 -D_POSIX_C_SOURCE=200809L \
//     -o tools/fuzz_runner tools/fuzz_runner.c
//
//   tools/sar_fuzz_runner --seconds 1800 --max-len 1048576 \
//     archive_entry_decode archive_audit parse_lfh parse_cd_footer parse_tlv
//
//   tools/sar_fuzz_runner --seconds 1800 --max-len 4096 \
//     stream_transcript_declared_lengths
//
// This runner:
// - accepts fuzz targets as positional arguments;
// - optionally builds each target first;
// - starts one cargo-fuzz run per target;
// - puts each cargo-fuzz job in its own process group;
// - kills child process groups on SIGTERM, SIGINT, or SIGHUP;
// - writes per-target build and run logs;
// - writes a Markdown summary;
// - does not pass explicit corpus directories to cargo-fuzz;
// - does not manage fuzz/corpus, fuzz/artifacts, or fuzz/target.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DEFAULT_SECONDS 1800
#define DEFAULT_MAX_LEN 1048576
#define DEFAULT_OUT_ROOT "/tmp/sar-fuzz-runs"

typedef struct {
    const char *target;
    pid_t pid;
    pid_t pgid;
    int exit_code;
    bool finished;
    time_t started_at;
    time_t ended_at;
    char log_path[PATH_MAX];
    char build_log_path[PATH_MAX];
} Job;

typedef struct {
    int seconds;
    int max_len;
    bool build_first;
    const char *out_root;
    int target_count;
    const char **targets;
} Config;

static Job *g_jobs = NULL;
static int g_job_count = 0;
static volatile sig_atomic_t g_shutdown_requested = 0;
static volatile sig_atomic_t g_shutdown_signal = 0;
static volatile sig_atomic_t g_active_cmd_pgid = -1;

static char g_run_dir[PATH_MAX];
static char g_logs_dir[PATH_MAX];
static char g_summary_path[PATH_MAX];

static void die(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
    exit(1);
}

static void checked_snprintf(char *dst, size_t dst_len, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    int n = vsnprintf(dst, dst_len, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= dst_len) {
        die("path or formatted string too long");
    }
}

static long parse_positive_long(const char *name, const char *value) {
    errno = 0;
    char *end = NULL;
    long parsed = strtol(value, &end, 10);

    if (errno != 0 || end == value || *end != '\0' || parsed <= 0) {
        die("invalid %s value: %s", name, value);
    }

    return parsed;
}

static void iso_time_local(time_t t, char *buf, size_t buf_len) {
    struct tm tm_buf;

    if (localtime_r(&t, &tm_buf) == NULL) {
        checked_snprintf(buf, buf_len, "unknown-time");
        return;
    }

    if (strftime(buf, buf_len, "%Y-%m-%dT%H:%M:%S%z", &tm_buf) == 0) {
        checked_snprintf(buf, buf_len, "unknown-time");
    }
}

static void make_run_id(char *buf, size_t buf_len) {
    time_t now = time(NULL);
    struct tm tm_buf;

    if (localtime_r(&now, &tm_buf) == NULL) {
        checked_snprintf(buf, buf_len, "sar-fuzz-unknown-time-%ld", (long)now);
        return;
    }

    if (strftime(buf, buf_len, "sar-fuzz-%Y%m%d-%H%M%S", &tm_buf) == 0) {
        checked_snprintf(buf, buf_len, "sar-fuzz-%ld", (long)now);
    }
}

static void mkdir_one(const char *path) {
    if (mkdir(path, 0755) == 0) {
        return;
    }

    if (errno == EEXIST) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            return;
        }
    }

    die("mkdir failed for %s: %s", path, strerror(errno));
}

static void mkdir_p(const char *path) {
    char tmp[PATH_MAX];
    size_t len = strlen(path);

    if (len == 0 || len >= sizeof(tmp)) {
        die("invalid directory path");
    }

    memcpy(tmp, path, len + 1);

    if (tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
    }

    for (char *p = tmp + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir_one(tmp);
            *p = '/';
        }
    }

    mkdir_one(tmp);
}

static void append_summary(const char *fmt, ...) {
    FILE *f = fopen(g_summary_path, "a");
    if (f == NULL) {
        fprintf(stderr, "failed to open summary %s: %s\n", g_summary_path, strerror(errno));
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);

    fclose(f);
}

static const char *exit_description(int exit_code) {
    if (exit_code == 0) {
        return "success";
    }

    if (exit_code >= 128) {
        return "terminated by signal or child reported signal-style exit";
    }

    return "non-zero exit";
}

static bool file_contains_indicator(const char *path, const char *needle) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return false;
    }

    char line[4096];
    bool found = false;

    while (fgets(line, sizeof(line), f) != NULL) {
        if (strstr(line, needle) != NULL) {
            found = true;
            break;
        }
    }

    fclose(f);
    return found;
}

static long extract_done_runs_from_log(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }

    char line[4096];
    long runs = -1;

    while (fgets(line, sizeof(line), f) != NULL) {
        char *done = strstr(line, "Done ");
        if (done == NULL) {
            continue;
        }

        done += 5;

        errno = 0;
        char *end = NULL;
        long parsed = strtol(done, &end, 10);

        if (errno == 0 && end != done && parsed >= 0) {
            runs = parsed;
        }
    }

    fclose(f);
    return runs;
}

static void restore_default_signal_handlers_for_child(void) {
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
}

static void handle_shutdown_signal(int signo) {
    g_shutdown_requested = 1;
    g_shutdown_signal = signo;
}

static void install_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = handle_shutdown_signal;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTERM, &sa, NULL) != 0) {
        die("sigaction(SIGTERM) failed: %s", strerror(errno));
    }

    if (sigaction(SIGINT, &sa, NULL) != 0) {
        die("sigaction(SIGINT) failed: %s", strerror(errno));
    }

    if (sigaction(SIGHUP, &sa, NULL) != 0) {
        die("sigaction(SIGHUP) failed: %s", strerror(errno));
    }
}

static void terminate_process_groups(int signo) {
    pid_t active = (pid_t)g_active_cmd_pgid;

    if (active > 0) {
        kill(-active, signo);
    }

    if (g_jobs == NULL) {
        return;
    }

    for (int i = 0; i < g_job_count; i++) {
        pid_t pgid = g_jobs[i].pgid;

        if (pgid > 0 && !g_jobs[i].finished) {
            kill(-pgid, signo);
        }
    }
}

static int wait_for_pid(pid_t pid, pid_t pgid, bool allow_shutdown_kill) {
    int status = 0;

    for (;;) {
        pid_t r = waitpid(pid, &status, 0);

        if (r == pid) {
            break;
        }

        if (r < 0 && errno == EINTR) {
            if (allow_shutdown_kill && g_shutdown_requested && pgid > 0) {
                kill(-pgid, SIGTERM);
            }
            continue;
        }

        if (r < 0) {
            return 127;
        }
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }

    return 126;
}

static int run_cmd_logged_argv(char *const argv[], const char *log_path) {
    pid_t pid = fork();

    if (pid < 0) {
        return 127;
    }

    if (pid == 0) {
        restore_default_signal_handlers_for_child();

        if (setpgid(0, 0) != 0) {
            _exit(111);
        }

        int fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            _exit(112);
        }

        if (dup2(fd, STDOUT_FILENO) < 0) {
            _exit(113);
        }

        if (dup2(fd, STDERR_FILENO) < 0) {
            _exit(114);
        }

        close(fd);

        execvp(argv[0], argv);
        _exit(127);
    }

    if (setpgid(pid, pid) != 0 && errno != EACCES && errno != ESRCH) {
        kill(pid, SIGTERM);
        return 127;
    }

    g_active_cmd_pgid = pid;
    int rc = wait_for_pid(pid, pid, true);
    g_active_cmd_pgid = -1;

    return rc;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s [options] <fuzz-target> [<fuzz-target> ...]\n"
            "\n"
            "Options:\n"
            "  --seconds N, --max-total-time N   libFuzzer -max_total_time value "
            "(default: %d)\n"
            "  --max-len N                       libFuzzer -max_len value "
            "(default: %d)\n"
            "  --out DIR                         output root directory "
            "(default: %s)\n"
            "  --no-build                        skip cargo fuzz build for each target\n"
            "  --help                            show this help\n"
            "\n"
            "Example:\n"
            "  %s --seconds 1800 --max-len 1048576 "
            "archive_entry_decode archive_audit parse_lfh\n",
            prog,
            DEFAULT_SECONDS,
            DEFAULT_MAX_LEN,
            DEFAULT_OUT_ROOT,
            prog);
}

static Config parse_args(int argc, char **argv) {
    Config cfg;
    cfg.seconds = DEFAULT_SECONDS;
    cfg.max_len = DEFAULT_MAX_LEN;
    cfg.build_first = true;
    cfg.out_root = DEFAULT_OUT_ROOT;
    cfg.target_count = 0;
    cfg.targets = NULL;

    int i = 1;
    while (i < argc) {
        const char *arg = argv[i];

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_usage(argv[0]);
            exit(0);
        }

        if (strcmp(arg, "--seconds") == 0 || strcmp(arg, "--max-total-time") == 0) {
            if (i + 1 >= argc) {
                die("%s requires a value", arg);
            }

            long value = parse_positive_long(arg, argv[i + 1]);
            if (value > INT_MAX) {
                die("%s value too large", arg);
            }

            cfg.seconds = (int)value;
            i += 2;
            continue;
        }

        if (strcmp(arg, "--max-len") == 0) {
            if (i + 1 >= argc) {
                die("%s requires a value", arg);
            }

            long value = parse_positive_long(arg, argv[i + 1]);
            if (value > INT_MAX) {
                die("%s value too large", arg);
            }

            cfg.max_len = (int)value;
            i += 2;
            continue;
        }

        if (strcmp(arg, "--out") == 0) {
            if (i + 1 >= argc) {
                die("%s requires a value", arg);
            }

            cfg.out_root = argv[i + 1];
            i += 2;
            continue;
        }

        if (strcmp(arg, "--no-build") == 0) {
            cfg.build_first = false;
            i += 1;
            continue;
        }

        if (strcmp(arg, "--") == 0) {
            i += 1;
            break;
        }

        if (arg[0] == '-') {
            die("unknown option: %s", arg);
        }

        break;
    }

    if (i >= argc) {
        print_usage(argv[0]);
        die("no fuzz targets provided");
    }

    cfg.target_count = argc - i;
    cfg.targets = (const char **)&argv[i];

    return cfg;
}

static void init_run_dirs(const Config *cfg) {
    char run_id[128];

    make_run_id(run_id, sizeof(run_id));

    mkdir_p(cfg->out_root);

    checked_snprintf(g_run_dir, sizeof(g_run_dir), "%s/%s", cfg->out_root, run_id);
    checked_snprintf(g_logs_dir, sizeof(g_logs_dir), "%s/logs", g_run_dir);
    checked_snprintf(g_summary_path, sizeof(g_summary_path), "%s/summary.md", g_run_dir);

    mkdir_p(g_run_dir);
    mkdir_p(g_logs_dir);

    FILE *f = fopen(g_summary_path, "w");
    if (f == NULL) {
        die("failed to create summary %s: %s", g_summary_path, strerror(errno));
    }

    time_t now = time(NULL);
    char now_iso[64];
    iso_time_local(now, now_iso, sizeof(now_iso));

    fprintf(f, "# SAR local fuzz run\n\n");
    fprintf(f, "- Run directory: `%s`\n", g_run_dir);
    fprintf(f, "- Logs directory: `%s`\n", g_logs_dir);
    fprintf(f, "- Started: `%s`\n", now_iso);
    fprintf(f, "- Max total time per target: `%d` seconds\n", cfg->seconds);
    fprintf(f, "- Max generated input length: `%d` bytes\n", cfg->max_len);
    fprintf(f, "- Target count: `%d`\n", cfg->target_count);
    fprintf(f, "- Build before run: `%s`\n\n", cfg->build_first ? "yes" : "no");

    fprintf(f, "## Targets\n\n");
    for (int i = 0; i < cfg->target_count; i++) {
        fprintf(f, "- `%s`\n", cfg->targets[i]);
    }
    fprintf(f, "\n");

    fclose(f);
}

static void init_jobs(Job *jobs, const Config *cfg) {
    for (int i = 0; i < cfg->target_count; i++) {
        jobs[i].target = cfg->targets[i];
        jobs[i].pid = -1;
        jobs[i].pgid = -1;
        jobs[i].exit_code = -1;
        jobs[i].finished = false;
        jobs[i].started_at = 0;
        jobs[i].ended_at = 0;

        checked_snprintf(
            jobs[i].log_path,
            sizeof(jobs[i].log_path),
            "%s/%s.run.log",
            g_logs_dir,
            jobs[i].target
        );

        checked_snprintf(
            jobs[i].build_log_path,
            sizeof(jobs[i].build_log_path),
            "%s/%s.build.log",
            g_logs_dir,
            jobs[i].target
        );
    }
}

static void build_targets(Job *jobs, const Config *cfg) {
    if (!cfg->build_first) {
        append_summary("## Build phase\n\nSkipped because `--no-build` was used.\n\n");
        return;
    }

    append_summary("## Build phase\n\n");

    for (int i = 0; i < cfg->target_count; i++) {
        Job *job = &jobs[i];

        printf("building target %s\n", job->target);
        append_summary("- `%s`: building, log `%s`\n", job->target, job->build_log_path);

        char *const argv[] = {
            "cargo",
            "+nightly",
            "fuzz",
            "build",
            (char *)job->target,
            NULL
        };

        int rc = run_cmd_logged_argv(argv, job->build_log_path);

        append_summary("  - build exit: `%d` (%s)\n", rc, exit_description(rc));

        if (rc != 0) {
            die("build failed for target %s; see %s", job->target, job->build_log_path);
        }

        if (g_shutdown_requested) {
            die("shutdown requested during build phase");
        }
    }

    append_summary("\n");
}

static void start_job(Job *job, const Config *cfg) {
    pid_t pid = fork();

    if (pid < 0) {
        die("fork failed for target %s: %s", job->target, strerror(errno));
    }

    if (pid == 0) {
        restore_default_signal_handlers_for_child();

        /*
         * Make cargo-fuzz the leader of its own process group.
         * The libFuzzer binary spawned by cargo-fuzz should inherit this group.
         * Killing -pgid should terminate cargo and its fuzz child.
         */
        if (setpgid(0, 0) != 0) {
            _exit(111);
        }

        int fd = open(job->log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            _exit(112);
        }

        if (dup2(fd, STDOUT_FILENO) < 0) {
            _exit(113);
        }

        if (dup2(fd, STDERR_FILENO) < 0) {
            _exit(114);
        }

        close(fd);

        char max_total_arg[64];
        char max_len_arg[64];

        checked_snprintf(
            max_total_arg,
            sizeof(max_total_arg),
            "-max_total_time=%d",
            cfg->seconds
        );

        checked_snprintf(
            max_len_arg,
            sizeof(max_len_arg),
            "-max_len=%d",
            cfg->max_len
        );

        /*
         * Important:
         * Do not pass fuzz/corpus/<target> explicitly here.
         * cargo-fuzz already supplies its default corpus directory.
         */
        execlp(
            "cargo",
            "cargo",
            "+nightly",
            "fuzz",
            "run",
            job->target,
            "--",
            max_total_arg,
            max_len_arg,
            (char *)NULL
        );

        _exit(127);
    }

    if (setpgid(pid, pid) != 0 && errno != EACCES && errno != ESRCH) {
        kill(pid, SIGTERM);
        die("setpgid failed for target %s pid %ld: %s",
            job->target,
            (long)pid,
            strerror(errno));
    }

    job->pid = pid;
    job->pgid = pid;
    job->started_at = time(NULL);
    job->finished = false;

    char iso[64];
    iso_time_local(job->started_at, iso, sizeof(iso));

    printf("started target %-40s pid=%ld pgid=%ld log=%s\n",
           job->target,
           (long)job->pid,
           (long)job->pgid,
           job->log_path);

    append_summary(
        "- `%s`: started pid `%ld`, pgid `%ld` at `%s`, log `%s`\n",
        job->target,
        (long)job->pid,
        (long)job->pgid,
        iso,
        job->log_path
    );
}

static void write_job_summary(const Job *job) {
    char started[64];
    char ended[64];

    iso_time_local(job->started_at, started, sizeof(started));
    iso_time_local(job->ended_at, ended, sizeof(ended));

    bool has_error = file_contains_indicator(job->log_path, "ERROR:");
    bool has_panic = file_contains_indicator(job->log_path, "panicked at");
    bool has_crash = file_contains_indicator(job->log_path, "Test unit written to");
    bool has_deadly = file_contains_indicator(job->log_path, "libFuzzer: deadly signal");
    bool has_done = file_contains_indicator(job->log_path, "DONE");
    long done_runs = extract_done_runs_from_log(job->log_path);

    append_summary("### `%s`\n\n", job->target);
    append_summary("- PID: `%ld`\n", (long)job->pid);
    append_summary("- PGID: `%ld`\n", (long)job->pgid);
    append_summary("- Started: `%s`\n", started);
    append_summary("- Ended: `%s`\n", ended);
    append_summary("- Exit code: `%d` (%s)\n", job->exit_code, exit_description(job->exit_code));
    append_summary("- Log: `%s`\n", job->log_path);

    if (done_runs >= 0) {
        append_summary("- Done runs: `%ld`\n", done_runs);
    } else {
        append_summary("- Done runs: `not found`\n");
    }

    append_summary("- Log contains `DONE`: `%s`\n", has_done ? "yes" : "no");
    append_summary("- Log contains `ERROR:`: `%s`\n", has_error ? "yes" : "no");
    append_summary("- Log contains `panicked at`: `%s`\n", has_panic ? "yes" : "no");
    append_summary("- Log contains `libFuzzer: deadly signal`: `%s`\n", has_deadly ? "yes" : "no");
    append_summary("- Log contains crash artifact marker: `%s`\n\n", has_crash ? "yes" : "no");
}

static void poll_jobs(Job *jobs, const Config *cfg) {
    int remaining = cfg->target_count;
    bool termination_sent = false;
    bool kill_sent = false;
    time_t termination_time = 0;

    append_summary("## Run phase\n\n");

    for (int i = 0; i < cfg->target_count; i++) {
        start_job(&jobs[i], cfg);
    }

    append_summary("\n## Results\n\n");

    while (remaining > 0) {
        if (g_shutdown_requested && !termination_sent) {
            printf("\nshutdown requested by signal %d; sending SIGTERM to child process groups\n",
                   (int)g_shutdown_signal);

            append_summary(
                "\nRun interrupted by signal `%d`; sending `SIGTERM` to child process groups.\n\n",
                (int)g_shutdown_signal
            );

            terminate_process_groups(SIGTERM);
            termination_sent = true;
            termination_time = time(NULL);
        }

        if (termination_sent && !kill_sent) {
            time_t now = time(NULL);
            if (now - termination_time >= 3) {
                printf("sending SIGKILL to remaining child process groups\n");
                append_summary("Escalating to `SIGKILL` for remaining child process groups.\n\n");
                terminate_process_groups(SIGKILL);
                kill_sent = true;
            }
        }

        int status = 0;
        pid_t r = waitpid(-1, &status, WNOHANG);

        if (r == 0) {
            sleep(1);
            continue;
        }

        if (r < 0 && errno == EINTR) {
            continue;
        }

        if (r < 0 && errno == ECHILD) {
            /*
             * No more children. Mark any still-unfinished jobs as interrupted.
             */
            for (int i = 0; i < cfg->target_count; i++) {
                if (!jobs[i].finished) {
                    jobs[i].finished = true;
                    jobs[i].ended_at = time(NULL);
                    jobs[i].exit_code = g_shutdown_requested ? 143 : 127;
                    remaining--;
                    write_job_summary(&jobs[i]);
                }
            }
            break;
        }

        if (r < 0) {
            die("waitpid failed: %s", strerror(errno));
        }

        bool matched = false;

        for (int i = 0; i < cfg->target_count; i++) {
            Job *job = &jobs[i];

            if (!job->finished && job->pid == r) {
                job->finished = true;
                job->ended_at = time(NULL);

                if (WIFEXITED(status)) {
                    job->exit_code = WEXITSTATUS(status);
                } else if (WIFSIGNALED(status)) {
                    job->exit_code = 128 + WTERMSIG(status);
                } else {
                    job->exit_code = 126;
                }

                remaining--;
                matched = true;

                printf("finished target %-40s exit=%d remaining=%d\n",
                       job->target,
                       job->exit_code,
                       remaining);

                write_job_summary(job);
                break;
            }
        }

        if (!matched) {
            /*
             * This should not normally happen because each cargo-fuzz process is
             * the direct child tracked by a Job. If it does happen, continue
             * polling rather than losing the whole run.
             */
            printf("reaped untracked child pid=%ld\n", (long)r);
        }
    }
}

static int final_exit_code(const Job *jobs, int job_count) {
    int rc = 0;

    for (int i = 0; i < job_count; i++) {
        if (jobs[i].exit_code != 0) {
            rc = 1;
        }
    }

    if (g_shutdown_requested) {
        rc = 130;
    }

    return rc;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);

    Config cfg = parse_args(argc, argv);

    init_run_dirs(&cfg);

    Job *jobs = calloc((size_t)cfg.target_count, sizeof(Job));
    if (jobs == NULL) {
        die("calloc failed");
    }

    init_jobs(jobs, &cfg);

    g_jobs = jobs;
    g_job_count = cfg.target_count;

    install_signal_handlers();

    printf("SAR fuzz runner\n");
    printf("run dir: %s\n", g_run_dir);
    printf("summary: %s\n", g_summary_path);
    printf("targets: %d\n", cfg.target_count);
    printf("seconds: %d\n", cfg.seconds);
    printf("max_len: %d\n", cfg.max_len);

    build_targets(jobs, &cfg);

    if (!g_shutdown_requested) {
        poll_jobs(jobs, &cfg);
    }

    time_t ended_at = time(NULL);
    char ended_iso[64];
    iso_time_local(ended_at, ended_iso, sizeof(ended_iso));

    append_summary("## Final status\n\n");
    append_summary("- Ended: `%s`\n", ended_iso);

    if (g_shutdown_requested) {
        append_summary("- Interrupted by signal: `%d`\n", (int)g_shutdown_signal);
    } else {
        append_summary("- Interrupted: `no`\n");
    }

    int rc = final_exit_code(jobs, cfg.target_count);
    append_summary("- Runner exit code: `%d`\n\n", rc);

    printf("summary written to: %s\n", g_summary_path);

    free(jobs);

    return rc;
}
