#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <scx/common.h>
#include <pthread.h>
#include <sys/stat.h> 
#include "scx_edf.bpf.skel.h"

#define FIFO_PATH "/tmp/pure-edf"

static bool verbose;
static volatile int exit_req;
static volatile int fd;
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int edf)
{
	exit_req = 1;
}

void update_ddl(pid_t pid, u64 ddl, struct scx_edf* skel) {
    printf("pid: %lu, ddl: %llu is being updated\n", pid, ddl);
    int ret = bpf_map_update_elem(bpf_map__fd(skel->maps.task_ctx_stor), &pid, &ddl, BPF_ANY);
    if (ret < 0) {
        perror("Update deadline failed");
        return;
    }
    
}

void* read_thread(void* arg) {
    struct scx_edf* skel = (struct scx_edf*) arg;
    char buffer[1024];
    ssize_t num_read;

    while (!exit_req) {
        num_read = read(fd, buffer, sizeof(buffer) - 1);
        
        if (num_read == -1) {
            if (errno == EBADF || errno == EINTR) {
                // Check if we should exit
                if (exit_req) break;
                continue;
            }
            perror("read error");
            exit(EXIT_FAILURE);
        } else if (num_read == 0) {
            // Writer closed, reopen FIFO
            close(fd);
            fd = open(FIFO_PATH, O_RDONLY | O_CREAT, 0622);
            if (fd == -1) {
                if (exit_req) break;  // Check if we're exiting
                perror("reopen failed");
                exit(EXIT_FAILURE);
            }
            continue;
        }
        
        buffer[num_read] = '\0';
        char *endptr;
        printf("Received: %s\n", buffer);
        u32 pid = strtoul(buffer, &endptr, 10);
        int i = 0;
        while (endptr[i] != ' ' && endptr[i] != '\0') {
            i++;
        }
        if (endptr[i] == '\0') {
            printf("cannot find deadline! This request is ignored\n");
            continue;
        }
        u64 deadline = strtoull(endptr + i, &endptr, 10);
        printf("pid: %lu, ddl: %llu\n", pid, deadline);
        update_ddl(pid, deadline, skel);
    }
    
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t thread;
    if (mkfifo(FIFO_PATH, 0666) == -1 && errno != EEXIST) {
        perror("mkfifo failed");
        exit(EXIT_FAILURE);
    }
    fd = open(FIFO_PATH, O_RDONLY | O_CREAT, 0622);
    if (fd == -1) {
        perror("open failed");
        exit(EXIT_FAILURE);
    }
	struct scx_edf *skel;
	struct bpf_link *link;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(edf_ops, scx_edf);
    skel->rodata->nr_cpu_ids = libbpf_num_possible_cpus();

	SCX_OPS_LOAD(skel, edf_ops, scx_edf, uei);
    if (pthread_create(&thread, NULL, read_thread, (void*) skel) != 0) {
        perror("pthread_create failed");
        close(fd);
        exit(EXIT_FAILURE);
    }
	link = SCX_OPS_ATTACH(skel, edf_ops, scx_edf);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
        sleep(1);
	}
    close(fd);
	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_edf__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
        printf("restarting edf!\n");
		goto restart;
	return 0;
}
