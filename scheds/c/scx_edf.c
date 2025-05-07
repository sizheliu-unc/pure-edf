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
#define ACK_PATH "/tmp/pure-edf-ack"

static bool verbose;
static volatile int exit_req;
static volatile int fd;
static volatile int fd_ack;

struct attr_struct {
    pid_t pid;
    uint64_t abs_deadline;
};

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

void update_ddl(pid_t pid, __u64 ddl, struct scx_edf* skel) {
    printf("pid: %d, ddl: %llu is being updated\n", pid, ddl);
    int ret = bpf_map_update_elem(bpf_map__fd(skel->maps.task_ctx_stor), &pid, &ddl, BPF_ANY);
    struct attr_struct ret_val = {pid, ddl};
    
    if (ret < 0) {
        ret_val.abs_deadline = 0;
        write(fd_ack, &ret_val, sizeof(struct attr_struct));
        perror("Update deadline failed");
        return;
    }
    write(fd_ack, &ret_val, sizeof(struct attr_struct));
}

void* read_thread(void* arg) {
    struct scx_edf* skel = (struct scx_edf*) arg;
    struct attr_struct edf_attr;
    ssize_t num_read;

    while (!exit_req) {
        num_read = read(fd, &edf_attr, sizeof(edf_attr));
        
        if (num_read == -1) {
            if (errno == EBADF || errno == EINTR) {
                // Check if we should exit
                if (exit_req) break;
                continue;
            }
            perror("read error");
            exit(EXIT_FAILURE);
        }
        
        if (num_read == 0) {
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

        if (num_read != sizeof(struct attr_struct)) {
            printf("cannot find deadline! This request is ignored\n");
            continue;
        }
        
        update_ddl(edf_attr.pid, edf_attr.abs_deadline, skel);
    }
    
    return NULL;
}

int main(int argc, char **argv)
{
    int nr_cpus = 0;
    int start_cpu = 8;
    if (argc == 2) {
        nr_cpus = atoi(argv[1]);
    }
    if (argc == 3) {
        start_cpu = atoi(argv[1]);
        nr_cpus = atoi(argv[2]);
    }
    int cpus_allowed = 0;
    for (int i = start_cpu; i < start_cpu + nr_cpus; i++) {
        cpus_allowed |= (1 << i);
    }

    // pthread_t thread;
    // if (mkfifo(FIFO_PATH, 0666) == -1 && errno != EEXIST) {
    //     perror("mkfifo failed");
    //     exit(EXIT_FAILURE);
    // }
    // if (mkfifo(ACK_PATH, 0666) == -1 && errno != EEXIST) {
    //     perror("mkfifo failed");
    //     exit(EXIT_FAILURE);
    // }
    // fd = open(FIFO_PATH, O_RDONLY | O_CREAT, 0622);
    // fd_ack = open(ACK_PATH, O_WRONLY | O_CREAT, 0666);
    // if (fd == -1) {
    //     perror("open failed");
    //     exit(EXIT_FAILURE);
    // }
	struct scx_edf *skel;
	struct bpf_link *link;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(edf_ops, scx_edf);
    printf("Opened.\n");
    skel->rodata->nr_cpu_ids = libbpf_num_possible_cpus();
    skel->rodata->cpu_bitmask = cpus_allowed;

	SCX_OPS_LOAD(skel, edf_ops, scx_edf, uei);
    printf("Loaded.\n");
    // if (pthread_create(&thread, NULL, read_thread, (void*) skel) != 0) {
    //     perror("pthread_create failed");
    //     close(fd);
    //     exit(EXIT_FAILURE);
    // }
	link = SCX_OPS_ATTACH(skel, edf_ops, scx_edf);
    printf("Attached.\n");
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
