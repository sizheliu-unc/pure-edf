#include <scx/common.bpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
char _license[] SEC("license") = "GPL";

// #define EDF_DEBUG

#ifdef EDF_DEBUG
    #define printd bpf_printk
#else
    #define printd(...)
#endif
#define DEFAULT_DEADLINE 0xFFFFFFFFFFFFFFFFULL

#define SCHED_NORMAL		0
#define SCHED_FIFO		1
#define SCHED_RR		2
#define SCHED_BATCH		3
/* SCHED_ISO: reserved but not implemented yet */
#define SCHED_IDLE		5
#define SCHED_DEADLINE		6
#define SCHED_EXT		7

const volatile u64 nr_cpu_ids;
struct task_ctx {
    u64 deadline;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, s32);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");


UEI_DEFINE(uei);

/*
 * define global variables
 */

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dsq_insert_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_simple only supported global FIFO scheduling, then we could just
 * use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0 // GLOBAL_DSQ has been taken, here we use shared to mean global


static u64 get_deadline(pid_t pid)
{
    struct task_ctx *tctx;

	if (!(tctx = bpf_map_lookup_elem(&task_ctx_stor, &pid))) {
		return DEFAULT_DEADLINE;
	}
	return tctx->deadline;
}
void BPF_STRUCT_OPS(edf_quiescent, struct task_struct *p, u64 deq_flags) {
    printd("[BLOCKED] Taks %lu is blocked!\n", p->pid);
}

int BPF_STRUCT_OPS(edf_yield, struct task_struct *from, struct task_struct *to)
{
    if (to) {
        printd("Yielding to another task: %lu, policy: %u\n", to->pid, to->policy);
        return 0;
    }
    u64 deadline = get_deadline(from->pid);
    struct task_struct *q;
    bool preempt = false;
    if (scx_bpf_dsq_nr_queued(SHARED_DSQ)) {
        bpf_for_each(scx_dsq, q, SHARED_DSQ, 0) {
            u64 cur_ddl = get_deadline(q->pid);
            if (cur_ddl < deadline) {
                preempt = true;
            }
            break;
        }
    }
    if (preempt) {
        from->scx.slice = 0;
    }
    return 0;   
}

// int BPF_STRUCT_OPS(update_deadline, pid_t pid, u64 deadline)
// {
//     s32 err = bpf_map_update_elem(&task_ctx_stor, pid, &deadline, BPF_ANY);
//     if (err != 0) {
//         return err;
//     }
//     struct task_struct * p = bpf_task_from_pid(pid);
//     s32 cpu = -1;
//     if ((cpu = scx_bpf_task_cpu(p)) >= 0) {
//         scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
//     }
//     return 0;
// }

void BPF_STRUCT_OPS(edf_enqueue, struct task_struct *p, u64 enq_flags)
{
    u64 deadline = get_deadline(p->pid);
    printd("[Enqueue] Task: %u, ddl: %u\n", p->pid, deadline);
    struct task_struct *q;
    /* 
     * Quickly do a check if there is anything on the shared dsq that has higher prio.
     * If so, then we simply enqueue into the shared dsq, and wait for dispatch. Otherwise,
     * we proceed to attempt to pick an idle CPU.
     */
    if (scx_bpf_dsq_nr_queued(SHARED_DSQ)) {
        bpf_for_each(scx_dsq, q, SHARED_DSQ, 0) {
            u64 cur_ddl = get_deadline(q->pid);
            if (cur_ddl < deadline) {
                scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_INF, DEFAULT_DEADLINE - deadline, enq_flags);
                printd("Task: %u is equeue to shared dsq, higher prio task is found on shared\n", p->pid);
                return;
            }
            break;
        }
    }
    u64 max_ddl = deadline;
    u32 cur_cpu;
    s32 cpu;
    if (enq_flags & SCX_ENQ_REENQ) {
        printd("Reenqueue task!\n");
    }

    if ((cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0)) >= 0) {
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_INF, enq_flags);
        scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
        // scx_bpf_kick_cpu(cpu, 0);
        printd("Task: %u is dispatched to cpu: %u, since the cpu is idle (scx_bpf_pick_idle_cpu)\n", p->pid, cpu);
        return;
    }
    cpu = -1;
    s32 start = bpf_cpumask_first(p->cpus_ptr);
    bpf_for(cur_cpu, start, nr_cpu_ids) {
        if (!bpf_cpumask_test_cpu(cur_cpu, p->cpus_ptr)) {
            continue;
        }
        /*
         * Check if there is any other SCX tasks (EDF tasks) on the local dsq of the CPU.
         * It is also possible that the task is running, and thus not on any DSQ at this point.
         */
        u32 len = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cur_cpu);
        struct task_struct* curr = scx_bpf_cpu_rq(cur_cpu)->curr;
        printd("cpu %u has %u tasks\n", cur_cpu, len);
        /*
         * If this CPU is simply idle, we can directly enqueue onto the CPU's dsq.
         */
        if (!curr || (curr->policy == SCHED_NORMAL && len == 0 && !(curr->flags & PF_KTHREAD))) {
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cur_cpu, SCX_SLICE_INF, enq_flags);
            scx_bpf_kick_cpu(cur_cpu, SCX_KICK_IDLE);
            printd("Task: %u is dispatched to cpu: %u, since the cpu is idle (curr is null)\n", p->pid, cur_cpu);
            return;
        }
        /*
         * It is also possible that the current task is ourselves (in case of prio change), in that case, we can just take this CPU.
         */
        u64 cur_ddl = DEFAULT_DEADLINE;
        if (len == 0 && curr == p) {
            
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cur_cpu, SCX_SLICE_INF, enq_flags); 
            printd("Task: %u is dispatched to cpu: %u, since the cpu is idle (dsq empty)\n", p->pid, cur_cpu);
            return;
        }
        /*
            * If it is some other SCHED_EXT task, then we must pick the one with the greatest deadline.
            */
        if (curr != p && curr->policy == SCHED_EXT) {
            cur_ddl = get_deadline(curr->pid);
            printd("Task: %u exist on cpu %u, ddl: %u\n", curr->pid, cur_cpu, cur_ddl);
            if (cur_ddl > max_ddl) {
                cpu = cur_cpu;
                max_ddl = cur_ddl;
            }
            continue;
        }
        // struct task_struct *q;
        
        // bpf_for_each(scx_dsq, q, SCX_DSQ_LOCAL_ON | cur_cpu, 0) {
        //     u64 cur_ddl = get_deadline(q->pid);
        //     printd("Task: %u exist on cpu %u, ddl: %u\n", q->pid, cur_cpu, cur_ddl);
        //     if (cur_ddl > max_ddl) {
        //         cpu = cur_cpu;
        //         max_ddl = cur_ddl;
        //     }
        // }
        
    }
    if (cpu >= 0) {
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_INF, enq_flags);
        scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
        printd("Task: %u is dispatched to cpu: %u, since the cpu is running lower prio job\n", p->pid, cpu);
        return;
    }
enq_global:    
    scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_INF, DEFAULT_DEADLINE - deadline, enq_flags);
    printd("Task: %u is equeue to shared dsq, since no available cpu is found\n", p->pid);
}

// void BPF_STRUCT_OPS(edf_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
// {
//     if (cpu == 2 || cpu == 4) {
//         printd("CPU %u is acquired\n", cpu);
//     }
//     return;
// }

// void BPF_STRUCT_OPS(edf_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
// {
//     if (cpu == 2 || cpu == 4) {
//         printd("CPU %u is released, reason: %u\n", cpu, args->reason);
//     }
//     return;
// }

void BPF_STRUCT_OPS(edf_runnable, struct task_struct *p, u64 enq_flags){
    printd("[WAKE] task %lu woke up!\n", p->pid);
}

s32 BPF_STRUCT_OPS(edf_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    printd("Select CPU for task: %lu!\n", p->pid);
    u64 deadline = get_deadline(p->pid);
    /*
     * If there are any task having smaller deadline than us, we cannot run
     * and thus instead enqueue ourselves and wait for a dispatch call, or
     * be enqueued into some other CPU.
     */
    if (scx_bpf_dsq_nr_queued(SHARED_DSQ)) {
        struct task_struct *q;
        bpf_for_each(scx_dsq, q, SHARED_DSQ, 0) {
            u64 cur_ddl = get_deadline(q->pid);
            if (cur_ddl < deadline) {
                p->scx.slice = 0;
            }
            break;
        }
    }
    bool is_idle = false;
    s32 dfl_cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
    if (dfl_cpu >= 0 && is_idle) {
        printd("[SELECT] Idle cpu is found on cpu %u!\n", dfl_cpu);
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | dfl_cpu, SCX_SLICE_INF, SCX_ENQ_WAKEUP | SCX_ENQ_CPU_SELECTED);
        return dfl_cpu;
    }
    /*
     * If idle cpu is not found, we have to find one with the largest deadline
     */
    s32 cpu = -1;

    u64 max_ddl = 0;
    s32 start = bpf_cpumask_first(p->cpus_ptr);
    s32 cur_cpu;
    bpf_for(cur_cpu, start, nr_cpu_ids) {
        if (!bpf_cpumask_test_cpu(cur_cpu, p->cpus_ptr)) {
            continue;
        }
        /*
         * Check if there is any other SCX tasks (EDF tasks) on the local dsq of the CPU.
         * It is also possible that the task is running, and thus not on any DSQ at this point.
         */
        u32 len = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cur_cpu);
        struct rq* run_q = scx_bpf_cpu_rq(cur_cpu);
        
        struct task_struct* curr = run_q->curr;
        printd("[SELECT] cpu %u has %u tasks\n", cur_cpu, len);
        /*
         * If this CPU is simply idle, we can directly enqueue onto the CPU's dsq.
         */
        if (!curr || (len == 0 && curr == p)) {
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cur_cpu, SCX_SLICE_INF, SCX_ENQ_WAKEUP | SCX_ENQ_CPU_SELECTED);
            printd("[SELECT] Task: %u is dispatched to cpu: %u, since the cpu is idle (curr is null)\n", p->pid, cur_cpu);
            return cur_cpu;
        }
        // /*
        //  * It is also possible that the current task is ourselves (in case of prio change), in that case, we can just take this CPU.
        //  */
        // if (len == 0 && curr == p) {
        //     scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cur_cpu, SCX_SLICE_INF, SCX_ENQ_WAKEUP | SCX_ENQ_CPU_SELECTED); 
        //     printd("[SELECT] Task: %u is dispatched to cpu: %u, since the cpu is idle (dsq empty)\n", p->pid, cur_cpu);
        //     return cur_cpu;
        // }

        if (curr->policy == SCHED_NORMAL && len == 0 && !(curr->flags & PF_KTHREAD)) {
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cur_cpu, SCX_SLICE_INF, SCX_ENQ_WAKEUP | SCX_ENQ_CPU_SELECTED | SCX_ENQ_PREEMPT); 
            printd("[SELECT] Task: %u is dispatched to cpu: %u, since the cpu is running SCHED_NORMAL\n", p->pid, cur_cpu);
            return cur_cpu;
        }
        /*
         * If it is some other SCHED_EXT task, then we must pick the one with the greatest deadline.
         */
        if (curr != p && curr->policy == SCHED_EXT) {
            u64 cur_ddl = get_deadline(curr->pid);
            printd("[SELECT] Task: %u exist on cpu %u, ddl: %u\n", curr->pid, cur_cpu, cur_ddl);
            if (cur_ddl > max_ddl) {
                cpu = cur_cpu;
                max_ddl = cur_ddl;
            }
            continue;
        }
        // struct task_struct *q;
        
        // bpf_for_each(scx_dsq, q, SCX_DSQ_LOCAL_ON | cur_cpu, 0) {
        //     u64 cur_ddl = get_deadline(q->pid);
        //     printd("Task: %u exist on cpu %u, ddl: %u\n", q->pid, cur_cpu, cur_ddl);
        //     if (cur_ddl > max_ddl) {
        //         cpu = cur_cpu;
        //         max_ddl = cur_ddl;
        //     }
        // }
        
    }
    if (cpu >= 0 && deadline < max_ddl) {
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_INF, SCX_ENQ_WAKEUP | SCX_ENQ_CPU_SELECTED | SCX_ENQ_PREEMPT);
        printd("[SELECT] Task: %u is dispatched to cpu: %u, since the cpu is running lower prio job\n", p->pid, cpu);
        return cpu;
    }
    p->scx.slice = 0;
    scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_INF, DEFAULT_DEADLINE - deadline, SCX_ENQ_WAKEUP);
    printd("[SELECT] Task: %u is equeue to shared dsq, since no available cpu is found\n", p->pid);
    if (cpu < 0) {
        cpu = dfl_cpu;
    }
    return cpu;
}
void BPF_STRUCT_OPS(edf_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	/*
     * We have lost the control of this cpu: we cannot run on this cpu for now
     * In that case, to make sure we do not lose control over the tasks already in 
     * the local dsq, we reenqueue them, so that they either find some other CPU to run on,
     * or they are enqueued into the shared dsq.
     * 
	 */
	scx_bpf_reenqueue_local();
    printd("CPU %u is released, reason: %u, next prio: %u, pid: %lu\n", cpu, args->reason, args->task->prio, args->task->pid);
}

bool BPF_STRUCT_OPS(edf_core_sched_before, struct task_struct *a, struct task_struct *b)
{
    return get_deadline(a->pid) <= get_deadline(b->pid);
}

void BPF_STRUCT_OPS(edf_dispatch, s32 cpu, struct task_struct *prev)
{
	bool moved = scx_bpf_dsq_move_to_local(SHARED_DSQ);
    if (moved) {
        printd("Dispatch!\n");
    }
}

// void BPF_STRUCT_OPS(edf_stopping, struct task_struct *p, bool runnable)
// {
//     printd("task: %u is stopping\n", p->pid);
//     // if (!runnable) {
//     //     return;
//     // }
//     // u64 cur_dsq = p->scx.dsq->id;
//     // struct bpf_iter_scx_dsq *it;
//     // bpf_iter_scx_dsq_new(it, cur_dsq, 0);
//     // scx_bpf_dsq_move(it, p, SHARED_DSQ, 0);
//     // bpf_iter_scx_dsq_destroy(it);
// }

s32 BPF_STRUCT_OPS_SLEEPABLE(edf_init)
{
    printd("EDF scheduler enabled!\n");
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(edf_exit, struct scx_exit_info *ei)
{
    scx_bpf_destroy_dsq(SHARED_DSQ);
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(edf_ops,
           .runnable          = (void *)edf_runnable,
	       .enqueue			  = (void *)edf_enqueue,
           .select_cpu        = (void *)edf_select_cpu,
           .quiescent         = (void*)edf_quiescent,
	       .dispatch		  = (void *)edf_dispatch,
           .core_sched_before = (void* )edf_core_sched_before,
        //    .stopping        = (void *)edf_stopping,
	       .init			  = (void *)edf_init,
	       .exit			  = (void *)edf_exit,
           .flags             = SCX_OPS_SWITCH_PARTIAL,
        //    .cpu_acquire     = (void *)edf_cpu_acquire,
           .cpu_release       = (void *)edf_cpu_release,
           .yield             = (void *)edf_yield,
	       .name			  = "edf");
