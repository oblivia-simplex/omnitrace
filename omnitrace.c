#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <capstone/capstone.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define MAX_INST_LEN 15
/**
 * Quick and dirty PoC
 * borrowing a bit from https://github.com/dongrote/ptrace_singlestep/blob/master/singlestepper.c
 **/


void fprintf_wait_status (FILE *stream, int status) {
    if (WIFSTOPPED(status)) {
      fprintf(stream, "Child stopped: %d\n", WSTOPSIG(status));
    }
    if (WIFSTOPPED(status)) {
      fprintf(stream, "Child exited: %d\n", WEXITSTATUS(status));
    }
    if (WIFSIGNALED(status)) {
      fprintf(stream, "Child signaled: %d\n", WTERMSIG(status));
    }
    if (WCOREDUMP(status)) {
      fprintf(stream, "Core dumped.\n");
    }
}

int disas (uint8_t *buf) {
  
}

int ptrace_pc (int pid, u64 *rip)
{
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid, NULL, (void*)&regs)) {
    fprintf(stderr, "Error fetching registers from child process: %s\n",
        strerror(errno));
    return -1;
  }
  if (rip)
    *rip = regs.rip;
  return 0;
}


int step (pid_t pid) {
  int status;
  if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
    fprintf(stderr, "[X] Failed to singlestep pid %d\n", pid);
    exit(1);
  } else {
    waitpid(pid, &status, 0);
  
    /* peek at the instruction */


    return status;
  }
}

int main (int argc, char **argv) {

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <path to executable>\n", argv[0]);
    exit(1);
  }


  
  pid_t pid;
  int status;
  long orig_rax;

  pid = fork();

  if (pid == 0) {
    /* If in the child process, launch the executable. */
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execv(argv[1], argv+1);
  } else {
    /* Parent process */
    /* Set up the capstone instance */
    csh handle;
    cs_insn *d_inst;
    size_t count;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
      fprintf(stderr, "[X] Failed to open capstone instance. Exiting.\n");
      exit(1);
    }

    u64 rip = 0;
    
    union inst {
      u64 words[2];
      u8  buf[16];
    } inst;
    inst.words[0] = inst.words[1] = 0; 

    waitpid(pid, &status, 0);
    fprintf_wait_status(stderr, status);
    while (WIFSTOPPED(status)) {
      if (ptrace_pc(pid, &rip)) {
        break;
      }
      /* now read the instruction at RIP */
      inst.words[0] = ptrace(PTRACE_PEEKTEXT, pid, rip, NULL);
      inst.words[1] = ptrace(PTRACE_PEEKTEXT, pid, rip + sizeof(u64), NULL);
      size_t count;

      count = cs_disasm(handle, (u8 *) inst.buf, sizeof(inst.buf), 0, 0, &d_inst); 
      if (!count) {
        fprintf(stderr, "[X] Failed to disassemble instruction at %p: %lx%lx\n", 
            (void *) rip, inst.words[0], inst.words[1]);
      } else {
        fprintf(stderr, "[%p]\t %s\t %s\n", 
            (void *) rip,
            d_inst[0].mnemonic,
            d_inst[0].op_str);
        cs_free(d_inst, count);
      }


      status = step(pid);
    }
    fprintf_wait_status(stderr, status);
    fprintf(stderr, "Detaching...\n");
    ptrace(PTRACE_DETACH, pid, 0, 0);
  }

  return 0;   

}

