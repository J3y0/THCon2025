#define _GNU_SOURCE
#include "packer.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

unsigned char encrypted[];
unsigned int encrypted_len;

int child_main(char *argv[], int *idx_key) {
  errno = 0;
  int res = ptrace(PTRACE_TRACEME, 0, 0, 0);
  if (errno && res == -1) {
    perror("ptrace(TRACEME) failed");
    return 1;
  }

  unsigned int decrypted_len = encrypted_len;
  unsigned char *decrypted = malloc(decrypted_len);
  unsigned int i = 0;
  while (1) {
    decrypt_block(encrypted + i, decrypted + i, *idx_key);
    asm volatile("int3"); // SIGTRAP here to access rax (return value)

    i += 1 << 4;
    if (i >= encrypted_len) {
      break;
    }
  }

  // Execute decrypted payload
  int tmp = memfd_create("targ_file", FD_CLOEXEC);
  write(tmp, decrypted, decrypted_len);
  free(decrypted);

  char *const envp2[] = {NULL};
  fexecve(tmp, argv, envp2);

  perror("fexecve() failed");
  close(tmp);
  return 0;
}

int main(int argc, char *argv[]) {
  (void)argc;
  int wstatus;
  int idx_key = 25; // Define here, so father knows address of this var

  pid_t pid_son = fork();
  if (pid_son == -1) {
    perror("fork() failed");
    exit(1);
  } else if (pid_son == 0) {
    // In child process
    exit(child_main(argv, &idx_key));
  }

  // In father process
  // Suspend father process and waits for child
  while (1) {
    wait(&wstatus);
    if (WIFEXITED(wstatus)) {
      break;
    }

    // Retrieve rax (that holds return of decrypt_block in child process when
    // stopped)
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid_son, 0, &regs) == -1) {
      perror("Can't read child process registers");
      return 1;
    }

    int cur_idx_key = ptrace(PTRACE_PEEKDATA, pid_son, &idx_key, 0);
    // Compute next idx_key
    int next_idx_key = ((regs.rax + cur_idx_key) * 25) % SIZE_KEYS_TABLE;
    // Set value in child process memory
    ptrace(PTRACE_POKEDATA, pid_son, &idx_key, next_idx_key);

    ptrace(PTRACE_CONT, pid_son, NULL, 0);
  }

  return 0;
}
