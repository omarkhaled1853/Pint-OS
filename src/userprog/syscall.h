#include <stdbool.h>
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

/* ======================================== ADDED ======================================== */
// Wrappers
void halt_wrapper (struct intr_frame *f); // Halt wrapper
void exit_wrapper (struct intr_frame *f); // Exit wrapper
void exec_wrapper (struct intr_frame *f); // Exec wrapper
void wait_wrapper (struct intr_frame *f); // Wait wrapper
void create_wrapper (struct intr_frame *f); // Create file wrapper
void remove_wrapper (struct intr_frame *f); // Remove file wrapper
void open_wrapper (struct intr_frame *f); // Open file wrapper
void filesize_wrapper (struct intr_frame *f); // File size wrapper
void read_wrapper (struct intr_frame *f); // Read file wrapper
void write_wrapper (struct intr_frame *f); // Write file wrapper
void seek_wrapper (struct intr_frame *f); // Seek file wrapper
void tell_wrapper (struct intr_frame *f); // Tell file wrapper
void close_wrapper (struct intr_frame *f); // Close file wrapper

/* ======================================== ADDED ======================================== */
// System calls
void halt (void); // Halt implementation
void exit (int status); // Exit implementation
tid_t exec (const char *cmd_line); // Exec implementation
int wait (tid_t tid); // Wait implementation
bool create (const char *file, unsigned initial_size); // Create file implementation
bool remove (const char *file); // Remove file implementation
int open (const char *file); // Open file implementation
int read (int fd, void *buffer, unsigned size); // Read file implementation
int filesize (int fd); // File size implementation
int write (int fd, const void *buffer, unsigned size); // write file implementation
void seek (int fd, unsigned position); // seek file implementation
signed tell (int fd); // Tell file implementation
void close (int fd); // Close file implementation

#endif /* userprog/syscall.h */
