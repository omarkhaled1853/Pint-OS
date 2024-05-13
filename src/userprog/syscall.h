#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

/* ======================================== ADDED ======================================== */
// Wrappers
void halt_wrapper (struct intr_frame *f); // Halt wrapper
void exit_wrapper (struct intr_frame *f); // Exit wrapper
void  create_wrapper (struct intr_frame *f); // Create file wrapper
void remove_wrapper (struct intr_frame *f); // Remove file wrapper
void open_wrapper (struct intr_frame *f); // Open file wrapper
void filesize_wrapper (struct intr_frame *f); // File size wrapper
void read_wrapper (struct intr_frame *f); // Read file wrapper

/* ======================================== ADDED ======================================== */
// System calls
void halt (void); // Halt implementation
void exit (int status); // Exit implementation
bool create (const char *file, unsigned initial_size); // Create file implementation
bool remove (const char *file); // Remove file implementation
int open (const char *file); // Open file implementation
int filesize (int fd); // File size implementation


#endif /* userprog/syscall.h */
