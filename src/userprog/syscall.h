#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H


extern struct lock global_lock; // filesystem functions will be mutually exclusive


void syscall_init (void);

// wrappers
void system_exit_wrapper(struct intr_frame *f);
void system_exec_wrapper(struct intr_frame *f);
void system_wait_wrapper(struct intr_frame *f);
void system_halt_wrapper(struct intr_frame *f);

void system_create_wrapper(struct intr_frame *f);
void system_remove_wrapper(struct intr_frame *f);
void system_open_wrapper(struct intr_frame *f);
void system_filesize_wrapper(struct intr_frame *f);
void system_read_wrapper(struct intr_frame *f);
void system_write_wrapper(struct intr_frame *f);
void system_close_wrapper(struct intr_frame *f);
// void system_tell_wrapper(struct intr_frame *f);
// void system_seek_wrapper(struct intr_frame *f);

// fun_to call file & system call

void sys_halt ();
int sys_wait (tid_t t);
void sys_exit (int status);
tid_t sys_exec (const char *file);

int sys_write(int fd, const void *buffer, unsigned size);
int sys_read(int fd, void *buffer, unsigned size);
bool sys_create (const char *file, unsigned initial_size);
bool sys_remove (const char *file);
int sys_open (const char *file);
int sys_filesize (struct files_opened *file);
void sys_seek (struct intr_frame *f);
void sys_tell(struct intr_frame *f);
int sys_close (int fd);


#endif /* userprog/syscall.h */