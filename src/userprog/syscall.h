#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H


extern struct lock global_lock; // filesystem functions will be mutually exclusive


void syscall_init (void);

// wrappers
void exit_wrapper(struct intr_frame *f);
void exec_wrapper(struct intr_frame *f);
void wait_wrapper(struct intr_frame *f);
void halt_wrapper(struct intr_frame *f);
void create_wrapper(struct intr_frame *f);
void remove_wrapper(struct intr_frame *f);
void open_wrapper(struct intr_frame *f);
void filesize_wrapper(struct intr_frame *f);
void read_wrapper(struct intr_frame *f);
void write_wrapper(struct intr_frame *f);
void close_wrapper(struct intr_frame *f);


void halt ();
int wait (tid_t t);
void exit (int status);
tid_t exec (const char *file);
int write(int fd, const void *buffer, unsigned size);
int read(int fd, void *buffer, unsigned size);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (struct files_opened *file);
void seek (struct intr_frame *f);
void tell(struct intr_frame *f);
int close (int fd);


#endif /* userprog/syscall.h */