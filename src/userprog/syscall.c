#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "userprog/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
/* ======================================== ADDED ======================================== */
static struct lock files_sync_lock; /* lock for synchronization between files */
int get_int(int **esp); /* get int from the stack */
char *get_char_ptr(char ***esp); /* get character pointer */
void *get_void_pointer(void ***esp); /* get void (generic) pointer */
void validate_void_ptr(const void *pt); /* check if the pointer is valid */
struct process_file *get_open_file(int fd); /* get opened file */

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  /* ======================================== ADDED ======================================== */
  // Initialize global lock
  lock_init(&files_sync_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  /* ======================================== ADDED ======================================== */
  // Check validity of pointer
  validate_void_ptr(f->esp);
  if(((*(int *)f->esp) < 0) || (*(int *)f->esp) > 12) {
    exit(-1);
  }

  printf ("system call!\n");
  
  int systemCallType = get_int(f->esp);
  switch (systemCallType)
  {
    case SYS_HALT:
    // Call halt wrapper
      halt_wrapper(f);
      break;
    case SYS_EXIT:
    // Call exit
      exit_wrapper(f);
      break;
    case SYS_EXEC:
    // Call exec wrapper
      exec_wrapper(f);
      break;
    case SYS_WAIT:
    // Call wait wrapper
      wait_wrapper(f);
      break;
    case SYS_CREATE:
    // Call create wrapper
      create_wrapper(f);
      break;
    case SYS_REMOVE:
    // Call remove wrapper
      remove_wrapper(f);
      break;
    case SYS_OPEN:
    // Call open wrapper
      open_wrapper(f);
      break;
    case SYS_FILESIZE:
    // Call open wrapper
      filesize_wrapper(f);
      break;
    case SYS_READ:
      read_wrapper(f);
    // Call read wrapper
      break;
    case SYS_WRITE:
    // Call write wrapper
      write_wrapper(f);
      break;
    case SYS_SEEK:
    // Call seek wrapper
      seek_wrapper(f);
      break;
    case SYS_TELL:
    // Call tell wrapper
      seek_wrapper(f);
      break;
    case SYS_CLOSE:
    // Call close wrapper
      close_wrapper(f);
      break;
    default:
      break;
  }

  thread_exit ();
}

/* ======================================== ADDED ======================================== */
// Casting int pointer to int
int
get_int(int **esp) 
{
  int *ptr = *esp; // Dereference once to get the pointer to an integer
  int value = *ptr; // Dereference again to get the integer value
  return value;
}

// Casting char pointer to string
char
*get_char_ptr(char ***esp)
{
  char **ptr1 = *esp;     // Dereference once to get char**
  char *ptr2 = *ptr1;     // Dereference again to get char*
  return ptr2;
}

// Casting general pointer to general pointer 
void 
*get_void_pointer(void ***esp)
{
  void **ptr1 = *esp;      // Dereference once to get void**
  void *ptr2 = *ptr1;      // Dereference again to get void*
  return ptr2;
}

// Check validation of pointer
void validate_void_ptr (const void *pt)
{
  // Convert pointer to int
  int address = get_int(pt);
  // Check null pointer
  bool is_null = address == NULL;
  // Check user space memory
  bool is_kernel_space = !is_user_vaddr(address);
  // Check unmapped to virtual address
  bool is_unmapped_vm = pagedir_get_page(thread_current()->pagedir, address) == NULL;

  if (is_null || is_unmapped_vm || is_kernel_space)
    exit(-1);
}

// Casting file descriptor to file
struct process_file
*get_open_file(int fd)
{
  struct thread *cur = thread_current();
  struct list_elem *head = list_begin(&cur->open_files);
  for (; head != list_end(&cur->open_files); list_next(head))
  {
    // Casting head to process_file
    struct process_file *open_file = list_entry(head, struct process_file, elem);
    if (open_file->f_d == fd)
      return open_file;
  }
  return NULL;
}

// Halt wrapper
void
halt_wrapper (struct intr_frame *f)
{
  // Call halt
  halt();
}
// Halt implementation
void
halt (void)
{
  shutdown_power_off();
}

// Exit wrapper
void
exit_wrapper (struct intr_frame *f)
{
  // Dummy
  int *sp = (int *)f->esp;
  sp++;
  f -> eax = -1;
  // Check valid arguments
  validate_void_ptr(*sp);
  int status = get_int(sp);
  // Call exit
  f->eax = status;
  exit (status);
}
// Exit implementation
void
exit (int status)
{
  // Current exit thread
  struct thread *cur = thread_current();
  
  // Save exit status
  cur->exit_status = status;

  // Print name and status of current exit thread
  printf("%s: exit(%d)\n", cur->name, status);
  
  // Thread exit
  thread_exit();
}

// Exec wrapper
void
exec_wrapper (struct intr_frame *f)
{
  int *sp = (int *)f -> esp;
  sp++;
  const char *cmd_line = get_char_ptr(sp);
  // Check valid arguments
  validate_void_ptr(cmd_line);
  // Call exec
  f->eax = exec (cmd_line);
}
// Exec implementation
tid_t
exec (const char *cmd_line)
{
  return process_execute(cmd_line);
}

// Wait wrapper
void
wait_wrapper (struct intr_frame *f)
{
  int *sp = (int *)f -> esp;
  sp++;
  // Check valid arguments
  validate_void_ptr(*sp);
  tid_t tid = get_int(sp);
  // Call wait
  f->eax = wait (tid);
}
// Wait implementation
int
wait (tid_t tid)
{
  return process_wait(tid);
}

// Create file wrapper
void 
create_wrapper (struct intr_frame *f)
{
  int *sp = (int *)f -> esp;
  sp++;
  const char *file = get_char_ptr(sp);
  // Check valid arguments
  validate_void_ptr(file);
  sp++;
  validate_void_ptr(*sp);
  unsigned initial_size = get_int(sp);

  // Call create
  f->eax = create (file, initial_size);
}

// Create file implementation
bool
create (const char *file, unsigned initial_size)
{
  // Lock critical section
  lock_acquire(&files_sync_lock);
  // Create file
  bool status = filesys_create (file, initial_size);
  // Release lock
  lock_release(&files_sync_lock);

  return status;
}

// Remove file wrapper
void
remove_wrapper (struct intr_frame *f)
{
  int *sp = (int *)f -> esp;
  sp++;
  const char *file = get_char_ptr(sp);
  // Check valid arguments
  validate_void_ptr(file);
  // Call remove
  f->eax = remove (file);
}
// Remove file implementation
bool
remove (const char *file)
{
  // Lock critical section
  lock_acquire(&files_sync_lock);
  // Remove file
  bool status = filesys_remove (file);
  // Release lock
  lock_release(&files_sync_lock);

  return status;
}

// Open file wrapper
void
open_wrapper (struct intr_frame *f)
{
    int *sp = (int *)f -> esp;
    sp++;
    const char *file = get_char_ptr(sp);
    // Check valid arguments
    validate_void_ptr(file);
    // Call open
    f->eax = open (file);
}

// Open file implementation
int
open (const char *file)
{
  // Lock critical section
  lock_acquire(&files_sync_lock);
  // Open file
  struct file *file_ptr = filesys_open (file);
  // Release lock
  lock_release(&files_sync_lock);

  // if valid file
  if (file_ptr != NULL) {
    // Current thread
    struct thread *cur = thread_current();
    // Allocat open_file
    struct process_file *open_file = (struct process_file *) malloc(sizeof(struct process_file));
    open_file->file = file_ptr;
    
    // Lock critical section
    lock_acquire(&files_sync_lock);
    // Increment last file descriptor
    cur->fd_last++;
    open_file->f_d = cur->fd_last;
    // Release lock
    lock_release(&files_sync_lock);

    list_push_back(&cur->open_files, &open_file->elem);

    return cur->fd_last;
  }

  // Not valid file 
  return -1;
}

// Read file wrapper
void
read_wrapper (struct intr_frame *f)
{
  int *sp = (int *)f->esp;
  sp++;
  // Check valid arguments
  validate_void_ptr(*sp);
  int fd = get_int(sp);
  
  sp++;
  char *buffer = get_char_ptr(sp);
  // Check valid arguments
  validate_void_ptr(buffer);
  sp++;
  // Check valid arguments
  validate_void_ptr(*sp);
  unsigned size = get_int(sp);
  // Call read
  f->eax = read(fd, buffer, size);
}
// Read file implementation
int
read (int fd, void *buffer, unsigned size)
{
  // Need implementation 
  if(fd == 0) {
    for(int i = 0; i < size; i++) {
      lock_acquire(&files_sync_lock);
      char c = input_getc();
      lock_release(&files_sync_lock);
      buffer = (char) buffer + c;
    }
    return size;
  } else if(fd == 1) {
    //negative space 
  } else if(fd == -1){
    exit(-1);
  } else {
    struct process_file *file = get_open_file(fd);
    lock_acquire(&files_sync_lock);
    size = file_read(file, buffer, size);
    lock_release(&files_sync_lock);
    return size;
  }
  return -1;
}

// File size wrapper
void
filesize_wrapper (struct intr_frame *f)
{
  int *sp = (int *)f -> esp;
  sp++;
  // Check valid arguments
  validate_void_ptr(*sp);
  int fd = get_int(sp);
  // Call file size
  f->eax = filesize (fd);
}
// File size implementation
int
filesize (int fd)
{
  struct process_file *process_file = get_open_file(fd);
  if (process_file == NULL)
  {
    return -1;
  }
  // Lock critical section
  lock_acquire(&files_sync_lock);
  int size = file_length (process_file -> file);
  // Release lock
  lock_release(&files_sync_lock);
  return size;
}

// Write file wrapper
void
write_wrapper (struct intr_frame *f)
{
  int *sp = (int *)f->esp;
  sp++;
  // Check valid arguments
  validate_void_ptr(*sp);
  int fd = get_int(sp);
  sp++;
  void *buffer = get_void_pointer(sp);
  // Check valid arguments
  validate_void_ptr(buffer);
  sp++;
  // Check valid arguments
  validate_void_ptr(*sp);
  unsigned size = get_int(sp);
  // Call write
  f->eax = write(fd, buffer, size);
}

// write file implementation
int 
write (int fd, const void *buffer, unsigned size)
{
  // Need implementation 
  if(fd == 0) {
    //negative space
  } else if(fd == 1) {
    lock_acquire(&files_sync_lock);
    putbuf(buffer, size);
    lock_release(&files_sync_lock); 
    return size;
  } else if (fd == -1){
    exit(-1);
  } else {
    struct process_file *process_file = get_open_file(fd);
    if(process_file == NULL) {
      exit(-1);
    }
    lock_acquire(&files_sync_lock);
    int return_value = file_write(process_file -> file, buffer, size);
    lock_release(&files_sync_lock);
    return return_value;
  }
  return -1;
}

// Seek file wrapper
void
seek_wrapper (struct intr_frame *f)
{
  int *sp = (int *)f -> esp;
  sp++;
  // Check valid arguments
  validate_void_ptr(*sp);
  int fd = get_int(sp);
  struct process_file *process_file = get_open_file(fd);
  if(process_file == NULL) {
    f -> eax = -1;
    return;
  }
  sp++;
  // Check valid arguments
  validate_void_ptr(*sp);
  unsigned position = get_int(sp);
  // Call seek
  f->eax = position;
  seek (fd, position);
}
// Seek file implementation
void
seek (int fd, unsigned position)
{
  // Lock critical section
  lock_acquire(&files_sync_lock);
  // Get file
  struct process_file *process_file = get_open_file(fd);
  file_seek (process_file -> file, position);
  // Release lock
  lock_release(&files_sync_lock);
}

// Tell file wrapper
void
tell_wrapper (struct intr_frame *f)
{
  int *sp = (int *)f -> esp;
  sp++;
  // Check valid arguments
  validate_void_ptr(*sp);
  int fd = get_int(sp);
  // Call tell
  f->eax = tell (fd);
}
// Tell file implementation
signed
tell (int fd)
{
  // Lock critical section
  lock_acquire(&files_sync_lock);
  // Get file

  // Dummy
  struct process_file *process_file = get_open_file(fd);
  if(process_file == NULL) {
    return -1;
  }
  int position = file_tell (process_file -> file);
  // Release lock
  lock_release(&files_sync_lock);

  return position;
}

// Close file wrapper
void
close_wrapper (struct intr_frame *f)
{
  int *sp = (int *)f -> esp;
  sp++;
  // Check valid arguments
  validate_void_ptr(*sp);
  int fd = get_int(sp);
   if (fd == 0 || fd == 1)
    {
      exit(-1);
    }
  // Call tell
  close (fd);
}
// Close file implementation
void
close (int fd)
{
  // Lock critical section
  lock_acquire(&files_sync_lock);
  // Get file

  // Dummy
  struct process_file *process_file = get_open_file(fd);
  if(process_file == NULL) {
    exit(-1);
  }
  file_close (process_file -> file);
  // Release lock
  lock_release(&files_sync_lock);
  // Remove from list
  list_remove(&process_file->elem);
}

