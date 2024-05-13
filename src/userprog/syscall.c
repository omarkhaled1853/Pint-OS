#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
/* ======================================== ADDED ======================================== */
#include "filesys/filesys.h"
#include "filesys/file.h"
/* ======================================== ADDED ======================================== */
#include "threads/vaddr.h"
#include "userprog/pagedir.c"
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
  validate_void_ptr(f);

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
  bool is_unmapped_vm = !lookup_page(address, thread_current()->pagedir);

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
    if (open_file->fd == fd)
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
  // Check valid arguments

  // Dummy
  int status = 0;
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
  // Check valid arguments

  // Dummy
  const char *cmd_line = "";
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
  // Check valid arguments

  // Dummy
  tid_t tid = NULL;
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
  // Check valid arguments

  // dummy
  const char *file = "";
  unsigned initial_size = 0;

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
  // Check valid arguments

  // Dummy
  const char *file = "";

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
    // Check valid arguments

    // dummy
    const char *file = "";

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
  struct file *file = filesys_open (file);
  // Release lock
  lock_release(&files_sync_lock);

  // if valid file
  if (file != NULL) {
    // Current thread
    struct thread *cur = thread_current();
    // Allocat open_file
    struct process_file *open_file = (struct process_file *) malloc(sizeof(struct process_file));
    open_file->file = file;
    
    // Lock critical section
    lock_acquire(&files_sync_lock);
    // Increment last file descriptor
    cur->fd_last++;
    open_file->fd = cur->fd_last;
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
  // Check valid arguments

  // Dummy
  int fd = 0;
  void *buffer = NULL;
  unsigned size = 0;
  // Call read
  f->eax = read(fd, buffer, size);
}
// Read file implementation
int
read (int fd, void *buffer, unsigned size)
{
  // Need implementation 
    return 0;
}

// File size wrapper
void
filesize_wrapper (struct intr_frame *f)
{
  // Check valid arguments

  // Dummy
  int fd = 0;

  // Call file size
  f->eax = filesize (fd);
}
// File size implementation
int
filesize (int fd)
{
  // Lock critical section
  lock_acquire(&files_sync_lock);
  // Get file size

  // Dummy
  struct file *file = NULL;
  int size = file_length (file);
  // Release lock
  lock_release(&files_sync_lock);
  return size;
}

// Write file wrapper
void
write_wrapper (struct intr_frame *f)
{
  // Check valid arguments

  // Dummy
  int fd = 0;
  const void *buffer = NULL;
  unsigned size = 0;
  // Call write
  f->eax = write (fd, buffer, size);
}

// write file implementation
int 
write (int fd, const void *buffer, unsigned size)
{
  // Need implementation 
  return 0;
}

// Seek file wrapper
void
seek_wrapper (struct intr_frame *f)
{
  // Check valid arguments

  // Dummy
  int fd = 0;
  unsigned position = 0;
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

  // Dummy
  struct file *file = NULL;
  file_seek (file, position);
  // Release lock
  lock_release(&files_sync_lock);
}

// Tell file wrapper
void
tell_wrapper (struct intr_frame *f)
{
  // Check valid arguments

  // Dummy
  int fd = 0;
  // Call tell
  f->eax = tell (fd);
}
// Tell file implementation
unsigned
tell (int fd)
{
  // Lock critical section
  lock_acquire(&files_sync_lock);
  // Get file

  // Dummy
  struct file *file = NULL;
  int position = file_tell (file);
  // Release lock
  lock_release(&files_sync_lock);

  return position;
}

// Close file wrapper
void
close_wrapper (struct intr_frame *f)
{
  // Check valid arguments

  // Dummy
  int fd = 0;
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
  struct file *file = NULL;
  file_close (file);
  // Release lock
  lock_release(&files_sync_lock);
  
  // Casting file
  struct process_file *open_file = get_open_file(fd);
  // Remove from list
  list_remove(&open_file->elem);
}

