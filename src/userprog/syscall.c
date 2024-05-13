#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
/* ======================================== ADDED ======================================== */
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
/* ======================================== ADDED ======================================== */
static struct lock files_sync_lock; /* lock for synchronization between files */
int get_int(int **esp); /* get int from the stack */
char *get_char_ptr(char ***esp); /* get character pointer */
void *get_void_pointer(void ***esp); /* get void (generic) pointer */
void validate_void_ptr(const void *pt); /* check if the pointer is valid */

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
  validate_void_ptr(f);

  printf ("system call!\n");
  
  int systemCallType = (int *) f->esp;
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
      break;
    case SYS_WAIT:
    // Call wait wrapper
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
      break;
    case SYS_SEEK:
    // Call seek wrapper
      break;
    case SYS_TELL:
    // Call tell wrapper
      break;
    case SYS_CLOSE:
    // Call close wrapper
      break;
    default:
      break;
  }

  thread_exit ();
}

/* ======================================== ADDED ======================================== */
// Check validation of pointer
void validate_void_ptr (const void *pt)
{
  // if valid

  // if not valid
  exit(-1);
}

// Halt wrapper
void
halt_wrapper (struct intr_frame *f)
{
  // Check valid arguments

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
  struct thread *curr = thread_current();
  
  // Print name and status of current exit thread
  printf("%s: exit(%d)\n", curr->name, curr->status);
  
  // Thread exit
  thread_exit();
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
    // Get file descriptor from thread 
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

  // Call read
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
  struct file *file;
  int size = file_length (file);
  // Release lock
  lock_release(&files_sync_lock);
  return size;
}


