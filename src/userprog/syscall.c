#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f ) 
{
  printf ("system call!\n");
  int SystemCallType= (int) f->esp;
  switch (SystemCallType)
  {
  case SYS_HALT:
    //process_halt
    break;
  case SYS_EXIT:
    //process_Exit
    break;
  case SYS_EXEC:
    // exec
    break;
  case SYS_WAIT:
    // wait
    break;
  //... another calls 
 
  default:
    break;
  }

  thread_exit ();
}
