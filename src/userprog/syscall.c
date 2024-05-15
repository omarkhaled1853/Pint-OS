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


struct lock global_lock;

// Validations in the method required by eng el Ta7an

// bool validate_stack_pointer(struct intr_frame *f);
bool validate_address_in_virtual_memory(void *add);
static void syscall_handler(struct intr_frame *f UNUSED);
bool valid_esp(struct intr_frame *f);
struct files_opened *sys_file_helper(int fd);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&global_lock);
}

bool valid_esp(struct intr_frame *f)
{
  return validate_address_in_virtual_memory((int *)f->esp) || ((*(int *)f->esp) < 0) || (*(int *)f->esp) > 12;
}

/*Is this thing in memory actually*/
bool validate_address_in_virtual_memory(void *val)
{
  return val != NULL && is_user_vaddr(val) && pagedir_get_page(thread_current()->pagedir, val) != NULL;
}

// struct files_opened *sys_file_helper(int fd)
// {
//   struct list *list_of_files = &(thread_current()->files_opened_by_me);
//   for (struct list_elem *cur = list_begin(list_of_files); cur != list_end(list_of_files); cur = list_next(cur))
//   {
//     struct files_opened *cur_file = list_entry(cur, struct files_opened, elem);
//     if ((cur_file->file_descriptor) == fd)
//     {
//       return cur_file;
//     }
//   }
//   return NULL;
// }

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  if (!valid_esp(f))
  {
    sys_exit(-1);
  }

  // We will read only one integer telling me what operation is to be executed
  switch (*(int *)f->esp)
  {

  case SYS_HALT:
  {
    system_halt_wrapper(f);
    break;
  }
  case SYS_EXIT:
  {
    system_exit_wrapper(f);
    break;
  }
  case SYS_EXEC:
  {
    system_exec_wrapper(f);
    break;
  }
  case SYS_WAIT:
  {
    system_wait_wrapper(f);
    break;
  }
  case SYS_CREATE:
  {
   // system_create_wrapper(f);
    break;
  }
  case SYS_REMOVE:
  {
    //system_remove_wrapper(f);
    break;
  }
  case SYS_OPEN:
  {
    //system_open_wrapper(f);
    break;
  }
  case SYS_FILESIZE:
  {
    //system_filesize_wrapper(f);
    break;
  }

  case SYS_READ:
  {
    //system_read_wrapper(f);
    break;
  }
  case SYS_WRITE:
  {
   // system_write_wrapper(f);
    break;
  }
  case SYS_TELL:
  {
    //sys_tell(f);
    break;
  }
  case SYS_SEEK:
  {
    //sys_seek(f);
    break;
  }
  case SYS_CLOSE:
  {
   // system_close_wrapper(f);
    break;
  }
  default:
    break;
  }
}

void system_halt_wrapper(struct intr_frame *f)
{
  sys_halt();
}

void sys_halt()
{
  shutdown_power_off();
}

void system_exit_wrapper(struct intr_frame *f)
{

  int *status_pointer = (int *) ((int *)f->esp + 1);
  if (!validate_address_in_virtual_memory(status_pointer))
  {
    f->eax = -1;
    sys_exit(-1);
  }

  f->eax = *status_pointer;
  sys_exit(*status_pointer);
}

void sys_exit(int status)
{
  struct thread *t = thread_current();
  char* name= t->name;
  char * save_ptr;
  char * exe = strtok_r (name, " ", &save_ptr);


  t->exit_status = status;

  printf("%s: exit(%d)\n",exe,status);

  thread_exit();
}

void system_exec_wrapper(struct intr_frame *f)
{
  char* cmd_line = (char*) (*((int*)f->esp + 1));
  if (!validate_address_in_virtual_memory(cmd_line)){
    sys_exit(-1);
  }
  
  f->eax = sys_exec(cmd_line);
}

tid_t sys_exec(const char *file)
{
  return process_execute(file);
}

void system_wait_wrapper(struct intr_frame *f)
{
  int *tid_pointer = (int *) ((int *)f->esp + 1);
  if (!validate_address_in_virtual_memory(tid_pointer))
  {
    sys_exit(-1);
  }

  f->eax = sys_wait(*tid_pointer);
}

int sys_wait(tid_t t)
{
  return process_wait(t);
}

// void system_write_wrapper(struct intr_frame *f)
// {
//   int fd = *((int *)f->esp + 1);
//   char *buffer = (char *)(*((int *)f->esp + 2));
//   // fd must not be 0 because zero is stdin, will be used in read
//   if (fd == 0 || !validate_address_in_virtual_memory(buffer))
//   { // fail, if fd is 0 (stdin), or its virtual memory
//     sys_exit(-1);
//   }
//   // Pull the fourth parameter which is size of the output
//   unsigned size = (unsigned)(*((int *)f->esp + 3));
//   f->eax = sys_write(fd, buffer, size);
// }

// int sys_write(int fd, const void *buffer, unsigned size)
// {
//   if (fd == 1)
//   { // fd is 1, writes to the stdout
//     lock_acquire(&global_lock);
//     putbuf(buffer, size);
//     lock_release(&global_lock);
//     return size;
//   }

//   struct files_opened *file = sys_file_helper(fd);
//   if (file == NULL)
//   { // fail
//     return -1;
//   }
//   else
//   {
//     int ans = 0;
//     lock_acquire(&global_lock);
//    // ans = file_write(file->f, buffer, size);
//     lock_release(&global_lock);
//     return ans;
//   }
// }

// void system_close_wrapper(struct intr_frame *f)
// {
//   int fd = *((int *)f->esp + 1);

//   if (fd == 0 || fd == 1)
//   {
//     sys_exit(-1);
//     // becouse 0 and 1 belongs to stdin&stdout
//   }
//   else
//   {
//     f->eax = sys_close(fd);
//   }
// }

// int sys_close(int fd)
// {
//   struct files_opened *open = sys_file_helper(fd);

//   if (open != NULL)
//   {
//     lock_acquire(&global_lock);
//     file_close(open->f);
//     lock_release(&global_lock);
//     list_remove(&open->elem);
//     return 1;
//   }
//   else
//   {
//     return -1;
//   }
// }

// void system_create_wrapper(struct intr_frame *f)
// {

//   // take it from esp
//   char *n_file = (char *)*((int *)f->esp + 1);
//   // check if it valid
//   if (!validate_address_in_virtual_memory(n_file))
//   {
//     sys_exit(-1);
//   }
//   // take size
//   unsigned int size = (unsigned)*((int *)f->esp + 2);
//   ;
//   // call sys_create and store in eax
//   f->eax = sys_create(n_file, size);
// }

// // bool sys_create(const char *file, unsigned initial_size)
// {
//   bool ok;
//   lock_acquire(&global_lock);
//   ok = filesys_create(file, initial_size);
//   lock_release(&global_lock);
//   return ok;
// }

// void system_remove_wrapper(struct intr_frame *f)
// {

//   char *n_file = (char *)*((int *)f->esp + 1);

//   // check if it valid
//   if (!validate_address_in_virtual_memory(n_file))
//   {
//     sys_exit(-1);
//   }
//   // call sys_create and store in eax
//   f->eax = sys_remove(n_file);
// }

// bool sys_remove(const char *file)
// {
//   bool ok;
//   lock_acquire(&global_lock);
//   ok = filesys_remove(file);
//   lock_release(&global_lock);
//   return ok;
// }

// void system_open_wrapper(struct intr_frame *f)
// {

//   char *n_file = (char *)*((int *)f->esp + 1);
//   if (!validate_address_in_virtual_memory(n_file))
//   {
//     sys_exit(-1);
//   }
//   f->eax = sys_open(n_file);
// }

// int sys_open(const char *file) // return -1 1 if the file could not be opened, else return fd
// {
//   static unsigned long fd_now = 2;
//   lock_acquire(&global_lock);
//   struct file *opened_file = filesys_open(file);
//   lock_release(&global_lock);
//   if (opened_file == NULL)
//   {
//     return -1;
//   }
//   else
//   {

//     struct files_opened *thread_files = (struct files_opened *)malloc(sizeof(struct files_opened));
//     int file_fd = fd_now;
//     thread_files->file_descriptor = fd_now;
//     thread_files->f = opened_file;

//     lock_acquire(&global_lock);
//     fd_now++;
//     lock_release(&global_lock);
//     // list of opended files
//     struct list_elem *elem = &thread_files->elem;
//     list_push_back(&thread_current()->files_opened_by_me, elem);
//     return file_fd;
//   }
// }

// void system_filesize_wrapper(struct intr_frame *f)
// {
//   int *fd = (int)(*((int *)f->esp + 1));
//   struct files_opened *open_file = sys_file_helper(fd);
//   if (open_file == NULL)
//   {
//     f->eax = -1;
//   }
//   else
//   {
//     f->eax = sys_filesize(open_file);
//   }
// }

// int sys_filesize(struct files_opened *file)
// {
//   long ans;
//   lock_acquire(&global_lock);
//   ans = file_length(file->f);
//   lock_release(&global_lock);
//   return ans;

//   return 0;
// }

// void system_read_wrapper(struct intr_frame *f)
// {

//   int fd = *((int *)f->esp + 1);
//   char *buffer = (char *)(*((int *)f->esp + 2));
//   // fd must not be 1 because zero is stdin, will be used in write
//   if (fd == 1 || !validate_address_in_virtual_memory(buffer))
//   { // fail, if fd is 1 (stdin)
//     sys_exit(-1);
//   }

//   unsigned size = (unsigned)(*((int *)f->esp + 3));
//   f->eax = sys_read(fd, buffer, size);
// }

// int sys_read(int fd, void *buffer, unsigned size)
// {
//   int size_of_file = size;
//   if (fd == 0)
//   {

//     while (size--)
//     {
//       lock_acquire(&global_lock);
//       char ch = input_getc();
//       lock_release(&global_lock);
//       buffer += ch;
//     }
//     return size_of_file;
//   }
//   else if (fd == -1)
//   {
//     // negative area
//   }
//   else
//   {
//     struct files_opened *file = sys_file_helper(fd);
//     if (file == NULL)
//     { // fail
//       return -1;
//     }
//     else
//     {
//       lock_acquire(&global_lock);
//       size_of_file = file_read(file->f, buffer, size);
//       lock_release(&global_lock);
//       return size_of_file;
//     }
//   }
// }

// void system_seek_wrapper(struct intr_frame *f){

// }

// void sys_seek(struct intr_frame *f)
// {
//   int fd = (int)(*((int *)f->esp + 1));
//   unsigned postion = (unsigned)(*((int *)f->esp + 2));
//   struct files_opened *opened_file = sys_file_helper(fd);
//   if (opened_file == NULL)
//   { // fail
//     f->eax = -1;
//   }
//   else
//   {
//     lock_acquire(&global_lock);
//     file_seek(opened_file->f, postion);
//     f->eax = postion;
//     lock_release(&global_lock);
//   }
// }

// // void system_tell_wrapper(struct intr_frame *f){

// // }

// void sys_tell(struct intr_frame *f)
// {
//   int fd = (int)(*((int *)f->esp + 1));
//   struct files_opened *file = sys_file_helper(fd);
//   if (file == NULL)
//   {
//     f->eax = -1;
//   }
//   else
//   {
//     lock_acquire(&global_lock);
//     f->eax = file_tell(file->f);
//     lock_release(&global_lock);
//   }
// }