#include <thread.h>
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
//added file sestem lock
struct lock files_lock;
//added 
///note it close all files if given -1 
void syscall_init (void);
void process_close_file(int file_descriptor) {
  struct thread *current_thread = thread_current();
  struct list_elem *next_element;
  struct list_elem *element = list_begin(&current_thread->open_files_list);

  for (; element != list_end(&current_thread->open_files_list); element = next_element) {
    next_element = list_next(element);
    struct process_file *file_ptr = list_entry(element, struct process_file, elem);
    if (file_descriptor == file_ptr->f_d || file_descriptor == -1) {
      file_close(file_ptr->file);
      list_remove(&file_ptr->elem);
      free(file_ptr);
      if (file_descriptor != -1) {
        return;
      }
    }
  }
}

#endif /* userprog/syscall.h */
