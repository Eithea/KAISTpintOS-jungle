#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

/// 2-1
void argument_stack(char **argv, const int argc, struct intr_frame *_if);

/// 2-3 Hierarchical Process Structure
struct thread *get_child_process(tid_t child_tid);

/// 3-2
struct lazy_load_info
{
    struct file *file;
    off_t ofs;
    size_t page_read_bytes;
};

#endif /* userprog/process.h */
