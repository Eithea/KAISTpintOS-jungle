#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/// 2-3
#include "threads/thread.h"


void syscall_init (void);

/// 2-2
void check_address(void *addr);

/// 2-3
int process_add_file(struct file *file);
struct file *process_get_file(int fd);
void process_close_file(int fd);

void halt (void);
void exit (int status);
int wait (tid_t pid);
tid_t fork (const char* thread_name, struct intr_frame *if_);
int exec (const char *file);
bool create (const char *file_name, unsigned initial_size);
bool remove (const char *file_name);
int open (const char *file_name);
int read (int fd, void *buffer, unsigned size);
int filesize (int fd);
int write (int fd, const void *buffer, unsigned size);
void close (int fd);
void seek (int fd, unsigned position);
unsigned tell (int fd);

struct lock filesys_lock;

#endif /* userprog/syscall.h */
