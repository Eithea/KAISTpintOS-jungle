#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

/// 2-3
#include <list.h>
#include "userprog/process.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	/// 2-3 File Descriptor
	// filesys에서 쓸 lock 생성
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	//printf ("system call!\n");
	/// 2-3
	// syscall-nr.h에 명시된 콜들을 구현
	// SYS_HALT,                   /* Halt the operating system. */
	// SYS_EXIT,                   /* Terminate this process. */
	// SYS_FORK,                   /* Clone current process. */
	// SYS_EXEC,                   /* Switch current process. */
	// SYS_WAIT,                   /* Wait for a child process to die. */
	// SYS_CREATE,                 /* Create a file. */
	// SYS_REMOVE,                 /* Delete a file. */
	// SYS_OPEN,                   /* Open a file. */
	// SYS_FILESIZE,               /* Obtain a file's size. */
	// SYS_READ,                   /* Read from a file. */
	// SYS_WRITE,                  /* Write to a file. */
	// SYS_SEEK,                   /* Change position in a file. */
	// SYS_TELL,                   /* Report current position in a file. */
	// SYS_CLOSE,                  /* Close a file. */
	switch (f->R.rax)
	{
		case SYS_HALT : 
			halt();
			break;

		case SYS_EXIT : 
			exit(f->R.rdi);
			break;

		case SYS_FORK : 
			f->R.rax = fork(f->R.rdi, f);
			break;

		case SYS_EXEC : 
			f->R.rax = exec(f->R.rdi);
			break;

		case SYS_WAIT : 
			f->R.rax = wait(f->R.rdi);
			break;

		case SYS_CREATE : 
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;

		case SYS_REMOVE : 
			f->R.rax = remove(f->R.rdi);
			break;
		
		case SYS_OPEN : 
			f->R.rax = open(f->R.rdi);
			break;
		
		case SYS_FILESIZE : 
			f->R.rax = filesize(f->R.rdi);
			break;
		
		case SYS_READ : 
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		
		case SYS_WRITE : 
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		
		case SYS_SEEK : 
			seek(f->R.rdi, f->R.rsi);
			break;
		
		case SYS_TELL : 
			f->R.rax = tell(f->R.rdi);
			break;
		
		case SYS_CLOSE : 
			close(f->R.rdi);
			break;	
		default :
			exit(-1);
			break;
	}	

	// thread_exit ();
}

/// 2-2
// 비정상적인 addr 인풋에 대해 프로세스를 중단하는 거름망
void check_address(void *addr)
{
	// addr이 NULL인 경우
	// addr의 가상메모리 주소값이 KERN_BASE 이상인 경우 (= 유저 영역이 아닐 경우)
	// addr의 주소값이 page table 외인 경우 (page fault) 라는데 아무튼 그럼
	if (addr == NULL || !(is_user_vaddr(addr)) || pml4_get_page(thread_current()->pml4, addr) == NULL)
	{
		exit(-1);
	}
}

/// 2-3 File Descriptor
// curr의 fdt에 file을 등록하고 fdtable의 range와 next order를 갱신
int process_add_file(struct file *file)
{
	struct thread *curr = thread_current();
	// curr.fdtable의 next order가 FD_MAX(최대 512개의 파일 오픈가능)을 초과시 error
	if (curr->next_fd >= FD_MAX)
	{
		return TID_ERROR;	
	}
	// curr에 저장된 next order를 받아 fdtable의 해당 index에 file 기록
	int fd = curr->next_fd;
	curr->fdtable[fd] = file;
	// fdtable의 range가 갱신되었을 경우 (= range 안에 빈 index가 없어서 오른쪽 끝에 추가) range 갱신
	if (fd > curr->rangeof_fd)
	{
		curr->rangeof_fd = fd;
	}
	// next order를 next fit으로 탐색
	// range를 갱신한 위의 경우에는 1회의 루프만에 바로 rangeof_fd + 1이 배정된다
	while (curr->next_fd < FD_MAX && curr->fdtable[curr->next_fd])
	{
		curr->next_fd = curr->next_fd + 1;
	}
	return fd;
}

/// 2-3 File Descriptor
// fd값으로부터 fdtable에서 file을 가져와 return
struct file *process_get_file(int fd)
{
	// range 밖은 return NULL
	if (fd < 0 || fd >= FD_MAX)
	{
		return NULL;
	}
	// return file
	// index fd에 file이 없으면 fdtable[fd] = NULL이므로 예외처리 불필요
	return thread_current()->fdtable[fd];
}

/// 2-3 File Descriptor
// fd값으로부터 fdtable에서 file을 제거
void process_close_file(int fd)
{
	// range 밖은 return NULL
	// stdin, stdout도 제거 불가
	if (fd < 2 || fd >= FD_MAX)
	{
		return;
	}
	struct thread *curr = thread_current();
	// fdtable에서 제거 후 next order와 range 갱신
	curr->fdtable[fd] = NULL;
	if (fd < curr->next_fd)
	{
		curr->next_fd = fd;
	}
	if (fd >= curr->rangeof_fd)
	{
		curr->rangeof_fd = curr->rangeof_fd -1;
	}
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	struct thread *curr = thread_current();
	curr->exit_status = status;
	/// 2-4
	printf("%s: exit(%d)\n", thread_name(), status);

	thread_exit();
}

tid_t fork(const char *thread_name, struct intr_frame *f)
{
	check_address(thread_name);
	return process_fork(thread_name, f);
}

int exec(const char *file_name)
{
	check_address(file_name);
	char *file_name_copy = palloc_get_page(PAL_ZERO);
	if (file_name_copy == NULL)
		return TID_ERROR;
	strlcpy(file_name_copy, file_name, strlen(file_name) + 1);
	if (process_exec(file_name_copy) < 0)
		exit(-1);
	NOT_REACHED();
}

int wait(tid_t pid)
{
	return process_wait(pid);
}

bool create(const char *file_name, unsigned initial_size)
{
	check_address(file_name);
	return filesys_create(file_name, initial_size);
}

bool remove(const char *file_name)
{
	check_address(file_name);
	return filesys_remove(file_name);
}

int open(const char *file_name)
{
	// file_name이 적합한 addr인지 체크 후
	check_address(file_name);
	struct file* file;
	// lock으로 보호 후 file open
	// file_name은 디렉토리까지 포함한 텍스트이므로 filesys_open으로 열어야 한다
	lock_acquire(&filesys_lock);
	file = filesys_open(file_name);
	lock_release(&filesys_lock);
	// 실패시 error
	if (file == NULL)
	{
		return TID_ERROR;
	}
	// file을 curr.fdtable에 등록하고 fd를 get
	int fd = process_add_file(file);
	// fd 배정에 실패한 경우 close
	if (fd == TID_ERROR)
	{
		lock_acquire(&filesys_lock);
		file_close(file);
		lock_release(&filesys_lock);
	}
	return fd;
}

int read(int fd, void *buffer, unsigned size)
{
	// fd가 stdout이거나 해당하는 file이 없는 경우 error
	check_address(buffer);
	struct file *file = process_get_file(fd);
	if (fd == 1 || file == NULL)
	{
		return TID_ERROR;
	}
	// stdin일 경우 input buffer를 get
	int bytes_read;
	if (fd == 0)
	{
		char key;
		char *buf = buffer;
		for (int i=0; i<size; i++)
		{
			// buf를 한칸씩 이동하며 인터럽트에서 받은 key를 기록
			key = input_getc();
			*buf++ = key;
			bytes_read = bytes_read + 1;
			if (key == '\0')
			{
				break;
			}
		}
		return bytes_read;
	}
	// 이외의 경우 해당하는 file에 buffer를 file_read()
	lock_acquire(&filesys_lock);
	bytes_read = file_read(file, buffer, size);
	lock_release(&filesys_lock);
	return bytes_read;
}

int filesize(int fd)
{
	struct file* file = process_get_file(fd);
	if (file == NULL)
	{
		return TID_ERROR;
	}
	return file_length(file);
}


int write(int fd, const void *buffer, unsigned size)
{
	check_address(buffer);
	struct file *file = process_get_file(fd);
	// fd가 stdin이거나 해당하는 file이 없는 경우 error
	if (fd == 0 || file == NULL)
	{
		return TID_ERROR;
	}
	// stdout일 경우 putbuf
	if (fd == 1)
	{
		putbuf(buffer, size);
		return size;
	}
	// 이외의 경우 해당하는 file에 buffer를 file_write()
	int bytes_written;
	lock_acquire(&filesys_lock);
	bytes_written = file_write(file, buffer, size);
	lock_release(&filesys_lock);
	return bytes_written;
}

void close(int fd)
{
	// stdin, stdout이 아니라면 close
	if (fd >= 2)
	{
		struct file *file = process_get_file(fd);
		lock_acquire(&filesys_lock);
		file_close(file);
		lock_release(&filesys_lock);
	}
	process_close_file(fd);
}

void seek(int fd, unsigned position)
{
	if (fd < 2)
	{
		return;
	}
	struct file *file = process_get_file(fd);
	if (file == NULL) 
	{
		return;
	}
	lock_acquire(&filesys_lock);
	file_seek(file, position);
	lock_release(&filesys_lock);
}

unsigned tell(int fd)
{
	if (fd < 2)
	{
		return;
	}
	struct file *file = process_get_file(fd);
	if (file == NULL) 
	{
		return;
	}
	unsigned position;
	lock_acquire(&filesys_lock);
	position = file_tell(file);
	lock_release(&filesys_lock);
	return position;
}