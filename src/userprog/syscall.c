#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
    : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
/*static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}*/

static void
copy_in (void *dst_, const void *usrc_, size_t size)
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;

  for (; size > 0; size--, dst++, usrc++)
    *dst = get_user (usrc);
}

/* Returns false on null pointers, pointers that don't point to
   user virtual memory, and pointers to unmapped virtual memory. */
static bool
verify_usrc (const void *usrc)
{
  if (usrc == NULL ||
      !is_user_vaddr (usrc) ||
      pagedir_get_page (thread_current ()->pagedir, usrc) == NULL)
    return false;
  return true;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  unsigned syscall_number;

  /* Extract syscall number. */
  copy_in (&syscall_number, f->esp, sizeof syscall_number);
  printf (" === system call %u! ===\n", syscall_number);

  /* Handle appropriate syscall. */
  switch (syscall_number) 
  {
    case SYS_HALT:
    case SYS_EXIT: 
    {
      int num_args = 1;
      int args[num_args];
      int status = 0;

      /* Extract arguments. */
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * num_args);

      /* Set the returned value. */
      f->eax = status;

      /* Terminate user program. */
      thread_exit();
    }
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_CREATE:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_READ:
    case SYS_WRITE: 
    {
      int num_args = 3;
      int args[num_args];
      int bytes_written = 0;

      /* Extract arguments. */
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * num_args);

      /*//DEBUG
      printf ("\tfd: %d (should be %u)\n", args[0], STDOUT_FILENO);
      printf ("\tbuf addr: %p\n", args[1]);
      printf ("\tsize: %u\n", args[2]);*/

      /* Execute the write. */
      if (args[0] == STDOUT_FILENO)
      {
        putbuf ((const char *) args[1], args[2]);
        bytes_written = args[2];
      }

      /* Set the returned value. */
      f->eax = bytes_written;
    }
    case SYS_SEEK:
    case SYS_TELL:
    case SYS_CLOSE:
    break;
  }

}
