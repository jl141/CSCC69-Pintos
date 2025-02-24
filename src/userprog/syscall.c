#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

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

/* Returns false on null pointers, pointers that don't point to
   user virtual memory, and pointers to unmapped virtual memory. */
static bool
is_valid_usrc (const void *usrc)
{
  if (usrc == NULL ||
      !is_user_vaddr (usrc) ||
      pagedir_get_page (thread_current ()->pagedir, usrc) == NULL)
    return false;
  return true;
}

static void
exit (int status)
{
  thread_current ()->exit_code = status;
  thread_exit ();
}

static void
copy_in (void *dst_, const void *usrc_, size_t size)
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;

  for (; size > 0; size--, dst++, usrc++)
  {
    if (!is_valid_usrc (usrc))
      {
        //printf ("copy in exit\n");
        exit (-1);
      }

    *dst = get_user (usrc);
  }
}

static void
extract_args (void *dst, struct intr_frame *f, int num_args)
{
  if (!is_valid_usrc ((uint32_t *) f->esp + 1) ||
      !is_valid_usrc ((uint32_t *) f->esp + sizeof(uint32_t) * num_args))
      {
        //printf ("extract args exit\n");
        exit (-1);
      }
  copy_in ((uint32_t *) dst, (uint32_t *) f->esp + 1, sizeof(uint32_t) * num_args);
}

static void
syscall_handler (struct intr_frame *f) 
{
  unsigned syscall_number;

  /* Extract syscall number. */
  if (!is_valid_usrc ((uint32_t *) f->esp) ||
      !is_valid_usrc ((uint32_t *) f->esp + sizeof syscall_number - 1))
      {
        //printf ("syscall exit\n");
        exit (-1);
      }
  copy_in (&syscall_number, f->esp, sizeof syscall_number);
  //DEBUG printf (" === system call %u ===\n", syscall_number);

  /* Handle appropriate syscall. */
  switch (syscall_number) 
  {
    case SYS_HALT:
      shutdown_power_off ();
    case SYS_EXIT: 
    {
      int num_args = 1;
      int args[num_args];

      /* Extract arguments. */
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * num_args);

      /* Exit user program. */
      exit (args[0]);
      NOT_REACHED ();
    }
    case SYS_EXEC:
    {
      int num_args = 1;
      int args[num_args];
      tid_t pid;

      /* Extract arguments. */
      extract_args (args, f, num_args);

      /* Execute command line. */
      if (strlen ((char *) args[0]) == 0)
        pid = -1;
      else
        pid = process_execute ((const char *) args[0]);

      /* Set the returned value. */
      f->eax = pid;
      break;
    }
    case SYS_WAIT:
    {
      int num_args = 1;
      int args[num_args];
      int status;

      /* Extract arguments. */
      extract_args (args, f, num_args);

      /* Wait for process PID. */
      if (args[0] < 0 || args[0] == 0 || args[0] == 1)
        status = -1;
      else
        status = process_wait ((tid_t) args[0]);

      /* Set the returned value. */
      f->eax = status;
      break;
    }
    case SYS_CREATE:
    {
      int num_args = 2;
      uint32_t args[num_args];
      bool success;

      /* Extract arguments. */
      extract_args (args, f, num_args);

      /* Create file. */
      if (strlen ((char *) args[0]) == 0)
        success = false;
      else
        success = filesys_create ((const char *) args[0], (off_t) args[1]);

      /* Set the returned value. */
      f->eax = success;
      break;
    }
    case SYS_REMOVE:
    {
      int num_args = 1;
      uint32_t args[num_args];
      bool success;

      /* Extract arguments. */
      extract_args (args, f, num_args);

      /* Remove file. */
      if (strlen ((char *) args[0]) == 0)
        success = false;
      else
        success = filesys_remove ((const char *) args[0]);

      /* Set the returned value. */
      f->eax = success;
      break;
    }
    case SYS_OPEN:
    {
      int num_args = 1;
      uint32_t args[num_args];
      int fd;

      /* Extract arguments. */
      extract_args (args, f, num_args);

      /* Open file. */
      if (strlen ((char *) args[0]) == 0)
        fd = -1;
      else
      {
        struct file *open_file = filesys_open ((const char *) args[0]);
        if (open_file == NULL)
          fd = -1;
        else
          fd = process_put_file (open_file);
      }

      /* Set the returned value. */
      f->eax = fd;
      break;
    }
    case SYS_FILESIZE:
    {
      int num_args = 1;
      uint32_t args[num_args];
      int bytes;

      /* Extract arguments. */
      extract_args (args, f, num_args);

      /* Get file length. */
      struct file *open_file = process_get_file (args[0]);
      if (open_file == NULL)
        bytes = 0;
      else
        bytes = file_length (open_file);

      /* Set the returned value. */
      f->eax = bytes;
      break;
    }
    case SYS_READ:
    {
      int num_args = 3;
      uint32_t args[num_args];
      int bytes_read;

      /* Extract arguments. */
      extract_args (args, f, num_args);

      /* Execute the read. */
      if (args[0] == STDIN_FILENO)
      {
        for (unsigned i = 0; i < args[2]; i++) 
        {
          ((char *) args[1])[i] = input_getc();
        }
        bytes_read = args[2];
      }

      /* Set the returned value. */
      f->eax = bytes_read;
      break;
    }
    case SYS_WRITE: 
    {
      int num_args = 3;
      uint32_t args[num_args];
      int bytes_written = 0;

      /* Extract arguments. */
      extract_args (args, f, num_args);

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
      break;
    }
    case SYS_SEEK:
    {
      int num_args = 2;
      uint32_t args[num_args];

      /* Extract arguments. */
      extract_args (args, f, num_args);

      /* Seek the file corresponding to the given FD. */
      struct file *open_file = process_get_file (args[0]);
      if (open_file != NULL)
        file_seek (open_file, args[1]);

      break;
    }
    case SYS_TELL:
    {
      int num_args = 1;
      uint32_t args[num_args];
      off_t pos;

      /* Extract arguments. */
      extract_args (args, f, num_args);

      /* Observe the file corresponding to the given FD. */
      struct file *open_file = process_get_file (args[0]);
      if (open_file == NULL)
        pos = 0;
      else
        pos = file_tell (open_file);

      /* Set the returned value. */
      f->eax = pos;
      break;
    }
    case SYS_CLOSE:
    {
      int num_args = 1;
      uint32_t args[num_args];

      /* Extract arguments. */
      extract_args (args, f, num_args);

      /* Close the FD. */
      if (args[0] == STDIN_FILENO || args[0] == STDOUT_FILENO)
        break;
      else
        process_close_file (args[0]);
      break;
    }
    break;
  }

}
