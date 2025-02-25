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

static void
exit (int status)
{
  thread_current ()->exit_code = status;
  thread_exit ();
}

/* Returns false on null pointers, pointers that don't point to
   user virtual memory, and pointers to unmapped virtual memory. */
static bool
is_valid_usrc (const uint8_t *usrc)
{
  if (usrc == NULL ||
      !is_user_vaddr (usrc) ||
      pagedir_get_page (thread_current ()->pagedir, usrc) == NULL)
    return false;
  return true;
}
      
/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  if (!is_valid_usrc (uaddr))
    exit (-1);
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
    : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Returns false on bad strings: NULL, no end of string character, or
   invalid user address. */
static bool
is_valid_string (const char *s)
{
  if (s == NULL)
    return false;
  char c;
  while (is_user_vaddr(s) && 
         (c = get_user((const uint8_t *) s)) != -1)
    if (c == '\0')
      return true;
    else
      s++;
  return false;
}
   
static void
copy_in (void *dst_, const void *usrc_, size_t size)
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;

  for (; size > 0; size--, dst++, usrc++)
  {
    int byte = get_user (usrc);
    if (byte == -1)
      exit (-1);
    *dst = byte;
  }
}

static void
extract_args (void *dst, struct intr_frame *f, int num_args)
{
  copy_in ((uint32_t *) dst, (uint32_t *) f->esp + 1, sizeof(uint32_t) * num_args);
}

static void
syscall_handler (struct intr_frame *f) 
{
  unsigned int syscall_number;

  /* Extract syscall number. */
  copy_in (&syscall_number, f->esp, sizeof syscall_number);

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
      if (!is_valid_string ((const char *) args[0]))
        exit (-1);
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
      if (!is_valid_string ((const char *) args[0]))
        exit (-1);
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
      if (!is_valid_string ((const char *) args[0]))
        exit (-1);
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
      uint32_t bytes_read;

      /* Extract arguments. */
      extract_args (args, f, num_args);

      /* Execute the read. */
      if (args[0] == STDIN_FILENO)
      {
        bytes_read = 0;
        for (uint32_t i = 0; i < args[2]; i++, bytes_read++)
          ((char *) args[1])[i] = input_getc ();
      }
      else 
      {
        struct file *f = process_get_file (args[0]);
        if (f == NULL)
          bytes_read = -1;
        else 
        {
          bytes_read = file_read (f, &args[1], (off_t) args[2]);
          if (bytes_read < args[2])
            bytes_read = 0;
        }
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

      /* Execute the write. */
      if (args[0] == STDOUT_FILENO)
      {
        putbuf ((const char *) args[1], args[2]);
        bytes_written = args[2];
      }
      else 
      {
        struct file *f = process_get_file (args[0]);
        if (f == NULL)
          bytes_written = -1;
        else 
          bytes_written = file_write (f, &args[1], (off_t) args[2]);
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
