/* Filename: fifoserver.c */
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "onvm_common.h"


int main(int argc, char *argv[]) {
   int fd;
   char readbuf[80];
   char end[10];
   int to_end;
   int read_bytes;
   
   /* Create the FIFO if it does not exist */
   mknod(get_cont_pipe_name(129), S_IFIFO|0640, 0);
   strcpy(end, "end");
   while(1) {
      fd = open(get_cont_pipe_name(129), O_RDONLY);
      read_bytes = read(fd, readbuf, sizeof(readbuf));
      readbuf[read_bytes] = '\0';
      printf("Received string: \"%s\" and length is %d\n", readbuf, (int)strlen(readbuf));
      to_end = strcmp(readbuf, end);
      if (to_end == 0) {
         close(fd);
         break;
      }
   }
   return 0;
}
