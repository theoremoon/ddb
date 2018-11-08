/*
  $ gcc -Wl,-z,now,-z,relro yosh.c -o yosh -fstack-protector -fPIE -pie
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

char whitelist[][8] = {"ls", "whoami", "pwd"};

void yosh()
{
  char *cmdline;
  char cmd[64];
  size_t n = NULL;
  int i, cmdlen;

  while(1) {
    printf("$ ");
    getline(&cmdline, &n, stdin);
    for(i = 0; i < strlen(cmdline); i++) {
      if (cmdline[i] == '\n') {
	cmdline[i] = 0;
      }
    }
    if (cmdline[0] == 0) continue;
    cmdlen = strlen(cmdline);

    strncpy(cmd, strtok(cmdline, " "), 63);
    
    for(i = 0; i < 3; i++) {
      if (strcmp(cmd, "exit") == 0) {
	return;
      }
      if (strcmp(cmd, whitelist[i]) == 0) {
	if (cmdlen > strlen(cmd)) {
	  for(i = strlen(cmd); cmdline[i] == 0; i++) {
	    cmdline[i] = ' ';
	  }
	}
	system(cmdline);
	break;
      }
      if (i == 2) {
	printf("yosh: %s: Command not found\n", cmd);
      }
    }
  }
}

int main(int argc, char** argv)
{
  setbuf(stdout, NULL);
  chdir("/home/pwn100/jail");
  
  puts("\nWelcome to OCamlabBox!\n");
  yosh();
  puts("\nBye...\n");
  
  return 0;
}
