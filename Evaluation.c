#include "Evaluation.h"
#include "Shell.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int evaluateExpr(Expression *expr) {
  static int first = 1;
  if (first) {
    // code d'initialisation
    first = 0;
  }
  //executer une commande externe simple donc le type d'expr est ET_SIMPLE
  if (expr->type == ET_SIMPLE) {
    int status;
    //premier arg sera la commande et la reste sera liste d'args
    char * cmd = expr->argv[0];
    //stocker l'adresse de argv[1] pour l'utiliser en execvp
    char ** listArgs = &expr->argv[0];
    //Il faut conserver le shell donc il faut creer un processus fils
    pid_t pid;
    if ((pid = fork()) < 0) {
      perror("fork error");
      exit(EXIT_FAILURE);
    } else if (pid > 0) {
      //processus pere attendra la termination de son fils et recupere le "exit status"
      if (waitpid(pid, &status, 0) != pid ) {
        fprintf(stderr, "waitpid error\n"); 
        exit(EXIT_FAILURE);
      }
    } //processus fils 
    else {
      execvp(cmd, listArgs);
      fprintf(stderr, "exec error\n"); //Ajouter le cas d'erreur apres execvp 
      exit(EXIT_FAILURE);
    }
    //Il faut modifier le shellStatus en utilisant les macros definis en <sys/wait.h>
    if (WIFEXITED(status)) {
      shellStatus = WEXITSTATUS(status);
    } else {  
      shellStatus = 1;
    }
  }
  return shellStatus;
}
