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
  //redirections  
  if (expr->type == ET_REDIRECT) {
    int status;
    //redirection de "input"
      //On verifie si c'est pas la redirection simultanée 
      if (!expr->redirect.toOtherFd) {
        if (expr->redirect.type == REDIR_IN) {
          pid_t pid;
          if ((pid = fork()) < 0) {
            perror("fork");
            exit(EXIT_FAILURE);
          } //parent attend pour la termination et retourne le status 
          else if (pid > 0) {
            if (waitpid(pid, &status,0) != pid) {
              perror("waitpid");
              exit(EXIT_FAILURE);
            }
            //Il faut modifier le shellStatus en utilisant les macros definis en <sys/wait.h>
            if (WIFEXITED(status)) {
              shellStatus = WEXITSTATUS(status);
            } else {  
              shellStatus = 1;
            }
            return shellStatus;
          } //fils fait la redirection 
          else {
            //redirection de "input" pour liser de fileName
            int fd_to_redirect = open(expr->redirect.fileName, O_RDONLY);
            if (fd_to_redirect < 0) {
              perror("open");
            } 
            if (dup2(fd_to_redirect, STDIN_FILENO) < 0) {
              perror("dup2");
              close(fd_to_redirect);
              exit(EXIT_FAILURE);
            };
            close(fd_to_redirect);
            //execute la commande avec "input" redirecté
            evaluateExpr(expr->left);
            exit(EXIT_SUCCESS);
          } 
        }
      }

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
      perror("fork");
      exit(EXIT_FAILURE);
    } else if (pid > 0) {
      //processus pere attendra la termination de son fils et recupere le "exit status"
      if (waitpid(pid, &status, 0) != pid) {
        perror("waitpid"); 
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
    return shellStatus;
  }

}
