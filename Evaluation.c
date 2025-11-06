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
    pid_t pid;
    if ((pid = fork()) < 0) {
      perror("fork");
      exit(EXIT_FAILURE);
    }
    if (pid > 0) {
      //parent attend pour la termination et retourne le status 
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
    }
    //redirection de "input,output et prolongation" (c'est le fils qui le fait car parent est en attente)
      //On verifie si c'est pas la redirection simultanée 
      if (!expr->redirect.toOtherFd) {
        //On a deja verifie si c'est pas la redirection simultanée donc REDIR_IN est <
        if (expr->redirect.type == REDIR_IN && expr->redirect.fd != -1) {
          //fils fait la redirection 
          if (pid == 0) {
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
            //execute la commande avec "input" redirecté et l'expression a gauche de < comme argument
            evaluateExpr(expr->left);
            exit(EXIT_SUCCESS);
          } 
        } 
        else if (expr->redirect.type == REDIR_OUT && expr->redirect.fd != -1) {
          //fils fait la redirection 
          if (pid == 0) {
            //redirection de "output" pour ecrire a fileName, si le fichier a ecrire n'existe pas, le creer, s'il existe deja,
            //effacer son contenu
            int fd_to_redirect = open(expr->redirect.fileName, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_to_redirect < 0) {
              perror("open");
            } 
            if (dup2(fd_to_redirect, STDOUT_FILENO) < 0) {
              perror("dup2");
              close(fd_to_redirect);
              exit(EXIT_FAILURE);
            };
            close(fd_to_redirect);
            //execute la commande avec "output" redirecté et l'expression a gauche de > comme argument
            evaluateExpr(expr->left);
            exit(EXIT_SUCCESS);
          } 
        }
        else if (expr->redirect.type == REDIR_APP && expr->redirect.fd != -1) {
          //fils fait la redirection 
          if (pid == 0) {
            //redirection de "output" pour ecrire a fileName, si le fichier a ecrire n'existe pas, le creer, s'il existe deja,
            //il faut garder le contenu et ecrire apres le fin, donc on utilise le flag O_APPEND au lieu de O_TRUNC qui efface 
            int fd_to_redirect = open(expr->redirect.fileName, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd_to_redirect < 0) {
              perror("open");
            } 
            if (dup2(fd_to_redirect, STDOUT_FILENO) < 0) {
              perror("dup2");
              close(fd_to_redirect);
              exit(EXIT_FAILURE);
            };
            close(fd_to_redirect);
            //execute la commande avec "output" redirecté et l'expression a gauche de >> comme argument
            evaluateExpr(expr->left);
            exit(EXIT_SUCCESS);
          }
        }
        //On verifie si c'est &> ou &>>
        else if (expr->redirect.fd == -1) {
          //&>
          if (expr->redirect.type == REDIR_OUT) {
            //fils fait la redirection
            if (pid == 0) {
            //redirection de "output et stderr" pour ecrire a fileName, si le fichier a ecrire n'existe pas, le creer, s'il existe deja,
            //effacer son contenu
              int fd_to_redirect = open(expr->redirect.fileName, O_WRONLY | O_CREAT | O_TRUNC, 0644);
              if (fd_to_redirect < 0) {
                perror("open");
              } 
              if (dup2(fd_to_redirect, STDOUT_FILENO) < 0) {
                perror("dup2");
                close(fd_to_redirect);
                exit(EXIT_FAILURE);
              };
              if (dup2(fd_to_redirect, STDERR_FILENO) < 0) {
                perror("dup2");
                close(fd_to_redirect);
                exit(EXIT_FAILURE);
              };
              close(fd_to_redirect);
              //execute la commande avec "output" redirecté et l'expression a gauche de >> comme argument
              evaluateExpr(expr->left);
              exit(EXIT_SUCCESS);
            }
          } else if (expr->redirect.type == REDIR_APP) {
              //fils fait la redirection
              if (pid == 0) {
              //redirection de "output et stderr" pour ecrire a fileName, si le fichier a ecrire n'existe pas, le creer, s'il existe deja,
              //effacer son contenu
              int fd_to_redirect = open(expr->redirect.fileName, O_WRONLY | O_CREAT | O_APPEND, 0644);
              if (fd_to_redirect < 0) {
                perror("open");
              } 
              if (dup2(fd_to_redirect, STDOUT_FILENO) < 0) {
                perror("dup2");
                close(fd_to_redirect);
                exit(EXIT_FAILURE);
              };
              if (dup2(fd_to_redirect, STDERR_FILENO) < 0) {
                perror("dup2");
                close(fd_to_redirect);
                exit(EXIT_FAILURE);
              };
              close(fd_to_redirect);
              //execute la commande avec "output" redirecté et l'expression a gauche de >> comme argument
              evaluateExpr(expr->left);
              exit(EXIT_SUCCESS);
            }
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
  //Pour executer une sequence non conditionnelle, il faut evaluer la gauche et la droite de la sequence comme ils sont des commandes
  if (expr->type == ET_SEQUENCE) {
    evaluateExpr(expr->left);
    evaluateExpr(expr->right);
  }
  //Si l'operateur est OR, Il faut tester si la commande a gauche est execute sans probleme, si c'est pas le cas, il faut executer la commande a droite
  if (expr->type == ET_SEQUENCE_OR) {
    //Il faut tester si la valeur du retour est 0 (pas d'erreur)
    int status;
    status = evaluateExpr(expr->left);
    //Code d'erreur si c'est different de 0
    if (status != 0) {
      evaluateExpr(expr->right);
    }
  }
  //Si l'operateur est AND, 
  //Il faut tester si la commande a gauche est execute sans probleme, si c'est le cas, il faut executer la commande a droite
  //Si la commande a gauche peut executer sans probleme, meme si la deuxieme cmd n'est pas valide, il faut executer la commande (d'après la simulation que j'ai fait sur
  //un shell)
  if (expr->type == ET_SEQUENCE_AND) {
    //Il faut tester si la valeur du retour est 0 (pas d'erreur)
    int status;
    status = evaluateExpr(expr->left);
    //Si et seuelement si la cmd a gauche est bon
    if (status == 0) {
      evaluateExpr(expr->right);
    }
  }
  return 0;
}
