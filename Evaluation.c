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
  //Pipeline de plusieurs commandes, pour cela, d'abord, on va caluler le nombre de pipes pour creer le tableau qu'on va les stocker
  if (expr->type == ET_PIPE) {
    //cpt sera le nombre de pipe a creer
    int cpt = 0;
    Expression *cur = expr;
    while (cur && cur->type == ET_PIPE) {
      cpt = cpt+1;
      cur = cur->left;
    }
    //Tableau a 2 dimensions car il faut qu'on stocke cpt pipes
    int fd[cpt][2];
    //Il y'aura cpt+1 commandes pour cpt pipes
    Expression *cmds[cpt+1];
    //Il faut conserver le shell donc il faut creer cpt+1 processus fils (chaque iteration)
    pid_t pids[cpt+1];
    int status[cpt+1];

    //Creation des pipes
    for (int i=0; i<cpt; i++) {
      pipe(fd[i]);
    }
    //On part de la racine
    cur = expr;
    //On recupere les commandes sauf le premier (le plus a gauche)
    for (int i = cpt; i >= 1; i--) {
      cmds[i] = cur->right;     //la commande située à droite du pipe courant
      cur = cur->left;          //vers la gauche
    }
    //On ajoute la toute premiere commande (la plus a gauche)
    cmds[0] = cur;
    //On cree les fils
    for (int i = 0; i <= cpt; i++) {
      pid_t pid;
      if ((pid = fork()) < 0) {        
        perror("fork");
      }
      if (pid == 0) {
        //Une expr peut etre connecte a 2 pipes differentes comme c'est une chaine
        if (i>0) {
          dup2(fd[i-1][0], STDIN_FILENO);
        } 
        if (i < cpt) {
          dup2(fd[i][1], STDOUT_FILENO);
        }
        //On ferme les extremites
        for (int i = 0; i < cpt; i++) {
          close(fd[i][0]);
          close(fd[i][1]);
        }
        //execution de commande
        execvp(cmds[i]->argv[0], cmds[i]->argv);
        perror("execvp");
      } //pere
      else {
        //pour utiliser dans waitpid
        pids[i] = pid;
      } 

    }
    for (int i = 0; i < cpt; i++) {
      close(fd[i][0]);
      close(fd[i][1]);
    }
    for (int i = 0; i <= cpt; i++) {
      if (waitpid(pids[i], &status[i], 0) != pids[i]) {
        perror("waitpid");
      }
    }
    int last = status[cpt];
    if (WIFEXITED(last)) {
      shellStatus = WEXITSTATUS(last);
    } else {  
      shellStatus = 1;
    }
    return shellStatus;
  }
  return 0;
}
