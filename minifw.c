#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define FILENAME "/proc/fwb"

int main ( int argc, char ** argv )
{
  int status = 0;
  FILE * fin, * fout;
  char * word;

  if ( argc!=2 && argc != 11 ) // check if correct number of arguments
    {
      printf("invalid arguments\n");
      exit(0);
    }

  //*********************** run, exit, lsrules ***********************/

  if (argc == 2) //non rules
    {
      if (strcasecmp(argv[1], "run") == 0) // run command
	{
	  pid_t pid = fork();
	  if(pid!=0)//parent
	    {
	      waitpid(-1,&status,0);
	      //load rules into proc
	      fin = fopen("fwrules.txt","r");
	      fout = fopen(FILENAME,"w");
	      word=(char*)malloc(1024*sizeof(char));
	      while(!feof(fin))
		{
		  fgets(word,1024,fin);
		  fprintf(fout,"%s",word);
		}
	      free(word);
	      word=NULL;
	      fclose(fin);
	      fclose(fout);
	    }
	  else
	    {
	      char* run[4] = {"sudo","insmod","fwmod.ko",NULL};
	      status=execvp(run[0],run);
	      if(status==-1)//bad command
		exit(0);
	    }
	
	}
      if(strcasecmp(argv[1],"exit")==0) // exit command
	{
	  pid_t pid = fork();
	  if(pid!=0)//parent
	    {
	      waitpid(-1,&status,0);

	      char* remove[4] = {"sudo","rmmod","fwmod",NULL};
	      status=execvp(remove[0],remove);
	      if(status==-1)//bad command
		exit(0);
	    }
	  else
	    {
	      fin = fopen(FILENAME,"r");
	      fout = fopen("fwrules.txt","w");
	      word=(char*)malloc(1024*sizeof(char));
	      while(!feof(fin))
		{
		  fgets(word,1024,fin);
		  fprintf(fout,"%s",word);
		}
	      free(word);
	      word=NULL;
	      fclose(fin);
	      fclose(fout);
	    }
	  
	}
      if(strcasecmp(argv[1],"lsrules")==0)//print command
	{

	  word=(char*)malloc(1024*sizeof(char));
	  fin = fopen(FILENAME,"r");
	  while(!feof(fin))
	    {
	      fgets(word,1024,fin);
	      printf("%s",word);
	    }
	  fclose(fin);
	  free(word);
	  word=NULL;
	}
    }
  // *********************************** add rule ********************/
  else //rules
    {
      word=(char*)malloc(1024*sizeof(char));
      fin = fopen(FILENAME,"w");
      strcat(word,argv[1]);
      strcat(word," ");
      strcat(word,argv[2]);
      strcat(word," ");
      strcat(word,argv[3]);
      strcat(word," ");
      strcat(word,argv[4]);
      strcat(word," ");
      strcat(word,argv[5]);
      strcat(word," ");
      strcat(word,argv[6]);
      strcat(word," ");
      strcat(word,argv[7]);
      strcat(word," ");
      strcat(word,argv[8]);
      strcat(word," ");
      strcat(word,argv[9]);
      strcat(word," ");
      strcat(word,argv[10]);
      strcat(word,"\n");
      fprintf(fin,"%s",word);//append to file
      fclose(fin);
      free(word);
      word=NULL;
    }
}
