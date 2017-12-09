#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int scan_file(char *virus_path, char *sig_path) {
  long file_size;
  int i, count = 0, match_flag = 0, sig_ptr, file_ptr;
  FILE *sig_file, *virus_file;

  // Assuming the maximum number of signatures is 1024
  char *signatures[1024], *sig_buffer, *virus_buffer;

  //open the signature file and read it
  sig_file = fopen ( sig_path , "rb" );
  if (sig_file==NULL) {
    perror("Error: Unable to open signature file");
    exit(1);
  }

  //get the size of the signature file
  fseek (sig_file , 0 , SEEK_END);
  file_size = ftell (sig_file);
  rewind (sig_file);

  //allocate memory for the signature buffer
  sig_buffer = (char*) malloc (file_size);
  if (sig_buffer == NULL) {
    perror("Error: Unable to allocate memory for signature buffer");
    exit (2);
  }

  //read the signaure file into buffer
  fread (sig_buffer,1,file_size,sig_file);

  //store signatures in an array
  signatures[0] = strtok(sig_buffer, "\n");
  ++count;
  while (1) {
    signatures[count] = strtok(NULL, "\n");
    if (signatures[count] == NULL) {
      break;
    }
    ++count;
  }
  fclose (sig_file);

  //open the file being scanned
  virus_file = fopen ( virus_path , "rb" );
  if (virus_file==NULL) {
    perror("Error: Unable to open signature file");
    exit(1);
  }

  //get size of the file
  fseek (virus_file , 0 , SEEK_END);
  file_size = ftell (virus_file);
  rewind (virus_file);

  //allocate memory for the buffer
  virus_buffer = (char*) malloc (file_size);
  if (virus_buffer == NULL) {
    perror("Error: Unable to allocate memory for virus buffer");
    exit (2);
  } 

  //read the file being scanned into buffer
  fread (virus_buffer,1,file_size,virus_file);

  //match signatures -- a simple way
  //search for each signature in the signature array
  for(i = 0; i < count; ++i) {
    //search the virus file for the signature substring
    for(file_ptr = 0; file_ptr < file_size; ++file_ptr){
      int characters_matched = 0;
      for(sig_ptr = 0; sig_ptr < strlen(signatures[i]); ++sig_ptr) {
        if(*(signatures[i]+sig_ptr) != virus_buffer[file_ptr]) {
          break;
        }
        ++characters_matched;
        ++file_ptr;
        /*if the no of character matched so far equals 
        **the length of the signature, we found the 
        **signature in the file*/
        if(characters_matched == strlen(signatures[i])) {
          match_flag = 1;
          printf("\tMatched signature %d - %s\n", i+1, signatures[i]);
          //move pointer to end of the file so loop exits to match next signature
          file_ptr = file_size;
        }
      }
    }
  }
  //if no signatures were matched.
  if(match_flag == 0) {
    printf("\tNo signatures matched.\n");
  }
  fclose (virus_file);
  free (sig_buffer);
  free(virus_buffer);
  return 0;
}

int recursive_scan(char *path, char *sig_path) {
  DIR *dir;
  struct dirent *file;
  struct stat sb;
  char currentPath[FILENAME_MAX];
  //open the directory
  if ((dir = opendir (path)) != NULL) {
    //get the absolute path of the directory
    if(!realpath(path, currentPath)) {
      perror("Error: Unable to get absolute path of the directory");
      return -1;
    }
    //read each file withn the direcotry
    while ((file = readdir (dir)) != NULL) {
      //Do not scan the current direcotry and the one direcotry up
      if (!strcmp(file->d_name, ".") || !strcmp(file->d_name, "..")) {
        continue;
      }
      //construct absolute path of the file being scanned
      char *abs_path = malloc(strlen(currentPath) + strlen(file->d_name) + 2);
      strcpy(abs_path, currentPath);
      strcat(abs_path, "/");
      strcat(abs_path, file->d_name);
      //get details of the file to determine if it is a directory
      if(lstat (abs_path, &sb) < 0) {
        perror("lstat");
      } else {
        if (S_ISDIR(sb.st_mode)) {          
          printf("\n\nFound new sub directory %s\n",file->d_name);
          printf("--------Scan results for sub directory %s--------\n",file->d_name);
          char *new_path = malloc(strlen(path) + strlen(file->d_name) + 2);
          strcpy(new_path, path);
          strcat(new_path, "/");
          strcat(new_path, file->d_name);
          //recursively scan all sub directories
          recursive_scan(new_path,sig_path);
          printf("\n--------Scan complete for sub directory %s--------\n",file->d_name);
        } else {
          printf("\nScan results for the file - %s\n",file->d_name);
          printf("----------------------------------------\n");
          char *virus_path = malloc(strlen(path) + strlen(file->d_name) + 2);
          strcpy(virus_path, path);
          strcat(virus_path, "/");
          strcat(virus_path, file->d_name);
          scan_file(virus_path, sig_path);          
        }
      }      
    }
    closedir (dir);
  }
  return 0;
}

int main (int argc, char **argv) {
  // check if the number of arguments passed is 3 including the executable name
  if (argc != 3) {
    fprintf(stderr, "Usage: %s directory signature_file\n", *argv);
    exit(1);
  }
  //get the absolute path of the signature file.
  char sigPath[FILENAME_MAX];
  if(!realpath(argv[2], sigPath))
    perror("realpath");
  //recursively scan the given directory
  recursive_scan(argv[1],sigPath);
  return 0;
}
