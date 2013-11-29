#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_parser.h"

char* first_non_whitspace(char* line)
{
   size_t k = 0;
   for(k=0; k < strlen(line); ++k)
     {
	if(isspace(line[k]))
	  {
	     continue;
	  }
	break;
     }
   return &line[k];
}

int is_empty(FILE* file)
{
   int ch = getc(file);
   if(ch == EOF)
     {
	return 1;
     }
   ungetc(ch, file);
   return 0; //no empty
}

char* parse_value(char* line)
{
   char* as_op = memchr(line, '=', strlen(line));
   if(as_op == NULL)
     {
	return NULL;
     }
   
   size_t buf_size = 32;
   char* buf = (char*) malloc(sizeof(char) * buf_size);
   size_t i = 0;
   for(i=0; i < buf_size; ++i)
     {
	buf[i] = 0x00;
     }
   
   size_t begin, end;
   for(begin = as_op-line+1; begin < strlen(line); ++begin)
     {
	if(isspace(line[begin]))
	  {
	     continue;
	  }
	break;
     }
   
   for(end = (strlen(line)-1); end > (as_op-line+1); --end)
     {
	if(isspace(line[end]))
	  {
	     continue;
	  }
	break;
     }
   
   char readed_ch;
   size_t buf_index = 0;
   size_t count = 0;
   
   size_t k = 0;
   for(k = begin; k < end; ++k)
     {
	if(buf_size == (count - 1))
	  {
	     buf = realloc(buf, sizeof(char)*buf_size);
	     for(i=buf_index; i < (buf_size+buf_index); ++i)
	       {
		  buf[i] = 0x00;
	       }
	     count = 0;
	     
	  }
	readed_ch = line[k];
	if( readed_ch == '#' ) 
	  {
	     buf[buf_index] = '\n';
	     break;
	  }	
	buf[buf_index] = readed_ch;
	buf_index++;
	count++;
     }
   buf[buf_index] = '\n';
   return buf;
}

char* get_value(char* key)
{
   char* line;
   FILE* init_file = fopen(CONF_FILE_WITH_PATH, "r");

   if(init_file == NULL)
     {
	return NULL;
     }
   
   if(is_empty(init_file))
     {
	return NULL; //Empty file
     }
   
   int has_next_line = 1; //1 = has next line 
   while(1)
     {	
	line = readline(init_file, &has_next_line);
	if( (*first_non_whitspace(line) == '#') ||
	    (*first_non_whitspace(line) == '[') )
	  {
	     free(line);
	     continue;
	  }
	char* assigment_op = memchr(line, '=', strlen(line));
	if(assigment_op == NULL)
	  {
	     free(line);
	     continue;
	  }
	char* key_line = (char*)malloc(sizeof(char)*(assigment_op-line));
	strncpy(key_line, line, assigment_op-line);
	
	if(strstr(key_line, key))
	  {
	     char* value;
	     if((value = parse_value(line)) == NULL)
	       {
		  free(key_line);
		  free(line);
		  return NULL;
	       }
	     free(key_line);
	     free(line);
	     return value;
	  }
	free(key_line);
	free(line);
	if(has_next_line == 0)
	  {
	     break;
	  }
     }
   return NULL;
}

int fill_ta_dir_path(struct Emulator_config *conf)
{
   char* value;
   if((value=get_value("ta_dir_path")) == NULL)
      {
	 return 0;
      }
   strncpy(conf->ta_dir_path, value, strlen(value));
   free(value);
   return 1;
}

int get_config(struct Emulator_config *conf)
{
   if(!fill_ta_dir_path(conf))
     {
	return 0;
     }
   return 1;
}

char* readline(FILE* file, int* has_next_line)
{
   size_t buf_size = 64;
   char* line_buf = (char*) malloc(sizeof(char) * buf_size);
   size_t i = 0;
   for(i=0; i < buf_size; ++i)
     {
	line_buf[i] = 0x00;
     }
   
   char readed_ch;
   size_t buf_index = 0;
   size_t count = 0;
   
   while( readed_ch != '\n' )
     {
	if(buf_size == (count - 1))
	  {
	     line_buf = realloc(line_buf, sizeof(char)*buf_size);
	     for(i=buf_index; i < (buf_size+buf_index); ++i)
	       {
		  line_buf[i] = 0x00;
	       }
	     count = 0;
	     
	  }
	readed_ch = getc(file);
	if( readed_ch == EOF ) 
	  {
	     line_buf[buf_index] = '\n';
	     *has_next_line = 0;
	     break;
	  }	
	line_buf[buf_index] = readed_ch;
	buf_index++;
	count++;
     }
   return line_buf;
}
