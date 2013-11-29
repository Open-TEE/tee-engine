#ifndef __CONFIG_PARSER_H__
#define __CONFIG_PARSER_H__


/*! 
 * \file conf_parser.h
 * \brief A simple modul for parsning a TEE emulator configure file. The 
 * configure file syntax is described in config.conf file.
 * 
 * How to Use:
 * 1. Function get_value() is retrieving a value from the configure file, 
 * which corresponds with a key. \sa getvalue()
 * or
 * 2. Function get_config() will populate the given struct, but this should
 * only be used if neccesary implementation is implemented. \sa get_config()
 * 
 * How these two differ from each other?
 * Function get_value() returns a value, which is allocated by malloc and 
 * freeing the allocated memory is the responsibility of users. If you do not 
 * wantfor example to do a  malloc-free-memory operation or want to get all 
 * config at once, you can implement the neccesary implemetation and use 
 * get_config() function.
 * 
 * How can I  add a new config parameter and use get_config()-function?
 * At this point the preferred solution
 * 1.Add a new member to Emulator_config-struct
 * 2.Create a function which will read and add value to struct
 * 3.Call your function in get_config()-function
 * Really simple, See for example fill_ta_dir_path()-function
 */


#define CONF_FILE_WITH_PATH "config.conf"
#define MAX_TA_DIR_PATH 64


/*!
 * \brief Emulator config struct
 * Emulator config parameters
 */
struct Emulator_config
{
   char ta_dir_path[MAX_TA_DIR_PATH]; /*!< Folder that contais TAs */
};


/*!
 * \brief get_config
 * Populates Emulator_config-struct. Should only be used if neccessary
 * steps have been taken. See more details in file description.
 * \param conf is populated struct
 * \return 1 on success, 0 on failure
 */
int get_config(struct Emulator_config *conf);


/*!
 * \brief readline
 * Reading a line from a file
 * \parem file that will be read
 * \param has_next_line 1 if there is next line, 0 if EOF has been read 
 * \return NULL if something has failed (no need freeing allocated memory).
 * In case of success returning pointer to allocated memory (with malloc) 
 * and the line is terminated with newline (\n). Note. user should free 
 * allocated memory.
 */
char* readline(FILE* file, int *has_next_line);


/*!
 * \brief get_value
 * Retrieving a value from configure file that is responding to a key.
 * \param key which value is wanted
 * \return In case of success returning pointer to value. Memory for value 
 * is allocated by malloc and it is the responsibility of a user to free 
 * memory. Value is newline terminated. On failure function will return  
 * NULL and no memory is malloced.
 */
char* get_value(char* key);


/*!
 * \brief is_empty
 * Checking if file is empty. No modifications to file.
 * \param file that is tested
 * \return 0 if file is not empty, 1 if file is empty
 */
int is_empty(FILE* file);


/*!
 * \brief first_non_whitspace
 * Allocate first non whitespace character location from the beginning
 * \param line is handled line
 * \return a pointer to first non whitespace character in line
 */
char* first_non_whitspace(char* line);


/*!
 * \brief parse_value
 * Function is retrieving a value from a line. At the beginning and at the
 * end whitespace is removed.
 * \param line that is containing a key-value pair
 * \return In case of success returning a pointer to value. Memory for value 
 * is allocated by malloc and it is the responsibility of a user to free 
 * memory. Value is newline terminated. In case of failure function will 
 * return NULL and no memory is malloced.
 */
char* parse_value(char* line);


/*!
 * \brief fill_ta_dir_path
 * Fill a TA directory path to Emulator config struct
 * \param conf Struct that contains a member which is populated 
 * \return 1 On success, 0 On failure
 */
int fill_ta_dir_path(struct Emulator_config *conf);

#endif /* __CONFIG_PARSER_H__ */