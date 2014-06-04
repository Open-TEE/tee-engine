/*****************************************************************************
** Copyright (C) 2013 Intel Corporation.                                    **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<linux/inotify.h>
#include<sys/epoll.h>
#include<dirent.h>

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN  ( 1024 * ( EVENT_SIZE + 16 ) )

char* concat(char *s1, char *s2) {
    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);
    char *result = malloc(len1+len2+1);

    memcpy(result, s1, len1);
    memcpy(result+len1, s2, len2+1);
    return result;
}

int read_metadata(FILE* elf_file) {
    // TODO
}

int read_ELF_file_for_metadata(char* elf_file_path) {
    FILE *elf_file;
    elf_file=fopen(elf_file_path,"r");
    if(!elf_file) {
        printf("Cannot open elf file : %s", elf_file_path);
        exit(-1);
    }
    read_metadata(elf_file);
    fclose(elf_file);
}

int init_directory_scan(char* dir_path) {
    int num_read;
    int inotify_fd;
    int inotify_wd;
    char inotify_buffer[EVENT_BUF_LEN];
    int epoll_fd;
    int epoll_cfg;
    int ret;
    struct epoll_event event;
    char* elf_file_path;

    printf("Directory to be scanned : %s \n", dir_path);

    /* Initializing inotify */
    inotify_fd = inotify_init();

    if ( inotify_fd < 0 ) {
        printf( "inotify initialization failed \n" );
        exit(-1);
    } else {
        printf( "inotify initialized successful \n" );
    }

    /*Add a directory watch for addition of new file*/
    inotify_wd = inotify_add_watch(inotify_fd, dir_path, IN_CREATE);

    if (inotify_wd == -1) {
        printf( "inotify add watch for directory failed.  \n" );
        exit(-1);
    } else {
        printf( "inotify add watch for directory is successful.  \n" );
    }

    epoll_fd = epoll_create(sizeof(inotify_fd));
    if (epoll_fd < 0) {
        printf("Could not initialized epoll file descriptor  \n");
        exit(-1);
    } else {
        printf("Initialized epoll file descriptor  \n");
    }

    event.events = EPOLLIN|EPOLLOUT|EPOLLET;
    epoll_cfg = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inotify_fd, &event);
    if (epoll_cfg < 0) {
        printf("Configuring epoll interface failed  \n");
        exit(-1);
    } else {
        printf("Configured epoll interface \n");
    }

    while(1) {
        ret = epoll_wait(epoll_fd, &event, 5, -1);
        if (ret > 0) {
            num_read = read(inotify_fd, inotify_buffer, EVENT_BUF_LEN );
            if (num_read == 0) {
                printf("Error while reading event  \n");
                continue;
            } else if (num_read == -1) {
                printf("Error while reading event  \n");
                continue;
            }

            char *tmp_str;
            struct inotify_event *event;
            for (tmp_str = inotify_buffer; tmp_str < inotify_buffer + num_read; ) {
                event = (struct inotify_event *) tmp_str;
                if (event->len > 0) {
                    elf_file_path = concat(dir_path, event->name);
                    printf("File added : %s\n", elf_file_path);
                    read_ELF_file_for_metadata(elf_file_path);
                }
                tmp_str += sizeof(struct inotify_event) + event->len;
            }
        }
        else if (ret < 0) {
            printf("Error while polling  \n");
            break;
        } else {
            printf("Timed Out  \n");
            break;
        }
    }
    inotify_rm_watch( inotify_fd, inotify_wd );
    close( inotify_fd );
}

int read_existing_binaries(char* dir_path) {
    DIR *d;
    struct dirent *dir;
    char* elf_file_path;

    d = opendir(dir_path);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            elf_file_path = concat(dir_path, dir->d_name);
            printf("%s\n", elf_file_path);
            read_ELF_file_for_metadata(elf_file_path);
        }
        closedir(d);
    }
}

int main(int argc, char **argv) {
    read_existing_binaries("/home/swapnil/tmp/");
    init_directory_scan("/home/swapnil/tmp/");
}
