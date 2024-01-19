#include "userfs.h"
#include <stdio.h>

int main() {
    int fd = ufs_open("file", 0);
    if (fd != -1) {
        puts("Opening unexisting file");
        return 1;
    }
    fd = ufs_open("file", UFS_CREATE);
	if (fd == -1) {
        puts("File creating failed");
        return 1;
    }
	ufs_close(fd);
        
    puts("ok");
    return 0;
}