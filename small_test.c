#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/extattr.h>
#include <errno.h>

int main() {
    const char *attrname = "secure";

    // 1. Try to open the file (should trigger taint if user.secure is set)
    int fd = open("b.txt", O_RDONLY);
    if (fd < 0) {
        perror("open");
    } else {
        printf("File opened successfully (fd=%d), now closing.\n", fd);
        close(fd);
    }

    // 2. Attempt to remove extended attribute 'user.secure'
    int ret = extattr_delete_file("a.txt", EXTATTR_NAMESPACE_USER, attrname);
    if (ret == -1) {
        perror("extattr_delete_file");
    } else {
        printf("Attribute 'user.secure' deleted successfully.\n");
    }

    return 0;
}

