// Reads a file with sendfile(2), to exercise the NFS splice read path.
#include <fcntl.h>
#include <stdio.h>
#include <sys/sendfile.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s FILE\n", argv[0]);
        return 2;
    }

    int in = open(argv[1], O_RDONLY);
    int out = open("/dev/null", O_WRONLY);
    struct stat st;
    if (in < 0 || out < 0 || fstat(in, &st) < 0) {
        perror("open");
        return 1;
    }

    off_t off = 0;
    while (off < st.st_size) {
        if (sendfile(out, in, &off, st.st_size - off) <= 0) {
            perror("sendfile");
            return 1;
        }
    }
    return 0;
}
