#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sched.h>

static int pivot_root(const char *new_root, const char *put_old) {
    return syscall(SYS_pivot_root, new_root, put_old);
}

void check_mount_point(const char *path) {
    struct statfs fs;
    if (statfs(path, &fs)) {
        perror("statfs failed");
        exit(1);
    }
    printf("%s is mounted on filesystem type: %lx\n", path, fs.f_type);
}

void check_subdir(const char *parent, const char *child) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", parent, child);
    if (access(path, F_OK) < 0) {
        perror("access failed");
        exit(1);
    }
    printf("%s is a valid subdirectory of %s\n", child, parent);
}

void check_filesystem(const char *path1, const char *path2) {
    struct statfs fs1, fs2;
    if (statfs(path1, &fs1) < 0 || statfs(path2, &fs2) < 0) {
        perror("statfs failed");
        exit(1);
    }
    if (fs1.f_type == fs2.f_type) {
        fprintf(stderr, "%s and %s are on the same filesystem\n", path1, path2);
        exit(1);
    }
    printf("%s and %s are on different filesystems\n", path1, path2);
}

void setup_namespace() {
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root\n");
        exit(1);
    }

    if (unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS) < 0) {
        perror("unshare failed");
        exit(1);
    }

    pid_t pid = getpid();
    char session_root[256];
    snprintf(session_root, sizeof(session_root), "/tmp/session_%d", pid);

    if (mkdir(session_root, 0755) < 0 && errno != EEXIST) {
        perror("mkdir session_root failed");
        exit(1);
    }

    if (mount("none", session_root, "tmpfs", 0, "") < 0) {
        perror("mount session_root failed");
        exit(1);
    }
    check_mount_point(session_root);

    char old_root[256];
    snprintf(old_root, sizeof(old_root), "%s/old_root", session_root);

    if (mkdir(old_root, 0755) < 0 && errno != EEXIST) {
        perror("mkdir old_root failed");
        exit(1);
    }
    check_subdir(session_root, "old_root");

    if (mount("/", old_root, NULL, MS_BIND, NULL) < 0) {
        perror("mount old_root failed");
        exit(1);
    }
    check_filesystem(session_root, old_root);

    if (chdir(session_root) < 0) {
        perror("chdir session_root failed");
        exit(1);
    }

    if (pivot_root(session_root, old_root) < 0) {
        perror("pivot_root failed");
        exit(1);
    }

    if (chdir("/") < 0) {
        perror("chdir to new / failed");
        exit(1);
    }

    // 强制卸载 /old_root
    if (umount2("/old_root", MNT_DETACH | MNT_FORCE) < 0) {
        perror("umount old_root failed");
        exit(1);
    }

    // 检查 /old_root 是否仍然挂载
    // struct statfs fs;
    // if (statfs("/old_root", &fs) == 0) {
    //     printf("/old_root is still mounted\n");
    // } else {
    //     printf("/old_root is unmounted\n");
    // }

    // // 清空 /old_root
    // if (system("rm -rf /old_root/*") != 0) {
    //     perror("failed to clear /old_root");
    //     exit(1);
    // }

    // 清空 /old_root 之前检查它是否仍然存在
    struct stat old_root_stat;
    if (stat("/old_root", &old_root_stat) == 0) {
        // /old_root 存在，执行删除操作
        if (system("rm -rf /old_root/*") != 0) {
            perror("failed to clear /old_root");
            // exit(1);
        }
    } else {
        printf("/old_root does not exist, skipping clearing.\n");
    }


    // 删除 /old_root
    if (rmdir("/old_root") < 0) {
        perror("rmdir old_root failed");
        // exit(1);
    }

    if (mkdir("/tmp", 0755) < 0 && errno != EEXIST) {
        perror("mkdir /tmp failed");
        exit(1);
    }

    if (mkdir("/home", 0755) < 0 && errno != EEXIST) {
        perror("mkdir /home failed");
        exit(1);
    }

    printf("Namespace setup complete! Isolated environment created.\n");
}

int main() {
    setup_namespace();
    return 0;
}