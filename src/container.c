
#define _GNU_SOURCE
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "core.h"

// #define PORT "2222"
// #define OVERLAY_BASE "/overlay"
// #define SHARED_FOLDER "/shared_folder"
// #define MNT_TARGET "/mnt"

// void setup_overlayfs(const char *user_id) {
//     char workdir[256], upperdir[256], mountdir[256], options[512];

//     snprintf(workdir, sizeof(workdir), "%s/%s/work", OVERLAY_BASE, user_id);
//     snprintf(upperdir, sizeof(upperdir), "%s/%s/upper", OVERLAY_BASE, user_id);
//     snprintf(mountdir, sizeof(mountdir), "%s/%s", MNT_TARGET, user_id);

//     mkdir(workdir, 0755);
//     mkdir(upperdir, 0755);
//     mkdir(mountdir, 0755);

//     snprintf(options, sizeof(options), "lowerdir=%s,upperdir=%s,workdir=%s", SHARED_FOLDER, upperdir, workdir);
//     if (mount("overlay", mountdir, "overlay", 0, options) != 0) {
//         perror("mount overlay failed");
//         exit(EXIT_FAILURE);
//     }

//     printf("User %s mounted at %s\n", user_id, mountdir);
// }

// void cleanup_overlayfs(const char *user_id) {
//     char mountdir[256];
//     snprintf(mountdir, sizeof(mountdir), "%s/%s", MNT_TARGET, user_id);

//     if (umount(mountdir) != 0) {
//         perror("umount overlay failed");
//     } else {
//         printf("Unmounted %s\n", mountdir);
//     }

//     rmdir(mountdir);
// }

// void start_user_session(const char *user_id, int client_fd) {
//     setsid();  // 创建新的 Session
//     unshare(CLONE_NEWNS);  // 创建新的 Mount Namespace

//     setup_overlayfs(user_id);

//     char mountdir[256];
//     snprintf(mountdir, sizeof(mountdir), "%s/%s", MNT_TARGET, user_id);
//     chdir(mountdir);

//     dup2(client_fd, STDIN_FILENO);
//     dup2(client_fd, STDOUT_FILENO);
//     dup2(client_fd, STDERR_FILENO);
//     close(client_fd);

//     execlp("/bin/bash", "bash", "--rcfile", NULL);
    
//     cleanup_overlayfs(user_id);
//     exit(EXIT_SUCCESS);
// }

// void handle_ssh_session(ssh_session session) {
//     if (ssh_handle_key_exchange(session) != SSH_OK) {
//         fprintf(stderr, "Key exchange failed: %s\n", ssh_get_error(session));
//         ssh_disconnect(session);
//         ssh_free(session);
//         return;
//     }

//     if (ssh_userauth_password(session, "user", "password") != SSH_AUTH_SUCCESS) {
//         fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));
//         ssh_disconnect(session);
//         ssh_free(session);
//         return;
//     }

//     ssh_channel channel = ssh_channel_new(session);
//     if (channel == NULL || ssh_channel_open_session(channel) != SSH_OK) {
//         fprintf(stderr, "Failed to open channel: %s\n", ssh_get_error(session));
//         ssh_disconnect(session);
//         ssh_free(session);
//         return;
//     }

//     ssh_channel_request_pty(channel);
//     ssh_channel_request_shell(channel);

//     int client_fd = ssh_get_fd(channel);
//     const char *user_id = ssh_userauth_none(session, NULL);

//     pid_t pid = fork();
//     if (pid == 0) {
//         start_user_session(user_id, client_fd);
//     } else {
//         waitpid(pid, NULL, 0);
//         ssh_channel_close(channel);
//         ssh_channel_free(channel);
//         ssh_disconnect(session);
//         ssh_free(session);
//     }
// }

// void start_ssh_server() {
//     ssh_bind sshbind = ssh_bind_new();
//     ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &PORT);
//     ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "ssh_host_rsa_key");

//     if (ssh_bind_listen(sshbind) < 0) {
//         fprintf(stderr, "Error listening: %s\n", ssh_get_error(sshbind));
//         return;
//     }

//     printf("SSH server running on port %s\n", PORT);

//     while (1) {
//         ssh_session session = ssh_new();
//         if (ssh_bind_accept(sshbind, session) == SSH_OK) {
//             handle_ssh_session(session);
//         } else {
//             fprintf(stderr, "Error accepting connection\n");
//             ssh_free(session);
//         }
//     }

//     ssh_bind_free(sshbind);
// }

int main() {
    ct_ssh_server_t ssh;

    ssh_set_log_level(SSH_LOG_DEBUG);
    ssh_set_log_level(SSH_LOG_TRACE);
    
    ct_ssh_init(&ssh);
    ct_ssh_loop(&ssh);
    return 0;
}
