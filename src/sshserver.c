/*
 * Copyright (c) 2025-2025, yanruibinghxu@gmail.com All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include "core.h"

static void sigchld_handler_with_count(int signo, siginfo_t *info, void *context) {
    (void)signo;
    (void)context;

    if (info->si_pid > 0) {
        log_warn("Session (PID %d) exited.", info->si_pid);
    }
}

#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void handle_session(ssh_event event, ssh_session session) {
    ssh_channel channel;
    int rc;

    // Create a new channel for interaction
    channel = ssh_channel_new(session);
    if (channel == NULL) {
        log_error("Failed to create SSH channel %s", ssh_get_error(session));
        return;
    }

    // Request a PTY (pseudo terminal) for the session to run a shell
    rc = ssh_channel_request_pty(channel);
    if (rc != SSH_OK) {
        log_error("Failed to request PTY for the channel\n");
        ssh_channel_free(channel);
        return;
    }

    // Request a shell for the user (typically /bin/bash)
    rc = ssh_channel_request_shell(channel);
    if (rc != SSH_OK) {
        log_error("Failed to request shell for the channel\n");
        ssh_channel_free(channel);
        return;
    }

    // Start interacting with the channel (handle I/O between SSH client and server)
    char buffer[1024];
    int nbytes;

    while (1) {
        // Read input from the client (SSH client sending data)
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        if (nbytes == SSH_ERROR) {
            log_error("Error reading from SSH channel\n");
            break;
        }
        if (nbytes == 0) {
            break;  // No more data, client disconnected
        }

        // Write the input to the channel (send response to client)
        int nwrite = ssh_channel_write(channel, buffer, nbytes);
        if (nwrite != nbytes) {
            log_error("Error writing to SSH channel\n");
            break;
        }
    }

    // Close the channel and free it
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
}


void ct_ssh_init(ct_ssh_server_t *ssh) {
    ssh->sshbind = NULL;
    ssh->session_count = 0;
}

int ct_ssh_loop(ct_ssh_server_t *ssh) {
    int rc;
    ssh_session session = NULL;
    struct sigaction sa;

    sa.sa_sigaction = sigchld_handler_with_count;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    /* Initialize global cryptographic data structures.*/
    rc = ssh_init();
    if (rc != SSH_OK) {
        log_error("ssh_init failed\n");
        return CT_ERROR;
    }

    /* Creates a new SSH server bind. */
    ssh->sshbind = ssh_bind_new();
    if (ssh->sshbind == NULL) {
        log_error("ssh_bind_new failed\n");
        ssh_finalize();
        return CT_ERROR;
    }

    const char *rsa_key_path = "/home/yrb/src/container/key/ssh_host_rsa_key";
    const char *ecdsa_key_path = "/home/yrb/src/container/key/ssh_host_ecdsa_key";
    const char *ed25519_key_path = "/home/yrb/src/container/key/ssh_host_ed25519_key";

    rc = ssh_bind_options_set(ssh->sshbind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
    if (rc != SSH_OK) {
        log_error("Failed to set bind address: %s", ssh_get_error(ssh->sshbind));
        ssh_finalize();
        return CT_ERROR;
    }
    int port = 2222;
    rc = ssh_bind_options_set(ssh->sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    if (rc < 0) {
        log_error("Failed to set SSH bind port: %s\n", ssh_get_error(ssh->sshbind));
        ssh_finalize();
        return CT_ERROR;
    }

    rc = ssh_bind_options_set(ssh->sshbind, SSH_BIND_OPTIONS_HOSTKEY, rsa_key_path);
    if (rc != SSH_OK) {
        log_error("Failed to set RSA host key: %s", ssh_get_error(ssh->sshbind));
        ssh_finalize();
        return CT_ERROR;
    }

    rc = ssh_bind_options_set(ssh->sshbind, SSH_BIND_OPTIONS_HOSTKEY, ecdsa_key_path);
    if (rc != SSH_OK) {
        log_error("Failed to set ECDSA host key: %s", ssh_get_error(ssh->sshbind));
        ssh_finalize();
        return CT_ERROR;
    }

    rc = ssh_bind_options_set(ssh->sshbind, SSH_BIND_OPTIONS_HOSTKEY, ed25519_key_path);
    if (rc != SSH_OK) {
        log_error("Failed to set ED25519 host key: %s", ssh_get_error(ssh->sshbind));
        ssh_finalize();
        return CT_ERROR;
    }

    log_info("Attempting to bind SSH server to port 2222...");

    rc = ssh_bind_listen(ssh->sshbind);
    if (rc < 0) {
        log_error("ssh_bind_listen failed %s", ssh_get_error(ssh->sshbind));
        ssh_bind_free(ssh->sshbind);
        ssh_finalize();
        return CT_ERROR;
    }

    while (1) {
        session = ssh_new();
        if (session == NULL) {
            log_error("Failed to allocate session");
            continue;
        }

        /* Blocks until there is a new incoming connection. */
        rc = ssh_bind_accept(ssh->sshbind, session);
        if (rc != SSH_ERROR) {
            log_info("New session started. Active sessions: %d", ++ssh->session_count);

            ssh_event event;
            pid_t pid = fork();
            if (pid == 0) {
                /* Remove socket binding, which allows us to restart the
                 * parent process, without terminating existing sessions. */
                ssh_bind_free(ssh->sshbind);

                event = ssh_event_new();
                if (event != NULL) {
                    /* Blocks until the SSH session ends by either
                     * child process exiting, or client disconnecting. */
                    handle_session(event, session);
                    ssh_event_free(event);
                } else {
                    log_error("Could not create polling context");
                }
                ssh_disconnect(session);
                ssh_free(session);
                exit(0);
            } else if (pid > 0) {
                ssh_free(session);
            } else {
                ssh_disconnect(session);
                ssh_free(session);
            }
        }
    }

    ssh_bind_free(ssh->sshbind);

    return CT_OK;
}