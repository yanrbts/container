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
#include <libssh/callbacks.h>
#include <libssh/server.h>

#include <poll.h>
#include <fcntl.h>
// #include <libutil.h>
#include <pthread.h>
#include <pty.h>
#include <signal.h>
#include <stdlib.h>
#include <utmp.h>
// #include <util.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#ifndef BUF_SIZE
#define BUF_SIZE 1048576
#endif

#define SESSION_END                 (SSH_CLOSED | SSH_CLOSED_ERROR)
#define SFTP_SERVER_PATH            "/usr/lib/sftp-server"
#define AUTH_KEYS_MAX_LINE_SIZE     2048

#define DEF_STR_SIZE 1024
char authorizedkeys[DEF_STR_SIZE] = {0};
char username[128] = "myuser";
char password[128] = "mypassword";

/* A userdata struct for channel. */
struct channel_data_struct {
    pid_t pid;                  /* pid of the child process the channel will spawn. */
    socket_t pty_master;        /* For PTY allocation */
    socket_t pty_slave;
    socket_t child_stdin;       /* For communication with the child process. */
    socket_t child_stdout;
    socket_t child_stderr;      /* Only used for subsystem and exec requests. */
    ssh_event event;            /* Event which is used to poll the above descriptors. */
    struct winsize *winsize;    /* Terminal size struct. */
};

/* A userdata struct for session. */
struct session_data_struct {
    ssh_channel channel;        /* Pointer to the channel the session will allocate. */
    int auth_attempts;
    int authenticated;
};

static int
data_function(ssh_session session,
              ssh_channel channel,
              void *data,
              uint32_t len,
              int is_stderr,
              void *userdata)
{
    struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;

    (void)session;
    (void)channel;
    (void)is_stderr;

    if (len == 0 || cdata->pid < 1 || kill(cdata->pid, 0) < 0) {
        return 0;
    }

    return write(cdata->child_stdin, (char *)data, len);
}

static int
pty_request(ssh_session session,
            ssh_channel channel,
            const char *term,
            int cols,
            int rows,
            int py,
            int px,
            void *userdata)
{
    struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;
    int rc;

    (void)session;
    (void)channel;
    (void)term;

    cdata->winsize->ws_row = rows;
    cdata->winsize->ws_col = cols;
    cdata->winsize->ws_xpixel = px;
    cdata->winsize->ws_ypixel = py;

    /* The openpty() function finds an available pseudoterminal and 
     * returns file descriptors for the master and
     * slave in amaster and aslave.  If name is not NULL, 
     * the filename of the slave is returned  in  name.   
     * If termp  is not NULL, the terminal parameters of 
     * the slave will be set to the values in termp.  If winp is
     * not NULL, the window size of the slave will be set to the values in winp */
    rc  = openpty(&cdata->pty_master,
                 &cdata->pty_slave,
                 NULL,
                 NULL,
                 cdata->winsize);
    
    if (rc != 0) {
        fprintf(stderr, "Failed to open pty\n");
        return SSH_ERROR;
    }
    return SSH_OK;
}

static int
pty_resize(ssh_session session,
           ssh_channel channel,
           int cols,
           int rows,
           int py,
           int px,
           void *userdata)
{
    struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;

    (void)session;
    (void)channel;

    cdata->winsize->ws_row = rows;
    cdata->winsize->ws_col = cols;
    cdata->winsize->ws_xpixel = px;
    cdata->winsize->ws_ypixel = py;

    if (cdata->pty_master != -1) {
        /* This line of code is typically used in the context of 
         * managing a pseudo-terminal (PTY) in Unix-like systems. 
         * It updates the window size of a pseudo-terminal to match the desired size.*/
        return ioctl(cdata->pty_master, TIOCSWINSZ, cdata->winsize);
    }

    return SSH_ERROR;
}

static int
exec_pty(const char *mode,
         const char *command,
         struct channel_data_struct *cdata)
{
    cdata->pid = fork();
    switch (cdata->pid) {
    case -1:
        close(cdata->pty_master);
        close(cdata->pty_slave);
        fprintf(stderr, "Failed to fork\n");
        return SSH_ERROR;
    case 0:
        close(cdata->pty_master);

        /* The  login_tty() function prepares for a login on the terminal fd 
         * (which may be a real terminal device, or the slave of a pseudoterminal 
         * as returned by openpty()) by creating a  new session,  
         * making  fd the controlling terminal for the calling process, 
         * setting fd to be the standard input, output, and error streams 
         * of the current process, and closing fd.*/
        if (login_tty(cdata->pty_slave) != 0) {
            exit(1);
        }
        execl("/bin/sh", "sh", mode, command, NULL);
        exit(0);
    default:
        close(cdata->pty_slave);
        /* pty fd is bi-directional */
        cdata->child_stdout = cdata->child_stdin = cdata->pty_master;
    }
    return SSH_OK;
}

static int
exec_nopty(const char *command, struct channel_data_struct *cdata)
{
    int in[2], out[2], err[2];

    /* Do the plumbing to be able to talk with the child process. */
    if (pipe(in) != 0) {
        goto stdin_failed;
    }
    if (pipe(out) != 0) {
        goto stdout_failed;
    }
    if (pipe(err) != 0) {
        goto stderr_failed;
    }

    cdata->pid = fork();
    switch (cdata->pid) {
    case -1:
        goto fork_failed;
    case 0:
        /* Finish the plumbing in the child process. */
        close(in[1]);
        close(out[0]);
        close(err[0]);
        dup2(in[0], STDIN_FILENO);
        dup2(out[1], STDOUT_FILENO);
        dup2(err[1], STDERR_FILENO);
        close(in[0]);
        close(out[1]);
        close(err[1]);
        /* exec the requested command. */
        execl("/bin/sh", "sh", "-c", command, NULL);
        exit(0);
    }

    close(in[0]);
    close(out[1]);
    close(err[1]);

    cdata->child_stdin = in[1];
    cdata->child_stdout = out[0];
    cdata->child_stderr = err[0];

    return SSH_OK;

fork_failed:
    close(err[0]);
    close(err[1]);
stderr_failed:
    close(out[0]);
    close(out[1]);
stdout_failed:
    close(in[0]);
    close(in[1]);
stdin_failed:
    return SSH_ERROR;
}

static int
exec_request(ssh_session session,
             ssh_channel channel,
             const char *command,
             void *userdata)
{
    struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;

    (void)session;
    (void)channel;

    if (cdata->pid > 0) {
        return SSH_ERROR;
    }

    if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
        return exec_pty("-c", command, cdata);
    }
    return exec_nopty(command, cdata);
}

static int
shell_request(ssh_session session, ssh_channel channel, void *userdata)
{
    struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;

    (void)session;
    (void)channel;

    if (cdata->pid > 0) {
        return SSH_ERROR;
    }

    if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
        return exec_pty("-l", NULL, cdata);
    }
    /* Client requested a shell without a pty, let's pretend we allow that */
    return SSH_OK;
}

static int
subsystem_request(ssh_session session,
                  ssh_channel channel,
                  const char *subsystem,
                  void *userdata)
{
    /* subsystem requests behave similarly to exec requests. */
    if (strcmp(subsystem, "sftp") == 0) {
        return exec_request(session, channel, SFTP_SERVER_PATH, userdata);
    }
    return SSH_ERROR;
}

static int
auth_password(ssh_session session,
              const char *user,
              const char *pass,
              void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *)userdata;

    (void)session;

    if (strcmp(user, username) == 0 && strcmp(pass, password) == 0) {
        sdata->authenticated = 1;
        return SSH_AUTH_SUCCESS;
    }

    sdata->auth_attempts++;
    return SSH_AUTH_DENIED;
}

static int
auth_publickey(ssh_session session,
               const char *user,
               struct ssh_key_struct *pubkey,
               char signature_state,
               void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *)userdata;
    ssh_key key = NULL;
    FILE *fp = NULL;
    char line[AUTH_KEYS_MAX_LINE_SIZE] = {0};
    char *p = NULL;
    const char *q = NULL;
    unsigned int lineno = 0;
    int result;
    int i;
    enum ssh_keytypes_e type;

    (void)user;
    (void)session;

    if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
        return SSH_AUTH_SUCCESS;
    }

    if (signature_state != SSH_PUBLICKEY_STATE_VALID) {
        return SSH_AUTH_DENIED;
    }

    fp = fopen(authorizedkeys, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error: opening authorized keys file %s failed, reason: %s\n",
                authorizedkeys, strerror(errno));
        return SSH_AUTH_DENIED;
    }

    while (fgets(line, sizeof(line), fp)) {
        lineno++;

        /* Skip leading whitespace and ignore comments */
        p = line;

        for (i = 0; i < AUTH_KEYS_MAX_LINE_SIZE; i++) {
            if (!isspace((int)p[i])) {
                break;
            }
        }

        if (i >= AUTH_KEYS_MAX_LINE_SIZE) {
            fprintf(stderr,
                    "warning: The line %d in %s too long! Skipping.\n",
                    lineno,
                    authorizedkeys);
            continue;
        }

        if (p[i] == '#' || p[i] == '\0' || p[i] == '\n') {
            continue;
        }

        q = &p[i];
        for (; i < AUTH_KEYS_MAX_LINE_SIZE; i++) {
            if (isspace((int)p[i])) {
                p[i] = '\0';
                break;
            }
        }

        type = ssh_key_type_from_name(q);

        i++;
        if (i >= AUTH_KEYS_MAX_LINE_SIZE) {
            fprintf(stderr,
                    "warning: The line %d in %s too long! Skipping.\n",
                    lineno,
                    authorizedkeys);
            continue;
        }

        q = &p[i];
        for (; i < AUTH_KEYS_MAX_LINE_SIZE; i++) {
            if (isspace((int)p[i])) {
                p[i] = '\0';
                break;
            }
        }

        result = ssh_pki_import_pubkey_base64(q, type, &key);
        if (result != SSH_OK) {
            fprintf(stderr,
                    "Warning: Cannot import key on line no. %d in authorized keys file: %s\n",
                    lineno,
                    authorizedkeys);
            continue;
        }

        result = ssh_key_cmp(key, pubkey, SSH_KEY_CMP_PUBLIC);
        ssh_key_free(key);
        if (result == 0) {
            sdata->authenticated = 1;
            fclose(fp);
            return SSH_AUTH_SUCCESS;
        }
    }
    if (ferror(fp) != 0) {
        fprintf(stderr,
                "Error: Reading from authorized keys file %s failed, reason: %s\n",
                authorizedkeys, strerror(errno));
    }
    fclose(fp);

    /* no matches */
    return SSH_AUTH_DENIED;
}

static ssh_channel
channel_open(ssh_session session, void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *)userdata;

    sdata->channel = ssh_channel_new(session);
    return sdata->channel;
}

static int
process_stdout(socket_t fd, int revents, void *userdata)
{
    char buf[BUF_SIZE];
    int n = -1;
    ssh_channel channel = (ssh_channel)userdata;

    if (channel != NULL && (revents & POLLIN) != 0) {
        n = read(fd, buf, BUF_SIZE);
        if (n > 0) {
            ssh_channel_write(channel, buf, n);
        }
    }

    return n;
}

static int
process_stderr(socket_t fd, int revents, void *userdata)
{
    char buf[BUF_SIZE];
    int n = -1;
    ssh_channel channel = (ssh_channel)userdata;

    if (channel != NULL && (revents & POLLIN) != 0) {
        n = read(fd, buf, BUF_SIZE);
        if (n > 0) {
            ssh_channel_write_stderr(channel, buf, n);
        }
    }

    return n;
}

/* SIGCHLD handler for cleaning up dead children. */
static void 
sigchld_handler(int signo) {
    (void)signo;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

static void
handle_session(ssh_event event, ssh_session session) {
    int n;
    int rc = 0;

    /* Structure for storing the pty size. */
    struct winsize wsize = {
        .ws_row = 0,
        .ws_col = 0,
        .ws_xpixel = 0,
        .ws_ypixel = 0
    };

    /* Our struct holding information about the channel. */
    struct channel_data_struct cdata = {
        .pid = 0,
        .pty_master = -1,
        .pty_slave = -1,
        .child_stdin = -1,
        .child_stdout = -1,
        .child_stderr = -1,
        .event = NULL,
        .winsize = &wsize
    };

    /* Our struct holding information about the session. */
    struct session_data_struct sdata = {
        .channel = NULL,
        .auth_attempts = 0,
        .authenticated = 0
    };

    struct ssh_channel_callbacks_struct channel_cb = {
        .userdata = &cdata,
        .channel_pty_request_function = pty_request,
        .channel_pty_window_change_function = pty_resize,
        .channel_shell_request_function = shell_request,
        .channel_exec_request_function = exec_request,
        .channel_data_function = data_function,
        .channel_subsystem_request_function = subsystem_request
    };

    struct ssh_server_callbacks_struct server_cb = {
        .userdata = &sdata,
        .auth_password_function = auth_password,
        .channel_open_request_session_function = channel_open,
    };

    if (authorizedkeys[0]) {
        server_cb.auth_pubkey_function = auth_publickey;
        ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
    } else
        ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);

    ssh_callbacks_init(&server_cb);
    ssh_callbacks_init(&channel_cb);

    ssh_set_server_callbacks(session, &server_cb);

    if (ssh_handle_key_exchange(session) != SSH_OK) {
        fprintf(stderr, "%s\n", ssh_get_error(session));
        return;
    }

    ssh_event_add_session(event, session);

    n = 0;
    while (sdata.authenticated == 0 || sdata.channel == NULL) {
        /* If the user has used up all attempts, or if he hasn't been able to
         * authenticate in 10 seconds (n * 100ms), disconnect. */
        if (sdata.auth_attempts >= 3 || n >= 100) {
            return;
        }

        if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
            fprintf(stderr, "%s\n", ssh_get_error(session));
            return;
        }
        n++;
    }

    ssh_set_channel_callbacks(sdata.channel, &channel_cb);

    do {
        /* Poll the main event which takes care of the session, the channel and
         * even our child process's stdout/stderr (once it's started). */
        if (ssh_event_dopoll(event, -1) == SSH_ERROR) {
          ssh_channel_close(sdata.channel);
        }

        /* If child process's stdout/stderr has been registered with the event,
         * or the child process hasn't started yet, continue. */
        if (cdata.event != NULL || cdata.pid == 0) {
            continue;
        }
        /* Executed only once, once the child process starts. */
        cdata.event = event;
        /* If stdout valid, add stdout to be monitored by the poll event. */
        if (cdata.child_stdout != -1) {
            if (ssh_event_add_fd(event, cdata.child_stdout, POLLIN, process_stdout,
                                 sdata.channel) != SSH_OK) {
                fprintf(stderr, "Failed to register stdout to poll context\n");
                ssh_channel_close(sdata.channel);
            }
        }

        /* If stderr valid, add stderr to be monitored by the poll event. */
        if (cdata.child_stderr != -1){
            if (ssh_event_add_fd(event, cdata.child_stderr, POLLIN, process_stderr,
                                 sdata.channel) != SSH_OK) {
                fprintf(stderr, "Failed to register stderr to poll context\n");
                ssh_channel_close(sdata.channel);
            }
        }
    } while (ssh_channel_is_open(sdata.channel) &&
             (cdata.pid == 0 || waitpid(cdata.pid, &rc, WNOHANG) == 0));

    close(cdata.pty_master);
    close(cdata.child_stdin);
    close(cdata.child_stdout);
    close(cdata.child_stderr);

    /* Remove the descriptors from the polling context, since they are now
     * closed, they will always trigger during the poll calls. */
    ssh_event_remove_fd(event, cdata.child_stdout);
    ssh_event_remove_fd(event, cdata.child_stderr);

    /* If the child process exited. */
    if (kill(cdata.pid, 0) < 0 && WIFEXITED(rc)) {
        rc = WEXITSTATUS(rc);
        ssh_channel_request_send_exit_status(sdata.channel, rc);
        /* If client terminated the channel or the process did not exit nicely,
         * but only if something has been forked. */
    } else if (cdata.pid > 0) {
        kill(cdata.pid, SIGKILL);
    }

    ssh_channel_send_eof(sdata.channel);
    ssh_channel_close(sdata.channel);

    /* Wait up to 5 seconds for the client to terminate the session. */
    for (n = 0; n < 50 && (ssh_get_status(session) & SESSION_END) == 0; n++) {
        ssh_event_dopoll(event, 100);
    }
}

int main(int argc, char **argv) {
    ssh_bind sshbind = NULL;
    ssh_session session = NULL;
    struct sigaction sa;
    int rc;

    /* Set up SIGCHLD handler. */
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) != 0) {
        fprintf(stderr, "Failed to register SIGCHLD handler\n");
        return 1;
    }

    rc = ssh_init();
    if (rc < 0) {
        fprintf(stderr, "ssh_init failed\n");
        return 1;
    }

    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "ssh_bind_new failed\n");
        ssh_finalize();
        return 1;
    }

    rc = ssh_bind_listen(sshbind);
    if (rc < 0) {
        fprintf(stderr, "%s\n", ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        ssh_finalize();
        return 1;
    }

    while (1) {
        session = ssh_new();
        if (session == NULL) {
            fprintf(stderr, "Failed to allocate session\n");
            continue;
        }

        /* Blocks until there is a new incoming connection. */
        rc = ssh_bind_accept(sshbind, session);
        if (rc == SSH_ERROR) {
            fprintf(stderr, "%s\n", ssh_get_error(sshbind));
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }

        ssh_event event;
        pid_t pid = fork();
        switch (pid) {
        case 0:
            /* Remove the SIGCHLD handler inherited from parent. */
            sa.sa_handler = SIG_DFL;
            sigaction(SIGCHLD, &sa, NULL);

            /* Remove socket binding, which allows us to restart the
             * parent process, without terminating existing sessions. */
            ssh_bind_free(sshbind);

            event = ssh_event_new();
            if (event != NULL) {
                /* Blocks until the SSH session ends by either
                 * child process exiting, or client disconnecting. */
                handle_session(event, session);
                ssh_event_free(event);
            } else {
                fprintf(stderr, "Could not create polling context\n");
            }
            ssh_disconnect(session);
            ssh_free(session);
            exit(0);
        case -1:
            fprintf(stderr, "Failed to fork\n");
        }

        /* Since the session has been passed to a child fork, do some cleaning
         * up at the parent process. */
        ssh_disconnect(session);
        ssh_free(session);
    }

    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}