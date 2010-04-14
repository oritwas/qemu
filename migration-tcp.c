/*
 * QEMU live migration
 *
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu-common.h"
#include "qemu/sockets.h"
#include "migration/migration.h"
#include "buffered_file.h"
#include "block/block.h"
#include "sysemu/sysemu.h"
#include "migration/ft_trans_file.h"
#include "migration/event-tap.h"

//#define DEBUG_MIGRATION_TCP

#ifdef DEBUG_MIGRATION_TCP
#define DPRINTF(fmt, ...) \
    do { printf("migration-tcp: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

static VMChangeStateEntry *vmstate;

static int socket_errno(MigrationState *s)
{
    return socket_error();
}

static int socket_write(MigrationState *s, const void * buf, size_t size)
{
    return send(s->fd, buf, size, 0);
}

static int socket_read(MigrationState *s, const void * buf, size_t size)
{
    ssize_t len;

    do {
        len = recv(s->fd, (void *)buf, size, 0);
    } while (len == -1 && socket_error() == EINTR);
    if (len == -1) {
        len = -socket_error();
    }

    return len;
}

static int tcp_close(MigrationState *s)
{
    int r = 0;
    DPRINTF("tcp_close\n");

    /* FIX ME: accessing ft_mode here isn't clean */
    if (ft_mode != FT_INIT && closesocket(s->fd) < 0) {
        r = -socket_error();
    }
    return r;
}

static void tcp_wait_for_connect(int fd, void *opaque)
{
    MigrationState *s = opaque;

    if (fd < 0) {
        DPRINTF("migrate connect error\n");
        s->fd = -1;
        migrate_fd_error(s);
    } else {
        DPRINTF("migrate connect success\n");
        s->fd = fd;
        migrate_fd_connect(s);
    }
}

void tcp_start_outgoing_migration(MigrationState *s, const char *host_port, Error **errp)
{
    s->get_error = socket_errno;
    s->write = socket_write;
    s->read = socket_read;
    s->close = tcp_close;

    s->fd = inet_nonblocking_connect(host_port, tcp_wait_for_connect, s, errp);
}

static void ft_trans_incoming(void *opaque)
{
    QEMUFile *f = opaque;

    qemu_file_get_notify(f);
    if (qemu_file_get_error(f)) {
        ft_mode = FT_ERROR;
        qemu_fclose(f);
    }
}

static void ft_trans_reset(void *opaque, int running, RunState state)
{
    QEMUFile *f = opaque;

    if (running) {
        if (ft_mode != FT_ERROR) {
            qemu_fclose(f);
        }
        ft_mode = FT_OFF;
        qemu_del_vm_change_state_handler(vmstate);
    }
}

static void ft_trans_schedule_replay(QEMUFile *f)
{
    event_tap_schedule_replay();
    vmstate = qemu_add_vm_change_state_handler(ft_trans_reset, f);
}

static void tcp_accept_incoming_migration(void *opaque)
{
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int s = (intptr_t)opaque;
    QEMUFile *f;
    int c;

    do {
        c = qemu_accept(s, (struct sockaddr *)&addr, &addrlen);
    } while (c == -1 && socket_error() == EINTR);
    qemu_set_fd_handler2(s, NULL, NULL, NULL, NULL);
    closesocket(s);

    DPRINTF("accepted migration\n");

    if (c == -1) {
        fprintf(stderr, "could not accept migration connection\n");
        goto out;
    }

    f = qemu_fopen_socket(c);
    if (f == NULL) {
        fprintf(stderr, "could not qemu_fopen socket\n");
        goto out;
    }

    if (ft_mode == FT_INIT) {
        autostart = 0;
    }

    process_incoming_migration(f);

    if (ft_mode == FT_INIT) {
        int ret;

        socket_set_nodelay(c);

        f = qemu_fopen_ft_trans(s, c);
        if (f == NULL) {
            fprintf(stderr, "could not qemu_fopen_ft_trans\n");
            goto out;
        }

        /* need to wait sender to setup */
        ret = qemu_ft_trans_begin(f);
        if (ret < 0) {
            goto out;
        }

        qemu_set_fd_handler2(c, NULL, ft_trans_incoming, NULL, f);
        ft_trans_schedule_replay(f);
        ft_mode = FT_TRANSACTION_RECV;

        return;
    }

    qemu_fclose(f);

out:
    closesocket(c);
}

void tcp_start_incoming_migration(const char *host_port, Error **errp)
{
    int s;

    s = inet_listen(host_port, NULL, 256, SOCK_STREAM, 0, errp);
    if (s < 0) {
        return;
    }

    qemu_set_fd_handler2(s, NULL, tcp_accept_incoming_migration, NULL,
                         (void *)(intptr_t)s);
}
