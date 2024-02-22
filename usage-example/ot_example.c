#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <poll.h>

#define OT_MSG_LEN      4
#define POLL_DESC_NUN   3

struct thread_ctx
{
    int fd;
    char inputname[16];
};

static int read_ot_device(int fd, char *devname, unsigned char *buf, unsigned buflen)
{
    int ret;
    struct timespec ts;
    ret = read(fd, buf, buflen);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    if(ret == buflen)
        printf("%ld:%09ld %s got message %x%x%x%x\n", ts.tv_sec, ts.tv_nsec, devname, buf[0], buf[1], buf[2], buf[3]);
    else if(ret < 0)
        printf("%ld:%09ld %s got error %d\n", ts.tv_sec, ts.tv_nsec, devname, errno);
    else
        printf("%ld:%09ld %s unexpected read bytes %d\n", ts.tv_sec, ts.tv_nsec, devname, ret);
    return ret;
}

static void *in_thread(void *ctx)
{
    int ret;
    unsigned char otmsg[OT_MSG_LEN];
    struct thread_ctx *thdctx = (struct thread_ctx *)ctx;
    printf("%s thread started, fd=%d\n", thdctx->inputname, thdctx->fd);
    do {
        ret = read_ot_device(thdctx->fd, thdctx->inputname, otmsg, sizeof(otmsg));
    } while(ret > 0);
    return NULL;
}

int main(int argc, char **argv)
{
    int flags = O_RDONLY | O_NONBLOCK;
    int fdrt, fdboil;
    struct thread_ctx rtin, boilin;
    pthread_t thrd_rtin, thrd_boilin;
    if(argc > 1)
    {
        if(strcmp(argv[1], "-b") == 0)
        {
            flags &= ~O_NONBLOCK;
            printf("Using blocking mode\n");
        }
    }
    fdrt = open("/dev/opentherm0", flags);
    if(fdrt < 0)
        printf("failed to open rtin, errno %d\n", errno);
    fdboil = open("/dev/opentherm2", flags);
    if(fdboil < 0)
        printf("failed to open boilin, errno %d\n", errno);
    if(fdrt < 0 && fdboil < 0)
    {
        printf("failed to open OT devices\n");
        return 1;
    }
    if((flags & O_NONBLOCK) > 0)
    {
        unsigned char otmsg[OT_MSG_LEN];
        int ret, i, stdquit = 0;
        nfds_t nfds = 0; 
        struct pollfd fds[POLL_DESC_NUN];

        printf("Using non blocking mode\n");
        for(i = 0; i < POLL_DESC_NUN; i++)
        {
            fds[i].fd = -1;
            fds[i].events = POLLIN;
            fds[i].revents = 0;
        }
        fds[nfds].fd = 0;
        nfds++;
        if(fdrt >= 0)
        {
            while(read_ot_device(fdrt, "rtin", otmsg, sizeof(otmsg)) > 0);
            fds[nfds].fd = fdrt;
            nfds++;
        }
        if(fdboil >= 0)
        {
            while(read_ot_device(fdboil, "boilin", otmsg, sizeof(otmsg)) > 0);
            fds[nfds].fd = fdboil;
            nfds++;
        }
        while(stdquit == 0)
        {
            ret = poll(fds, nfds, 5000);
            if(ret > 0)
            {
                for(i = 0; i < nfds; i++)
                {
                    if(fds[i].revents != 0)
                    {
                        if(fds[i].fd == 0)
                        {
                            printf("Got event on stdin %x, exiting\n", fds[i].revents);
                            stdquit = 1;
                            break;
                        }
                        else if(fds[i].fd == fdrt || fds[i].fd == fdboil)
                        {
                            char *devname;
                            devname = fds[i].fd == fdrt ? "rtin" : "boilin";
                            if((fds[i].revents & POLLIN) != 0)
                            {
                                //printf("Got read event %x on %s\n", fds[i].revents, devname);
                                ret = read_ot_device(fds[i].fd, devname, otmsg, sizeof(otmsg));
                                if(ret <= 0)
                                    stdquit = 1;
                            }
                            else 
                            {
                                printf("Got unexpected event %x on %s\n", fds[i].revents, devname);
                                stdquit = 1;
                            }
                            fds[i].revents = 0;
                        }
                    }
                }
            }
            else if(ret < 0)
            {
                printf("poll error %d\n", errno);
                sleep(1);
            }
            else
                printf("poll timeout\n");
        }
    }
    else
    {
        if(fdrt >= 0)
        {
            rtin.fd = fdrt;
            sprintf(rtin.inputname, "rtin");
            pthread_create(&thrd_rtin, NULL, in_thread, &rtin);
        }
        if(fdboil >= 0)
        {
            boilin.fd = fdboil;
            sprintf(boilin.inputname, "boilin");
            pthread_create(&thrd_boilin, NULL, in_thread, &boilin);
        }
        if(fdrt >= 0)
            pthread_join(thrd_rtin, NULL);
        if(fdboil >= 0)
            pthread_join(thrd_boilin, NULL);
    }

    if(fdrt >= 0)
        close(fdrt);
    if(fdboil >= 0)
        close(fdboil);
    return 0;
}
