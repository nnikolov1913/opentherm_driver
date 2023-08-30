#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/err.h>
#include <linux/uaccess.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <uapi/linux/sched/types.h>
#include <linux/poll.h>
#include <linux/completion.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>

#define TIMEOUT 5000
#define OT_RT_IN    23
#define OT_RT_OUT   22
#define OT_BOIL_IN  25
#define OT_BOIL_OUT 24
#define TRANSITION_TIMEOUT 1100000
#define BITRECEIVE_TIMEOUT 650000
#define OT_HALFBIT_TIME    500000
#define FRAME_SIZE    34
#define BITSEND_TOOLONG 650000
#define BITSEND_TOOSHORT 400000
#define WRITE_TIMEOUT_MS    50

#define BITRECEIVE_TIMEOUT_NEW 800000
#define TRANSITION_TIMEOUT_NEW 1300000

#define MESSAGE_INTERVAL    500000000

#define LINE_IDLE   0
#define LINE_BIT    1
#define LINE_MID    2

#define DEVICE_NUM  4
#define OT_MSG_SIZE 4

/*
cat /dev/opentherm0 > /tmp/therm_in.txt
echo -n -e '\xf0\x05\x00\x00' > /dev/opentherm1
cat /dev/opentherm2 > /tmp/boil_in.txt
echo -n -e '\xf0\x05\x00\x00' > /dev/opentherm3
cat /sys/class/opentherm_class/opentherm_device/dev
*/

static struct timer_list opentherm_timer;
static unsigned int tmr_count = 0;
static unsigned int gpio_rt_irq;
static unsigned int gpio_boil_irq;
 
int ot_rt_irq_edge = 2;
int ot_boil_irq_edge = 2;
unsigned loglevel = 1;

#define LOGLVL_ERROR    0
#define LOGLVL_INFO     1
#define LOGLVL_DEBUG    2

#define OTMSG(lvl, msg...)  do {    \
        if(lvl == LOGLVL_ERROR)     \
            pr_err(msg);            \
        else if(lvl <= loglevel)    \
            pr_info(msg);           \
    } while(0)

struct ot_ctx
{
    unsigned pin;
    int last_gpio_val;
    u64 timestamp;
    int irq_gpio_val;
    u64 irq_timestamp;
    unsigned irq_cnt;
    unsigned linestate;
    u64 data;
    unsigned bitpos;
    unsigned msg;
    unsigned hasmsg;
    unsigned invert;
    unsigned irq;
    u64 lastmsg_ts;
    unsigned sendstat;
    unsigned wrerrors;
    unsigned rderrors;
    unsigned opened;
    wait_queue_head_t wait;
    struct completion ot_msg_written;
    struct hrtimer send_hrtimer;
    spinlock_t lock;
    struct mutex otmutex;
};

static dev_t otdev = 0;
static struct class *dev_class;
static struct cdev opentherm_cdev;

static int __init opentherm_driver_init(void);
static void __exit opentherm_driver_exit(void);

static int opentherm_open(struct inode *inode, struct file *filp);
static int opentherm_release(struct inode *inode, struct file *filp);
static ssize_t opentherm_read(struct file *filp, char __user *buf, size_t len,loff_t * off);
static ssize_t opentherm_write(struct file *filp, const char *buf, size_t len, loff_t * off);
static __poll_t opentherm_poll(struct file *filp, struct poll_table_struct *wait);

static struct ot_ctx otrtinctx = { .pin = OT_RT_IN };
static struct ot_ctx otboilinctx = { .pin = OT_BOIL_IN };
static struct ot_ctx otrtoutctx = { .pin = OT_RT_OUT };
static struct ot_ctx otboiloutctx = { .pin = OT_BOIL_OUT };

static struct ot_ctx * otctxarr[DEVICE_NUM] = { &otrtinctx, &otrtoutctx, &otboilinctx, &otboiloutctx };

static struct file_operations fops =
{
        .owner          = THIS_MODULE,
        .read           = opentherm_read,
        .write          = opentherm_write,
        .open           = opentherm_open,
        .release        = opentherm_release,
        .poll           = opentherm_poll,
};
 
void timer_callback(struct timer_list * data)
{
    //unsigned long flags;
    tmr_count++;
    OTMSG((tmr_count % 120) == 0 ? LOGLVL_INFO : LOGLVL_DEBUG,
            "Timer callback called %d times, ot_rt_in %d ot_boil_in %d, wrerrors %u,%u, rderrors %u,%u\n",
            tmr_count, gpio_get_value(OT_RT_IN), gpio_get_value(OT_BOIL_IN),
            otrtoutctx.wrerrors, otboiloutctx.wrerrors, otrtinctx.rderrors, otboilinctx.rderrors);
    mod_timer(&opentherm_timer, jiffies + msecs_to_jiffies(TIMEOUT));
}

static int opentherm_open(struct inode *inode, struct file *filp)
{
    int minor;
    struct ot_ctx *otinctx;
    dev_t device = inode->i_rdev;
    minor = MINOR(device) - MINOR(otdev);
    if(minor < 0 || minor > 3)
    {
        OTMSG(LOGLVL_ERROR, "Openttherm device does not exist %d\n", minor);
        return -ENODEV;
    }
    otinctx = otctxarr[minor];
    if(otinctx->opened > 0)
    {
        OTMSG(LOGLVL_ERROR, "Openttherm device %d already opened\n", minor);
        return -EBUSY;
    }
    otinctx->opened = 1;
    filp->private_data = otinctx;
    //pr_info("Openttherm device opened %x, %d, %d\n", device, MAJOR(device), MINOR(device));
    return 0;
}

static int opentherm_release(struct inode *inode, struct file *filp)
{
    //dev_t device = inode->i_rdev;
    //pr_info("Opentherm device closed %x, %d, %d\n", device, MAJOR(device), MINOR(device));
    if(filp->private_data)
    {
        struct ot_ctx *otinctx;
        otinctx = filp->private_data;
        otinctx->opened = 0;
        filp->private_data = NULL;
    }
    return 0;
}

static ssize_t opentherm_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
    unsigned msg = 0;
    unsigned char tmpbuf[OT_MSG_SIZE];
    unsigned hasmsg = 0;
    struct ot_ctx *otinctx;
    if(filp->private_data == NULL)
    {
        OTMSG(LOGLVL_ERROR, "Openttherm device no priv data\n");
        return -ENXIO;
    }
    otinctx = filp->private_data;
    if(otinctx->pin != OT_RT_IN && otinctx->pin != OT_BOIL_IN)
    {
        OTMSG(LOGLVL_ERROR, "Openttherm device %d read not possible\n", otinctx->pin);
        return -EIO;
    }
    if(len < OT_MSG_SIZE)
    {
        OTMSG(LOGLVL_ERROR, "Openttherm device %d read not enough space\n", otinctx->pin);
        return -EMSGSIZE;
    }
    if(otinctx->hasmsg == 0)
    {
        int ret;
        if(filp->f_flags & O_NONBLOCK)
            return -EAGAIN;
        ret = wait_event_interruptible(otinctx->wait, otinctx->hasmsg);
        if(ret)
            return ret;
    }
    mutex_lock(&otinctx->otmutex);
    if(otinctx->hasmsg)
    {
        msg = otinctx->msg;
        otinctx->hasmsg = 0;
        otinctx->msg = 0;
        hasmsg = 1;
    }
    mutex_unlock(&otinctx->otmutex);
    OTMSG(LOGLVL_DEBUG, "Opentherm read %d pin hasmsg %x, msg %x, len %ld\n", otinctx->pin, hasmsg, msg, len);
    if(hasmsg)
    {
        tmpbuf[0] = 0x000000FF & (msg >> 24);
        tmpbuf[1] = 0x000000FF & (msg >> 16);
        tmpbuf[2] = 0x000000FF & (msg >> 8);
        tmpbuf[3] = 0x000000FF & msg;
        if(copy_to_user(buf, &tmpbuf, OT_MSG_SIZE))
        {
            OTMSG(LOGLVL_ERROR, "Opentherm read copy to user failed\n");
            return -EFAULT;
        }
        return OT_MSG_SIZE;
    }
    return -EAGAIN;
}

static inline void reset_line(struct ot_ctx *otinctx)
{
    otinctx->linestate = LINE_IDLE;
    otinctx->data = 0LLU;
    otinctx->bitpos = 0;
    otinctx->lastmsg_ts = ktime_get_real_ns();
}

#ifdef USE_WAITLOOP_FOR_WRITE
static int mid_bit_wait(u64 *ts)
{
    int ret = 0;
    u64 curts, diff;
    do {
        curts = ktime_get_real_ns();
        diff = curts - *ts;
    } while(diff < OT_HALFBIT_TIME);
    if(diff > BITRECEIVE_TIMEOUT)
    {
        OTMSG(LOGLVL_ERROR, "Opentherm too much sleep %llu\n", diff);
        ret = 1;
    }
    *ts = curts;
    return ret;
}

static int ot_write_bit(struct ot_ctx *otinctx, int value)
{
    int ret;
    u64 timestamp;
    timestamp = ktime_get_real_ns();
    gpio_set_value(otinctx->pin, !value);
    ret = mid_bit_wait(&timestamp);
    gpio_set_value(otinctx->pin, value);
    ret |= mid_bit_wait(&timestamp);
    return ret;
}

static int ot_send_msg(struct ot_ctx *otinctx, unsigned msg)
{
    int i = 0, value = 0, ret;
    ret = ot_write_bit(otinctx, !otinctx->invert);
    while(ret == 0 && i < 32)
    {
        value = ((msg & 0x80000000) == 0x80000000);
        ret = ot_write_bit(otinctx, !otinctx->invert ? value : !value);
        msg <<= 1;
        i++;
    }
    ret |= ot_write_bit(otinctx, !otinctx->invert);
    gpio_set_value(otinctx->pin, !otinctx->invert);
    return ret;
}
#endif

static enum hrtimer_restart hrtimer_sendmsg_fire(struct hrtimer *timer)
{
    int value;
    u64 timestamp, ts;
    struct ot_ctx *otinctx = container_of(timer, struct ot_ctx, send_hrtimer);
    value = ((otinctx->data << otinctx->bitpos) & 0x200000000LLU) == 0x200000000LLU;
    value = !otinctx->invert ? value : !value;
    timestamp = ktime_get_real_ns();
    ts = timestamp - otinctx->timestamp;
    if((otinctx->linestate == LINE_MID || otinctx->linestate == LINE_BIT) && (ts < BITSEND_TOOSHORT || ts > BITSEND_TOOLONG))
    {
        if(ts < BITSEND_TOOSHORT) {
            //OTMSG(LOGLVL_INFO, "Opentherm pin %d send bitpos %d reschedule for %lld\n", otinctx->pin, otinctx->bitpos, OT_HALFBIT_TIME-ts);
            hrtimer_forward_now(timer, ktime_set(0, OT_HALFBIT_TIME-ts));
            return HRTIMER_RESTART;
        }
        OTMSG(LOGLVL_ERROR, "ERROR: Opentherm pin %d send bitpos %d wrong time %lld\n", otinctx->pin, otinctx->bitpos, ts);
        otinctx->wrerrors++;
        //gpio_set_value(otinctx->pin, !otinctx->invert);
        //otinctx->sendstat = 1;
        //goto outtimer:
    }
    otinctx->timestamp = timestamp;
    if(otinctx->linestate == LINE_IDLE || otinctx->linestate == LINE_MID)
    {
        //pr_info("Opentherm pin %d write value %d, idle or mid %lld\n", otinctx->pin, !value, otinctx->linestate == LINE_IDLE ? timestamp : ts);
        gpio_set_value(otinctx->pin, !value);
        otinctx->linestate = LINE_BIT;
    }
    else if(otinctx->linestate == LINE_BIT)
    {
        //pr_info("Opentherm pin %d write value %d, bit, %lld\n", otinctx->pin, value, ts);
        gpio_set_value(otinctx->pin, value);
        otinctx->linestate = LINE_MID;
        otinctx->bitpos++;
    }
    else
    {
        OTMSG(LOGLVL_ERROR, "ERROR: UNKNOWN line state %d ???\n", otinctx->linestate);
        otinctx->sendstat = 1;
        goto outtimer;
    }

    if(otinctx->bitpos == FRAME_SIZE)
    {
        //pr_info("Opentherm pin %d msg %x sent, %lld\n", otinctx->pin, otinctx->msg, otinctx->timestamp);
        otinctx->bitpos = 0;
        otinctx->linestate = LINE_IDLE;
        otinctx->lastmsg_ts = otinctx->timestamp;
        otinctx->sendstat = 0;
        goto outtimer;
    }
    hrtimer_forward_now(timer, ktime_set(0, OT_HALFBIT_TIME/2));
    return HRTIMER_RESTART;

outtimer:
    if(!completion_done(&otinctx->ot_msg_written))
        complete(&otinctx->ot_msg_written);
    return HRTIMER_NORESTART;
}

static ssize_t opentherm_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
#ifdef USE_WAITLOOP_FOR_WRITE
    int ret, nice;
#else
    unsigned long ret;
#endif
    unsigned char tmpbuf[OT_MSG_SIZE];
    struct ot_ctx *otinctx;
    if(filp->private_data == NULL)
    {
        OTMSG(LOGLVL_ERROR, "Openttherm device no priv data\n");
        return -ENXIO;
    }
    otinctx = filp->private_data;
    if(otinctx->pin != OT_RT_OUT && otinctx->pin != OT_BOIL_OUT)
    {
        OTMSG(LOGLVL_ERROR, "Openttherm device %d write not possible\n", otinctx->pin);
        return -EIO;
    }
    if(len != OT_MSG_SIZE)
    {
        OTMSG(LOGLVL_ERROR, "Opentherm write wrong len %ld\n", len);
        return -EINVAL;
    }
    if(copy_from_user(tmpbuf, buf, len))
    {
        OTMSG(LOGLVL_ERROR, "Opentherm write copy from user failed\n");
        return -EFAULT;
    }
    OTMSG(LOGLVL_DEBUG, "Opentherm write pin %d got bytes %x, %x, %x, %x\n", otinctx->pin, tmpbuf[0], tmpbuf[1], tmpbuf[2], tmpbuf[3]);
    otinctx->msg = tmpbuf[0] << 24 | tmpbuf[1] << 16 | tmpbuf[2] << 8 | tmpbuf[3];
    otinctx->bitpos = 0;
    otinctx->linestate = LINE_IDLE;
#ifdef USE_WAITLOOP_FOR_WRITE
    nice = task_nice(current);
    set_user_nice(current, -20);
    ret = ot_send_msg(otinctx, otinctx->msg);
    set_user_nice(current, nice);
    if(ret != 0)
    {
        OTMSG(LOGLVL_ERROR, "Opentherm write wrong timing\n");
        return -EBUSY;
    }
#else
    otinctx->data = (1LLU << 32);
    otinctx->data = otinctx->data | otinctx->msg;
    otinctx->data = otinctx->data << 1;
    otinctx->data = otinctx->data | 1;
    otinctx->timestamp = ktime_get_real_ns();
    hrtimer_start(&otinctx->send_hrtimer, ktime_set(0, OT_HALFBIT_TIME/2), HRTIMER_MODE_REL);
    ret = wait_for_completion_timeout(&otinctx->ot_msg_written, msecs_to_jiffies(WRITE_TIMEOUT_MS));
    if(otinctx->sendstat != 0 || ret == 0)
    {
        OTMSG(LOGLVL_ERROR, "Opentherm write ERROR %u,%lu, pin %d\n", otinctx->sendstat, ret, otinctx->pin);
        otinctx->sendstat = 0;
        if(ret == 0)
        {
            hrtimer_cancel(&otinctx->send_hrtimer);
            reset_line(otinctx);
            otinctx->wrerrors++;
            gpio_set_value(otinctx->pin, !otinctx->invert);
        }
        return -EBUSY;
    }
#endif
    //pr_info("Opentherm write pin %d msg %x written\n", otinctx->pin, otinctx->msg);
    return len;
}

static __poll_t opentherm_poll(struct file *filp, struct poll_table_struct *wait)
{
    __poll_t revents = 0;
    struct ot_ctx *otinctx;
    otinctx = filp->private_data;
    if(otinctx)
    {
        poll_wait(filp, &otinctx->wait, wait);
        if(otinctx->hasmsg)
            revents = EPOLLIN | EPOLLRDNORM;
    }
    return revents;
}

static inline void bit_received(struct ot_ctx *otinctx, int val)
{
    otinctx->data = (otinctx->data << 1) | val;
    otinctx->bitpos++;
}

static inline void receive_error(struct ot_ctx *otinctx)
{
    otinctx->rderrors++;
    reset_line(otinctx);
}

static inline void handle_received_val(struct ot_ctx *otinctx, int val)
{
    if(otinctx->last_gpio_val != val)
        bit_received(otinctx, otinctx->invert ? val : !val);
    else
    {
        OTMSG(LOGLVL_ERROR, "Same bit in %d state, pin %d. Should not happen!\n", otinctx->linestate, otinctx->pin);
        receive_error(otinctx);
    }
}


static inline void process_input(struct ot_ctx *otinctx, int val, u64 timestamp)
{
    unsigned hasmsg = 0;
    u64 tmdiff = timestamp - otinctx->timestamp;
    if(tmdiff > MESSAGE_INTERVAL/5 && otinctx->linestate != LINE_IDLE)
    {
        OTMSG(LOGLVL_ERROR, "Big interval pin %d for state %d, diff %llu, val %d, pos %d\n", otinctx->pin,
                otinctx->linestate, tmdiff, val, otinctx->bitpos);
        reset_line(otinctx);
    }
    if(otinctx->linestate == LINE_BIT)
    {
        if(timestamp - otinctx->timestamp < BITRECEIVE_TIMEOUT_NEW)
        {
            otinctx->linestate = LINE_MID;
            handle_received_val(otinctx, val);
        }
        else
        {
            OTMSG(LOGLVL_INFO, "pin %d bit transition timeout %llu, %llu, bitpos %d val %d\n", otinctx->pin, timestamp, otinctx->timestamp, otinctx->bitpos, val);
            receive_error(otinctx);
        }
    }
    else if(otinctx->linestate == LINE_MID)
    {
        if(timestamp - otinctx->timestamp < BITRECEIVE_TIMEOUT_NEW)
        {
            //Mid transition
            otinctx->linestate = LINE_BIT;
        }
        else if(tmdiff < TRANSITION_TIMEOUT_NEW)
        {
            //Most likely a bit
            handle_received_val(otinctx, val);
        }
        else
        {
            OTMSG(LOGLVL_INFO, "pin %d mid transition timeout %lld, diff %lld, bitpos %d, val %d\n", otinctx->pin, timestamp, tmdiff, otinctx->bitpos, val);
            receive_error(otinctx);
        }
    }
    if(otinctx->linestate == LINE_IDLE)
    {
        if((otinctx->invert && val == 0) || (!otinctx->invert && val == 1)) 
            otinctx->linestate = LINE_BIT;
    }
    //pr_info("pin %d bitpos %d, data %llx\n", otinctx->pin, otinctx->bitpos, otinctx->data);
    if(otinctx->bitpos == FRAME_SIZE)
    {
        OTMSG(LOGLVL_DEBUG, "pin %d msg received bitpos %d, data %llx\n", otinctx->pin, otinctx->bitpos, otinctx->data);
        mutex_lock(&otinctx->otmutex);
        otinctx->msg = (unsigned)(otinctx->data >> 1);
        otinctx->hasmsg = hasmsg = 1;
        mutex_unlock(&otinctx->otmutex);
        reset_line(otinctx);
    }
    otinctx->timestamp = timestamp;
    otinctx->last_gpio_val = val;
    if(hasmsg)
        wake_up(&otinctx->wait);
}

static irqreturn_t gpio_isr(int irq, void *ctx)
{
    int val;
    u64 timestamp;
    struct ot_ctx *otinctx = (struct ot_ctx *)ctx;
    val = gpio_get_value(otinctx->pin);
    timestamp = ktime_get_real_ns();
    //OTMSG(LOGLVL_INFO, "HIRQ: pin %d interrupt! value on port %d, linestate %d, %lld\n", otinctx->pin, val, otinctx->linestate, timestamp);
    spin_lock(&otinctx->lock);
    otinctx->irq_gpio_val = val;
    otinctx->irq_timestamp = timestamp;
    ++otinctx->irq_cnt;
    spin_unlock(&otinctx->lock);
    return IRQ_WAKE_THREAD;
    //return IRQ_HANDLED;
}

static irqreturn_t gpio_isr_thread(int irq, void *ctx)
{
    int val;
    u64 timestamp;
    unsigned long flags;
    struct ot_ctx *otinctx = (struct ot_ctx *)ctx;
    spin_lock_irqsave(&otinctx->lock, flags);
    val = otinctx->irq_gpio_val;
    timestamp = otinctx->irq_timestamp;
    --otinctx->irq_cnt;
    if(unlikely(otinctx->irq_cnt != 0)) {
        OTMSG(LOGLVL_ERROR, "SIRQ: irq_cnt not 0 %d, tm %llu\n", otinctx->irq_cnt, timestamp);
        otinctx->irq_cnt = 0;
    }
    spin_unlock_irqrestore(&otinctx->lock, flags);
    process_input(otinctx, val, timestamp);
    return IRQ_HANDLED;
}

static inline void otinctx_init(struct ot_ctx *otinctx)
{
    spin_lock_init(&otinctx->lock);
    mutex_init(&otinctx->otmutex);
    init_waitqueue_head(&otinctx->wait);
    init_completion(&otinctx->ot_msg_written);
    hrtimer_init(&otinctx->send_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    otinctx->send_hrtimer.function = hrtimer_sendmsg_fire;
}

static int __init opentherm_driver_init(void)
{
    int ret, minor;
    unsigned long edge_flags = IRQF_TRIGGER_RISING;
    otinctx_init(&otrtinctx);
    otinctx_init(&otboilinctx);
    otinctx_init(&otrtoutctx);
    otinctx_init(&otboiloutctx);
    if((alloc_chrdev_region(&otdev, 0, DEVICE_NUM, "opentherm")) <0){
        OTMSG(LOGLVL_ERROR, "Cannot allocate major number\n");
        return -1;
    }
    OTMSG(LOGLVL_INFO, "Major=%d Minor=%d jiffies/ms=%ld\n", MAJOR(otdev), MINOR(otdev), msecs_to_jiffies(20));
 
    cdev_init(&opentherm_cdev, &fops);
 
    if((cdev_add(&opentherm_cdev, otdev, DEVICE_NUM)) < 0){
        OTMSG(LOGLVL_ERROR, "Cannot add the device to the system\n");
        goto err_class;
    }
 
    if(IS_ERR(dev_class = class_create(THIS_MODULE, "opentherm_class"))){
        OTMSG(LOGLVL_ERROR, "Cannot create the struct class\n");
        goto err_del;
    }
 
    for(minor = 0; minor < DEVICE_NUM; minor++)
    {
        unsigned char devname[16];
        sprintf(devname, "opentherm%d", minor);
        if(IS_ERR(device_create(dev_class, NULL, MKDEV(MAJOR(otdev), minor), NULL, devname))){
            OTMSG(LOGLVL_ERROR, "Cannot create the device %s\n", devname);
            goto err_device;
        }
    }
 
    if(gpio_is_valid(OT_RT_IN) == false)
    {
        OTMSG(LOGLVL_ERROR, "OT_RT_IN not valid\n");
        goto err_device;
    }

    if(gpio_is_valid(OT_BOIL_IN) == false)
    {
        OTMSG(LOGLVL_ERROR, "OT_BOIL_IN not valid\n");
        goto err_device;
    }
    if(gpio_is_valid(OT_RT_OUT) == false)
    {
        OTMSG(LOGLVL_ERROR, "OT_RT_OUT not valid\n");
        goto err_device;
    }
    if(gpio_is_valid(OT_BOIL_OUT) == false)
    {
        OTMSG(LOGLVL_ERROR, "OT_BOIL_OUT not valid\n");
        goto err_device;
    }

    ret = gpio_request(OT_RT_IN, "ot_rt_in");
    if(ret < 0){
        OTMSG(LOGLVL_ERROR, "ERROR: GPIO %d request failed %d\n", OT_RT_IN, ret);
        goto err_device;
    }
    gpio_direction_input(OT_RT_IN);

    ret = gpio_request(OT_BOIL_IN, "ot_boil_in");
    if(ret < 0){
        OTMSG(LOGLVL_ERROR, "ERROR: GPIO %d request failed %d\n", OT_BOIL_IN, ret);
        goto err_rt_in;
    }
    gpio_direction_input(OT_BOIL_IN);

    ret = gpio_request(OT_RT_OUT, "ot_rt_out");
    if(ret < 0){
        OTMSG(LOGLVL_ERROR, "ERROR: GPIO %d request failed %d\n", OT_RT_OUT, ret);
        goto err_boil_in;
    }
    gpio_direction_output(OT_RT_OUT, 1);
    gpio_set_value(otrtoutctx.pin, !otrtoutctx.invert);

    ret = gpio_request(OT_BOIL_OUT, "ot_boil_out");
    if(ret < 0){
        OTMSG(LOGLVL_ERROR, "ERROR: GPIO %d request failed %d\n", OT_BOIL_OUT, ret);
        goto err_rt_out;
    }
    gpio_direction_output(OT_BOIL_OUT, 1);
    gpio_set_value(otboiloutctx.pin, !otboiloutctx.invert);

    gpio_rt_irq = gpio_to_irq(OT_RT_IN);
    gpio_boil_irq = gpio_to_irq(OT_BOIL_IN);
    if(ot_rt_irq_edge == 1)
        edge_flags = IRQF_TRIGGER_FALLING;
    else if(ot_rt_irq_edge == 2)
        edge_flags = IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING;
    OTMSG(LOGLVL_INFO, "OT_RT_IN intr %d, ot_rt_irq_edge %d, edge_flags %lx\n", gpio_rt_irq, ot_rt_irq_edge, edge_flags);
    if(request_threaded_irq(gpio_rt_irq, gpio_isr, gpio_isr_thread, edge_flags, "ot_rt_in", &otrtinctx))
    {
        OTMSG(LOGLVL_ERROR, "opentherm: cannot register RT_IN IRQ\n");
        goto err_boil_out;
    }
    edge_flags = IRQF_TRIGGER_RISING;
    if(ot_boil_irq_edge == 1)
        edge_flags = IRQF_TRIGGER_FALLING;
    else if(ot_boil_irq_edge == 2)
        edge_flags = IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING;
    OTMSG(LOGLVL_INFO, "OT_BOIL_IN intr %d, ot_boil_irq_edge %d, edge_flags %lx\n", gpio_boil_irq, ot_boil_irq_edge, edge_flags);
    if(request_threaded_irq(gpio_boil_irq, gpio_isr, gpio_isr_thread, edge_flags, "ot_boil_in", &otboilinctx))
    {
        OTMSG(LOGLVL_ERROR, "opentherm: cannot register BOIL_IN IRQ\n");
        goto err_rt_irq;
    }

    timer_setup(&opentherm_timer, timer_callback, 0);
    mod_timer(&opentherm_timer, jiffies + msecs_to_jiffies(TIMEOUT));
 
    otrtinctx.irq = gpio_rt_irq;
    otboilinctx.irq = gpio_boil_irq;
    printk(KERN_INFO "Opentherm inited. OT_RT_IN value %d, OT_BOIL_IN value %d\n", gpio_get_value(OT_RT_IN), gpio_get_value(OT_BOIL_IN));

    return 0;
err_rt_irq:
    free_irq(gpio_rt_irq, &otrtinctx);
err_boil_out:
    gpio_free(OT_BOIL_OUT);
err_rt_out:
    gpio_free(OT_RT_OUT);
err_boil_in:
    gpio_free(OT_BOIL_IN);
err_rt_in:
    gpio_free(OT_RT_IN);
err_device:
    for(; minor > 0; minor--)
        device_destroy(dev_class, MKDEV(MAJOR(otdev), minor - 1));
    class_destroy(dev_class);
err_del:
    cdev_del(&opentherm_cdev);
err_class:
    unregister_chrdev_region(otdev, DEVICE_NUM);
    return -1;
}

static void __exit opentherm_driver_exit(void)
{
    int minor;
    //If devices are not opened in userspace it is not needed to stop hrtimers and completions here
    del_timer(&opentherm_timer);
    free_irq(gpio_rt_irq, &otrtinctx);
    free_irq(gpio_boil_irq, &otboilinctx);
    gpio_free(OT_BOIL_IN);
    gpio_free(OT_RT_IN);
    gpio_free(OT_BOIL_OUT);
    gpio_free(OT_RT_OUT);
    for(minor = 0; minor < DEVICE_NUM; minor++)
        device_destroy(dev_class, MKDEV(MAJOR(otdev), minor));
    class_destroy(dev_class);
    cdev_del(&opentherm_cdev);
    unregister_chrdev_region(otdev, DEVICE_NUM);
    printk(KERN_INFO "Opentherm driver removed!!!\n");
}
 
module_param(ot_rt_irq_edge, int, S_IRUSR|S_IWUSR);
MODULE_PARM_DESC(ot_rt_irq_edge, "Set OT_RT_IN interrupt edge 0=rising, 1=falling, 2=both");
module_param(ot_boil_irq_edge, int, S_IRUSR|S_IWUSR);
MODULE_PARM_DESC(ot_boil_irq_edge, "Set OT_BOIL_IN interrupt edge 0=rising, 1=falling, 2=both");
module_param(loglevel, uint, S_IRUSR|S_IWUSR);
MODULE_PARM_DESC(loglevel, "Set opentherm log level 0=error, 1=info, 2=debug");

module_init(opentherm_driver_init);
module_exit(opentherm_driver_exit);
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nikolay Nikolov <dobrev666@gmail.com>");
MODULE_DESCRIPTION("A simple opentherm dirver");
MODULE_VERSION("1.0");
