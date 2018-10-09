/**
 * @file main.c
 *
 * \brief Main of dummy
 *
 */


#include "api/syscall.h"
#include "api/print.h"
#include "libcryp.h"
#include "libdma.h"
//#include "dma_regs.h"
#include "main.h"
#include "handlers.h"
#include "aes.h"
#include "ipc_proto.h"

#define CRYPTO_MODE CRYP_PRODMODE
#define CRYPTO_DEBUG 1

#ifdef CONFIG_APP_CRYPTO_USE_GETCYCLES
const char *tim = "tim";
#endif

volatile uint32_t numipc = 0;

uint32_t num_dma_in_it = 0;
uint32_t num_dma_out_it = 0;

bool sdio_ready = false;
bool usb_ready = false;
bool smart_ready = false;

status_reg_t status_reg = { 0 };

uint32_t td_dma = 0;

void my_cryptin_handler(uint8_t irq, uint32_t status);
void my_cryptout_handler(uint8_t irq, uint32_t status);

void encrypt_dma(const uint8_t * data_in, uint8_t * data_out,
                 uint32_t data_len);

#if 1
void init_crypt_dma(const uint8_t * data_in,
                    uint8_t * data_out, uint32_t data_len);
#endif

uint32_t get_cycles(void)
{
    volatile uint32_t *cnt = (uint32_t *) 0x40000024;
 // tim2 samples at 21Mhz (APB1_f / 2), Cortex M4 is at 168Mhz
    return (*cnt * 2 * 4);
}

uint32_t get_duration(uint32_t tim1, uint32_t tim2)
{
    if (tim2 < tim1) {
        return tim2 - tim1;
    }
    return tim1 - tim2;
}

uint8_t id_sdio = 0;
uint8_t id_usb = 0;
uint8_t id_smart = 0;
uint8_t id_benchlog = 0;

uint32_t dma_in_desc;
uint32_t dma_out_desc;

uint8_t buf_in[512] = { 0 };
uint8_t buf_out[512] = { 0 };

uint8_t master_key_hash[32] = {0};

/*
 * We use the local -fno-stack-protector flag for main because
 * the stack protection has not been initialized yet.
 *
 * We use _main and not main to permit the usage of exactly *one* arg
 * without compiler complain. argc/argv is not a goot idea in term
 * of size and calculation in a microcontroler
 */
int _main(uint32_t task_id)
{
    char *wellcome_msg = "hello, I'm crypto";
//    char buffer_in[128];
    logsize_t size;
    uint8_t id = 0;
    char ipc_buf[32] = {0};
    const char * inject_order = "INJECT";
    struct sync_command ipc_sync_cmd;

    strncpy(ipc_buf, inject_order, 6);
#ifdef CONFIG_APP_CRYPTO_USE_GETCYCLES
    device_t dev2 = { 0 };
    int      dev_descriptor = 0;
#endif
    e_syscall_ret ret = 0;

    /**
     * Initialization sequence
     */
    printf("%s, my id is %x\n", wellcome_msg, task_id);

#ifdef CONFIG_APP_CRYPTO_USE_GETCYCLES
    strncpy(dev.name, tim, 3);
    dev2.address = 0x40000020;
    dev2.size = 0x20;
    dev2.isr_ctx_only = false;
    dev2.irq_num = 0;
    dev2.gpio_num = 0;

    printf("registering %s driver\n", dev2.name);
    ret = sys_init(INIT_DEVACCESS, &dev2, &dev_descriptor);
    printf("sys_init returns %s !\n", strerror(ret));
#endif

    ret = sys_init(INIT_GETTASKID, "smart", &id_smart);
    printf("smart is task %x !\n", id_smart);

    ret = sys_init(INIT_GETTASKID, "sdio", &id_sdio);
    printf("sdio is task %x !\n", id_sdio);

    ret = sys_init(INIT_GETTASKID, "usb", &id_usb);
    printf("usb is task %x !\n", id_usb);

    ret = sys_init(INIT_GETTASKID, "benchlog", &id_benchlog);
    printf("benchlog is task %x !\n", id_benchlog);

    cryp_early_init(true, CRYP_USER, CRYP_PRODMODE, (int*) &dma_in_desc, (int*) &dma_out_desc);

    printf("set init as done\n");
    ret = sys_init(INIT_DONE);
    printf("sys_init returns %s !\n", strerror(ret));

    /*******************************************
     * let's syncrhonize with other tasks
     *******************************************/
    do {
        size = 2;

        /*
         * CRYPTO is a central node, it waits for mostly all tasks
         * (usb, sdio & smart), in any order
         */
        id = ANY_APP;
        do {
            ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
        } while (ret != SYS_E_DONE);
        if (   ipc_sync_cmd.magic == MAGIC_TASK_STATE_CMD
                && ipc_sync_cmd.state == SYNC_READY) {
            printf("task %x has finished its init phase, acknowledge...\n", id);
        }

        ipc_sync_cmd.magic = MAGIC_TASK_STATE_RESP;
        ipc_sync_cmd.state = SYNC_ACKNOWLEDGE;

        do {
            size = 2;
            ret = sys_ipc(IPC_SEND_SYNC, id, size, (char*)&ipc_sync_cmd);
        } while (ret != SYS_E_DONE);

        if (id == id_smart) { smart_ready = true; }
        if (id == id_usb)   { usb_ready = true; }
        if (id == id_sdio)  { sdio_ready = true; }

    } while (   (smart_ready == false)
             || (usb_ready   == false)
             || (sdio_ready  == false));
    printf("All tasks have finished their initialization, continuing...\n");

    /*******************************************
     * End of full task end_of_init synchronization
     *******************************************/

    /*******************************************
     * Ask smart for key injection and
     * get back key hash
     *******************************************/

    
	unsigned char AES_CBC_ESSIV_h_key[32] = {0};
    /* Then Syncrhonize with crypto */
    size = 2;

    printf("sending end_of_init syncrhonization to smart\n");
    ipc_sync_cmd.magic = MAGIC_CRYPTO_INJECT_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    do {
      ret = sys_ipc(IPC_SEND_SYNC, id_smart, size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    id = id_smart;
    size = 3 + 32;

    do {
        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    if (   ipc_sync_cmd.magic == MAGIC_CRYPTO_INJECT_RESP
        && ipc_sync_cmd.state == SYNC_DONE) {
        printf("key injection done from smart. Hash received.\n");
        memcpy(AES_CBC_ESSIV_h_key, &ipc_sync_cmd.data, ipc_sync_cmd.data_size);

#ifdef CRYPTO_DEBUG
        printf("hash received:\n");
        hexdump(AES_CBC_ESSIV_h_key, 32);
#endif
    } else {
        goto err;
    }

    /*******************************************
     * cryptography initialization done.
     * Let start 2nd pase (SDIO/Crypto/USB runtime)
     *******************************************/


    printf("sending end_of_cryp syncrhonization to sdio\n");
    ipc_sync_cmd.magic = MAGIC_TASK_STATE_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    /* First inform SDIO block that everything is ready... */
    size = 2;
    do {
      ret = sys_ipc(IPC_SEND_SYNC, id_sdio, size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    id = id_sdio;
    size = 2;

    do {
        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    if (   ipc_sync_cmd.magic == MAGIC_TASK_STATE_RESP
        && ipc_sync_cmd.state == SYNC_READY) {
        printf("SDIO module is ready\n");
    }


    printf("sending end_of_cryp syncrhonization to usb\n");
    ipc_sync_cmd.magic = MAGIC_TASK_STATE_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    /* First inform SDIO block that everything is ready... */
    size = 2;
    do {
      ret = sys_ipc(IPC_SEND_SYNC, id_usb, size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    id = id_usb;
    size = 2;

    do {
        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    if (   ipc_sync_cmd.magic == MAGIC_TASK_STATE_RESP
        && ipc_sync_cmd.state == SYNC_READY) {
        printf("USB module is ready\n");
    }


    /*******************************************
     * Now crypto will wait for IPC orders from USB
     * (read or write access request) and transmit it
     * to SDIO.
     * For read:
     *   - when the SDIO read is ok, SDIO will send an IPC to
     *     CRYPTO which will start the CRYP DMA for uncypher
     *     and tell USB, USB will then start DMA transfer of
     *     uncyphered data directly into the USB IP.
     * For write
     *   - when the USB ask for write (when the USB read from
     *     host using USB DMA is done), Crypto will start DMA-based
     *     cyphering and then ask SDIO to read from the output buffer
     *     SDIO DMA will then read from it and write into the SDIO
     *     storage
     *******************************************/
    struct dataplane_command dataplane_command_wr = { 0 };
    struct dataplane_command dataplane_command_ack = { DATA_WR_DMA_ACK, 0, 0 };
    uint8_t sinker = 0;
    logsize_t ipcsize = 0;


    // hide your children !!
    while (1) {
        sinker = id_usb;
        ipcsize = sizeof(struct dataplane_command);
        // wait for sdio & usb and react to buffers reception and IPCs from
        // sdio & usb with DMA activation
        //do {
           sys_ipc(IPC_RECV_SYNC, &sinker, &ipcsize, (char*)&dataplane_command_wr);
           //numipc++;
        //} while ((sinker != id_usb) || (ipcsize != sizeof(struct dataplane_command)));
        //
        // start DMA transfer to SDIO
        //cryp_do_dma(bufin, bufout, size, dma_in_desc, dma_out_desc);
        //printf("received request to launch DMA: write %d block at sector %d\n",
        //        dataplane_command_wr.num_sectors,
        //        dataplane_command_wr.sector_address);
        sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(struct dataplane_command), (const char*)&dataplane_command_ack);
        // receiving ipc from USB

    }
#if 0
    while (1) {
        //sys_yield();
        // avoiding sys_yield() here, there is a possible race condition between
        // yielding and the IRQ that can be faster (and make yielding being executed
        // just after, making the main thread sleeping for ever
        if (status_reg.dmain_done == true) {
            status_reg.dmain_done = false;
            //ret = sys_ipc(IPC_DMA_RELOAD, 0, (uint32_t)&dma_in, 0);
            //printf("cryp DMA in done\n");
        }
        if (status_reg.dmain_fifo_err == true) {
            printf("DMA in FIFO error !\n");
            status_reg.dmain_fifo_err = false;
        }
        if (status_reg.dmain_tr_err == true) {
            printf("DMA in transfer error !\n");
            status_reg.dmain_tr_err = false;
        }
        if (status_reg.dmain_dm_err == true) {
            printf("DMA in direct mode error !\n");
            status_reg.dmain_dm_err = false;
        }

        if (status_reg.dmaout_done == true) {
            status_reg.dmaout_done = false;
            //printf("reloading all DMAs\n");
            td_dma++;
            //ret = sys_ipc(IPC_DMA_RELOAD, 0, (uint32_t)&dma_in, 0);
            //ret = sys_ipc(IPC_DMA_RELOAD, 0, (uint32_t)&dma_out, 0);
        }
        if (status_reg.dmaout_fifo_err == true) {
            printf("DMA out FIFO error !\n");
            status_reg.dmaout_fifo_err = false;
        }
        if (status_reg.dmaout_tr_err == true) {
            printf("DMA out transfer error !\n");
            status_reg.dmaout_tr_err = false;
        }
        if (status_reg.dmaout_dm_err == true) {
            printf("DMA out direct mode error !\n");
            status_reg.dmaout_dm_err = false;
        }
    }
#endif

err:
    while (1) {
        sys_yield();
    }
}
