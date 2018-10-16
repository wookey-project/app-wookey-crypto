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
#define CRYPTO_DEBUG 0

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

enum shms {
    ID_USB = 0,
    ID_SDIO = 1
};

volatile struct {
    uint32_t address;
    uint16_t size;
} shms_tab[2] = { 0 };

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
    } while (ret == SYS_E_BUSY);

    id = id_smart;
    size = 3 + 32;

    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);

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
    cryp_init_dma(my_cryptin_handler, my_cryptout_handler, dma_in_desc, dma_out_desc);

    /*******************************************
     * cryptography initialization done.
     * Let start 2nd pase (SDIO/Crypto/USB runtime)
     *******************************************/

    size = 2;

    printf("sending end_of_cryp syncrhonization to sdio\n");
    ipc_sync_cmd.magic = MAGIC_TASK_STATE_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    /* First inform SDIO block that everything is ready... */
    do {
      ret = sys_ipc(IPC_SEND_SYNC, id_sdio, size, (char*)&ipc_sync_cmd);
    } while (ret == SYS_E_BUSY);
    printf("sending end_of_cryp to sdio done.\n");


    printf("sending end_of_cryp syncrhonization to usb\n");
    ipc_sync_cmd.magic = MAGIC_TASK_STATE_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    /* First inform SDIO block that everything is ready... */
    do {
      ret = sys_ipc(IPC_SEND_SYNC, id_usb, size, (char*)&ipc_sync_cmd);
    } while (ret == SYS_E_BUSY);
    printf("sending end_of_cryp to usb done.\n");


    printf("waiting for end_of_cryp response from USB & SDIO\n");
    for (uint8_t i = 0; i < 2; ++i) {
        id = ANY_APP;
        size = 2;

        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
        if (ret == SYS_E_DONE) {
            if (id == id_usb) {
                if (ipc_sync_cmd.magic == MAGIC_TASK_STATE_RESP
                        && ipc_sync_cmd.state == SYNC_READY) {
                    printf("USB module is ready\n");
                }
            } else if (id == id_sdio) {
                if (ipc_sync_cmd.magic == MAGIC_TASK_STATE_RESP
                        && ipc_sync_cmd.state == SYNC_READY) {
                    printf("SDIO module is ready\n");
                }
            } else {
                    printf("received msg from id %d ??\n", id);
            }
        }
    }


    /*******************************************
     * Syncrhonizing DMA SHM buffer address with USB and SDIO, through IPC
     ******************************************/
    struct dmashm_info {
        uint32_t addr;
        uint16_t size;
    };

    struct dmashm_info shm_info;

    // 2 receptions are waited: one from usb, one from sdio, in whatever order
    for (uint8_t i = 0; i < 2; ++i) {
        id = ANY_APP;
        size = sizeof(struct dmashm_info);

        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&shm_info);
        if (ret == SYS_E_DONE) {
            if (id == id_usb) {
                    shms_tab[ID_USB].address = shm_info.addr;
                    shms_tab[ID_USB].size = shm_info.size;
                    printf("received DMA SHM info from USB: @: %x, size: %d\n",
                            shms_tab[ID_USB].address, shms_tab[ID_USB].size);
            } else if (id == id_sdio) {
                    shms_tab[ID_SDIO].address = shm_info.addr;
                    shms_tab[ID_SDIO].size = shm_info.size;
                    printf("received DMA SHM info from SDIO: @: %x, size: %d\n",
                            shms_tab[ID_SDIO].address, shms_tab[ID_SDIO].size);
            } else {
                    printf("received msg from id %d ??\n", id);
            }
        }
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
    t_ipc_command ipc_mainloop_cmd = { 0 };
    logsize_t ipcsize = sizeof(ipc_mainloop_cmd);

    struct dataplane_command dataplane_command_rw = { 0 };
    struct dataplane_command dataplane_command_ack = { DATA_WR_DMA_ACK, 0, 0 };
    uint8_t sinker = 0;
    //logsize_t ipcsize = 0;

    // Default mode is encryption
    cryp_init_user(KEY_256, 0, AES_ECB, ENCRYPT);

    // hide your children !!
    while (1) {
        //unsigned char tonpere[32] = { 0 }; // "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
        sinker = id_usb;
        ipcsize = sizeof(ipc_mainloop_cmd);
        // wait for read or write request from USB

        sys_ipc(IPC_RECV_SYNC, &sinker, &ipcsize, (char*)&ipc_mainloop_cmd);

        switch (ipc_mainloop_cmd.magic) {


            case MAGIC_STORAGE_SCSI_BLOCK_SIZE_CMD:
                {
                    /***************************************************
                     * SDIO/USB block size synchronization
                     **************************************************/
                    /*
                     * INFO: this line makes a copy of the structure. Not impacting here (init phase) but
                     * should not be used in the dataplane, as it will impact the performances
                     */
                    ipc_sync_cmd = ipc_mainloop_cmd.sync_cmd;
                    /*
                     * By now, request is sent 'as is' to SDIO. Nevertheless, it would be possible
                     * to clean the struct content to avoid any data leak before transfering the content
                     * to sdio task, behavioring like a filter.
                     */ 
                    sys_ipc(IPC_SEND_SYNC, id_sdio, sizeof(struct sync_command), (char*)&ipc_sync_cmd);

                    id = id_sdio;
                    size = sizeof(struct sync_command);

                    sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);

                    /* now that SDIO has returned, let's return to USB */
                    sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(struct sync_command), (char*)&ipc_sync_cmd);

                    break;
                }

            case MAGIC_STORAGE_SCSI_BLOCK_NUM_CMD:
                {
                    /***************************************************
                     * SDIO/USB block number synchronization
                     **************************************************/
                    /*
                     * INFO: this line makes a copy of the structure. Not impacting here (init phase) but
                     * should not be used in the dataplane, as it will impact the performances
                     */
                    ipc_sync_cmd = ipc_mainloop_cmd.sync_cmd;
                    /*
                     * By now, request is sent 'as is' to SDIO. Nevertheless, it would be possible
                     * to clean the struct content to avoid any data leak before transfering the content
                     * to sdio task, behavioring like a filter.
                     */ 
                    sys_ipc(IPC_SEND_SYNC, id_sdio, sizeof(struct sync_command), (char*)&ipc_sync_cmd);

                    id = id_sdio;
                    size = sizeof(struct sync_command);

                    sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);

                    /* now that SDIO has returned, let's return to USB */
                    sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(struct sync_command), (char*)&ipc_sync_cmd);

                    break;
                }



            case DATA_WR_DMA_REQ:
                {
                    /***************************************************
                     * Write mode automaton
                     **************************************************/
                    dataplane_command_rw = ipc_mainloop_cmd.dataplane_cmd;

                    //write plane, first exec DMA, then ask SDIO for writing
                    //cryp_init(0, 0, AES_CBC_ESSIV_h_key, AES_CBC, ENCRYPT);
                    //
                    if (cryp_get_dir() == DECRYPT) {

                        cryp_wait_for_emtpy_fifos();
                        //printf("===> Asking for reinjection!\n");
                        /* When switching from DECRYPT to ENCRYPT, we have to inject the key again */
                        id = id_smart;
                        size = sizeof (struct sync_command);
                        ipc_sync_cmd.magic = MAGIC_CRYPTO_INJECT_CMD;
                        ipc_sync_cmd.data[0] = ENCRYPT;
                        ipc_sync_cmd.data_size = (uint8_t)1;

                        sys_ipc(IPC_SEND_SYNC, id_smart, sizeof(struct sync_command), (char*)&ipc_sync_cmd);

                        sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
                    }

                    cryp_init_user(KEY_256, 0, AES_ECB, ENCRYPT);
                    //cryp_init(0, KEY_256, 0, AES_ECB, ENCRYPT);
                    cryp_do_dma((const uint8_t *)shms_tab[ID_USB].address, (const uint8_t *)shms_tab[ID_SDIO].address, shms_tab[ID_USB].size, dma_in_desc, dma_out_desc);
                    // wait for DMA crypto to return
                    do {
                        sys_yield();
                    } while (status_reg.dmaout_done == true);

#if CRYPTO_DEBUG
                    printf("[write] CRYP DMA has finished ! %d\n", shms_tab[ID_USB].size);
#endif
                    status_reg.dmaout_done = false;
                    // request DMA transfer to SDIO block device (IPC)


                    sys_ipc(IPC_SEND_SYNC, id_sdio, sizeof(struct dataplane_command), (const char*)&dataplane_command_rw);

                    // wait for SDIO task acknowledge (IPC)
                    sinker = id_sdio;
                    ipcsize = sizeof(struct dataplane_command);

                    ret = sys_ipc(IPC_RECV_SYNC, &sinker, &ipcsize, (char*)&dataplane_command_ack);

#if CRYPTO_DEBUG
                    printf("[write] received ipc from sdio (%d)\n", sinker);
#endif
                    // set ack magic for write ack
                    dataplane_command_ack.magic = DATA_WR_DMA_ACK;
                    // acknowledge to USB: data has been written to disk (IPC)
                    sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(struct dataplane_command), (const char*)&dataplane_command_ack);

                    break;
                }


            case DATA_RD_DMA_REQ:
                {
                    dataplane_command_rw = ipc_mainloop_cmd.dataplane_cmd;
                    /***************************************************
                     * Read mode automaton
                     **************************************************/

                    // first ask SDIO to load data to its own buffer from the SDCard
                    sys_ipc(IPC_SEND_SYNC, id_sdio, sizeof(struct dataplane_command), (const char*)&dataplane_command_rw);

                    // wait for SDIO task acknowledge (IPC)
                    sinker = id_sdio;
                    ipcsize = sizeof(struct dataplane_command);

                    ret = sys_ipc(IPC_RECV_SYNC, &sinker, &ipcsize, (char*)&dataplane_command_ack);

#if CRYPTO_DEBUG
                    printf("[read] received ipc from sdio (%d): data loaded\n", sinker);
#endif

                    if (cryp_get_dir() == ENCRYPT) {

                        cryp_wait_for_emtpy_fifos();
                        /* When switching from ENCRYPT to DECRYPT, we only have to prepare the key!
                         * We only have to do the key preparation once when multiple decryptions are done.
                         */
                        cryp_set_mode(AES_KEY_PREPARE);
                    }

                    cryp_init_user(KEY_256, 0, AES_ECB, DECRYPT);
                    // read plane, uncypher, from sdio to usb
                    //cryp_init(0, KEY_256, 0, AES_ECB, DECRYPT);
                    cryp_do_dma((const uint8_t *)shms_tab[ID_SDIO].address, (const uint8_t *)shms_tab[ID_USB].address, shms_tab[ID_SDIO].size, dma_in_desc, dma_out_desc);
                    // wait for DMA crypto to return
                    do {
                        sys_yield();
                    } while (status_reg.dmaout_done == true);

#if CRYPTO_DEBUG
                    printf("[read] CRYP DMA has finished !\n");
#endif
                    // set ack magic for read ack
                    dataplane_command_ack.magic = DATA_RD_DMA_ACK;

                    // acknowledge to USB: data has been written to disk (IPC)
                    sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(struct dataplane_command), (const char*)&dataplane_command_ack);

                    break;

                }


            default:
                {
                    printf("invalid request from USB !\n");
                    // returning INVALID magic to USB
                    ipc_mainloop_cmd.magic = MAGIC_INVALID;

                    // acknowledge to USB: data has been written to disk (IPC)
                    sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(t_ipc_command), (const char*)&ipc_mainloop_cmd);
                    break;

                }
        }


    }

err:
    while (1) {
        sys_yield();
    }
}
