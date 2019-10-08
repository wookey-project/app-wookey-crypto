/**
 * @file main.c
 *
 * \brief Main of dummy
 *
 */


#include "libc/syscall.h"
#include "libc/stdio.h"
#include "libc/nostd.h"
#include "libc/string.h"
#include "libc/regutils.h"
#include "libc/arpa/inet.h"
#include "libcryp.h"
//#include "dma_regs.h"
#include "main.h"
#include "handlers.h"
#include "wookey_ipc.h"
#include "autoconf.h"

/* Include hash header for CBC-ESSIV IV derivation */
#include "libsig.h"

/* Include the AES or TDES header (for CBC-ESSIV IV derivation) */

#ifdef CONFIG_AES256_CBC_ESSIV
# include "aes.h"
#endif
#ifdef CONFIG_TDES_CBC_ESSIV
# include "libdes.h"
#endif

/* The SCSI block size that has been set in the configuration */
#ifdef CONFIG_USB_DEV_SCSI_BLOCK_SIZE_512
# define SCSI_BLOCK_SIZE 512
#else
# ifdef CONFIG_USB_DEV_SCSI_BLOCK_SIZE_1024
#  define SCSI_BLOCK_SIZE 1024
# else
#  ifdef CONFIG_USB_DEV_SCSI_BLOCK_SIZE_2048
#   define SCSI_BLOCK_SIZE 2048
#  else
#   ifdef CONFIG_USB_DEV_SCSI_BLOCK_SIZE_4096
#    define SCSI_BLOCK_SIZE 4096
#   else
#    ifdef CONFIG_USB_DEV_SCSI_BLOCK_SIZE_8192
#     define SCSI_BLOCK_SIZE 8192
#    else
#     error "SCSI block size is not defined!"
#    endif
#   endif
#  endif
# endif
#endif

volatile uint32_t scsi_block_size = SCSI_BLOCK_SIZE;

/* The size that we get from the SD layer */
volatile uint32_t sdio_block_size = 0;

#define CRYPTO_MODE CRYP_PRODMODE
#define CRYPTO_DEBUG 0

#ifdef CONFIG_APP_CRYPTO_USE_GETCYCLES
const char *tim = "tim";
#endif

volatile uint32_t numipc = 0;

bool    sdio_ready = false;
bool    usb_ready = false;
bool    smart_ready = false;

enum shms {
    ID_USB = 0,
    ID_SDIO = 1
};

volatile struct {
    uint32_t address;
    uint16_t size;
} shms_tab[2] = {
    {.address = 0,.size = 0},
    {.address = 0,.size = 0}
};

uint32_t td_dma = 0;

void    my_cryptin_handler(uint8_t irq, uint32_t status);
void    my_cryptout_handler(uint8_t irq, uint32_t status);

void    encrypt_dma(const uint8_t * data_in, uint8_t * data_out,
                    uint32_t data_len);

#if 1
void    init_crypt_dma(const uint8_t * data_in,
                       uint8_t * data_out, uint32_t data_len);
#endif

uint8_t id_sdio = 0;
uint8_t id_usb = 0;
uint8_t id_smart = 0;
uint8_t id_pin   = 0;

uint32_t dma_in_desc;
uint32_t dma_out_desc;

static unsigned char CBC_ESSIV_h_key[32] = { 0 };

static bool CBC_ESSIV_h_key_initialized = false;
static bool CBC_ESSIV_ctx_initialized = false;

#ifdef CONFIG_AES256_CBC_ESSIV
static aes_context CBC_ESSIV_ctx;
#else
#ifdef CONFIG_TDES_CBC_ESSIV
static des3_context CBC_ESSIV_ctx;
#else
#error "No FDE algorithm has been selected ..."
#endif
#endif

/* This is the global buffer holding the SD card unique serial used for
 * IV derivation/
 * The CID is on 128 bits as per SDIO standard.
 */
uint8_t sd_serial[4*sizeof(uint32_t)] = { 0 };
/*
*   unlocking password diversification
*/

static int unlocking_passwd_derivation(uint8_t pwd[16], 
          const uint8_t * restrict sd_serial, unsigned int sd_serial_len, 
          const uint8_t * restrict passwd, unsigned int passwd_len)
{
    uint8_t passwd_digest[SHA256_DIGEST_SIZE];
    sha256_context sha256_ctx;

    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, sd_serial, sd_serial_len);
    sha256_update(&sha256_ctx, passwd, paswd_len);
    sha256_final(&sha256_ctx, passwd_digest);
    
      memcpy(passwd_digest,pwd,16);
      
}
/* Crypto helper to perform the IV derivation for CBC-ESSIV depending
 * on the block address.
 * The diversification varies depending on the underlying block cipher.
 */
static int cbc_essiv_iv_derivation(uint32_t sector_number, uint8_t * sd_unique_serial, unsigned int sd_unique_serial_len, uint8_t * iv,
                                   unsigned int iv_len)
{
    /* The key hash is not really a secret, we can safely use an unprotected (and faster) AES/TDES algorithm.
     *
     * NOTE: obviously, we cannot use accelerated AES/TDES here since it is already configured with the master key
     * to perform blocks encryption/decryption!
     */

    /* Sanity check: the key hash must be initialized */
    if (CBC_ESSIV_h_key_initialized == false) {
        goto err;
    }
    /* Handle the SD unique serial derivation for the IV */
    uint8_t sd_serial_digest[SHA256_DIGEST_SIZE];
    sha256_context sha256_ctx;
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, sd_unique_serial, sd_unique_serial_len);
    sha256_final(&sha256_ctx, sd_serial_digest);

#ifdef CONFIG_AES256_CBC_ESSIV
    /*
     * The AES ESSIV IV before encryption is split using the following
     * scheme:
     *  
     * <------ 32 bits -----------><-------- 96 bits ----------->
     * [ sector number big endian | 96 bits MSB of SHA-256(CID) ]
     * <----------------------- 128 bits ----------------------->
     * 
     * with "sector number big endian" being the sector number encoded
     * on 32 bits big endian, and CID being the SD unique serial number.
     */
    uint8_t sector_number_buff[16] = { 0 };
    /* Encode the sector number in big endian 16 bytes */
    uint32_t big_endian_sector_number = htonl(sector_number);

    sector_number_buff[0] = (big_endian_sector_number >> 0) & 0xff;
    sector_number_buff[1] = (big_endian_sector_number >> 8) & 0xff;
    sector_number_buff[2] = (big_endian_sector_number >> 16) & 0xff;
    sector_number_buff[3] = (big_endian_sector_number >> 24) & 0xff;
    /* Copy bytes of the SD serial hash.
     * NOTE: only the 96 bits MSB from the SD serial digest are copied to the
     * 96 bits LSB of the IV.
     */
    memcpy(&(sector_number_buff[4]), sd_serial_digest, sizeof(sector_number_buff)-4);

    /* Sanity checks */
    if (iv_len != 16) {
        goto err;
    }
    if (CBC_ESSIV_ctx_initialized == false) {
        if (aes_init
            (&CBC_ESSIV_ctx, CBC_ESSIV_h_key, AES256, NULL, ECB, AES_ENCRYPT,
             AES_SOFT_UNMASKED, NULL, NULL, -1, -1)) {
            goto err;
        }
        CBC_ESSIV_ctx_initialized = true;
    }
    if (aes_exec(&CBC_ESSIV_ctx, sector_number_buff, iv, iv_len, -1, -1)) {
        goto err;
    }
#else
#ifdef CONFIG_TDES_CBC_ESSIV
    /*
     * The TDES ESSIV IV before encryption is split using the following
     * scheme:
     *  
     * <------ 32 bits -----------><-------- 32 bits ----------->
     * [ sector number big endian | 32 bits MSB of SHA-256(CID) ]
     * <----------------------- 64 bits ------------------------>
     * 
     * with "sector number big endian" being the sector number encoded
     * on 32 bits big endian, and CID being the SD unique serial number.
     */
    uint8_t sector_number_buff[8] = { 0 };
    /* Encode the sector number in big endian 8 bytes */
    uint32_t big_endian_sector_number = htonl(sector_number);

    sector_number_buff[0] = (big_endian_sector_number >> 0) & 0xff;
    sector_number_buff[1] = (big_endian_sector_number >> 8) & 0xff;
    sector_number_buff[2] = (big_endian_sector_number >> 16) & 0xff;
    sector_number_buff[3] = (big_endian_sector_number >> 24) & 0xff;
    /* Copy bytes of the SD serial hash.
     * NOTE: only the 32 bits MSB from the SD serial digest are copied to the
     * 32 bits LSB of the IV.
     */
    memcpy(&(sector_number_buff[4]), sd_serial_digest, sizeof(sector_number_buff)-4);

    /* Sanity checks */
    if (iv_len != 8) {
        goto err;
    }
    if (CBC_ESSIV_ctx_initialized == false) {
        if(des3_set_keys(&CBC_ESSIV_ctx, &(CBC_ESSIV_h_key[0]),
                       &(CBC_ESSIV_h_key[8]), &(CBC_ESSIV_h_key[16]), DES_ENCRYPTION)){
            goto err;
        }
        CBC_ESSIV_ctx_initialized = true;
    }
    if(des3_exec(&CBC_ESSIV_ctx, sector_number_buff, iv)){
        goto err;
    }

#else
#error "No FDE algorithm has been selected ..."
#endif
#endif
    return 0;
 err:
    return -1;

}


/* Ask the dfusmart task to reboot through IPC */
static void ask_reboot(void){
        struct sync_command_data sync_command;
        sync_command.magic = MAGIC_REBOOT_REQUEST;
        sync_command.state = SYNC_WAIT;
        sys_ipc(IPC_SEND_SYNC, id_smart,
                    sizeof(struct sync_command),
                    (char*)&sync_command);
	/* We should not end up here in case of reset ...
	 * But this can happen when dfusmart refuses to perform
	 * the reset: in this case, we yield.
	 */
        while (1) {
        	sys_yield();
        }
}



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
    char   *wellcome_msg = "hello, I'm crypto";

//    char buffer_in[128];
    logsize_t size;
    uint8_t id = 0;
    char    ipc_buf[32] = { 0 };
    const char *inject_order = "INJECT";

    struct sync_command ipc_sync_cmd;
    struct sync_command_data ipc_sync_cmd_data;

    strncpy(ipc_buf, inject_order, 6);
#ifdef CONFIG_APP_CRYPTO_USE_GETCYCLES
    device_t dev2;

    memset(&dev2, 0, sizeof(device_t));
    int     dev_descriptor = 0;
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
    if ((ret = sys_init(INIT_DEVACCESS, &dev2, &dev_descriptor)) != SYS_E_DONE) {
        printf("sys_init returns %s !\n", strerror(ret));
        goto err_init;
    }

#endif

    if ((ret = sys_init(INIT_GETTASKID, "smart", &id_smart)) != SYS_E_DONE) {
        printf("sys_init returns %s !\n", strerror(ret));
        goto err_init;
    }
    printf("smart is task %x !\n", id_smart);

    if ((ret = sys_init(INIT_GETTASKID, "sdio", &id_sdio)) != SYS_E_DONE) {
        printf("sys_init returns %s !\n", strerror(ret));
        goto err_init;
    }
    printf("sdio is task %x !\n", id_sdio);

    if ((ret = sys_init(INIT_GETTASKID, "usb", &id_usb)) != SYS_E_DONE) {
        printf("sys_init returns %s !\n", strerror(ret));
        goto err_init;
    }
    printf("usb is task %x !\n", id_usb);

    if ((ret = sys_init(INIT_GETTASKID, "pin", &id_pin)) != SYS_E_DONE) {
        printf("sys_init returns %s !\n", strerror(ret));
        goto err_init;
    }
    printf("pin is task %x !\n", id_pin);

    cryp_early_init(true, CRYP_MAP_AUTO, CRYP_USER, (int *) &dma_in_desc,
                    (int *) &dma_out_desc);

    printf("set init as done\n");
    if ((ret = sys_init(INIT_DONE)) != SYS_E_DONE) {
        printf("sys_init returns %s !\n", strerror(ret));
        goto err_init;
    }

    /*******************************************
     * let's synchronize with other tasks
     *******************************************/
    do {
        size = sizeof(struct sync_command);

        /*
         * CRYPTO is a central node, it waits for mostly all tasks
         * (usb, sdio & smart), in any order
         */
        id = ANY_APP;
        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char *) &ipc_sync_cmd);
        if (ret != SYS_E_DONE) {
            /* defensive programing, should not append as there is no
             * asynchronous IPC in this task */
            continue;
        }
        if (ipc_sync_cmd.magic == MAGIC_TASK_STATE_CMD
            && ipc_sync_cmd.state == SYNC_READY) {
            printf("task %x has finished its init phase, acknowledge...\n", id);
        }

        ipc_sync_cmd.magic = MAGIC_TASK_STATE_RESP;
        ipc_sync_cmd.state = SYNC_ACKNOWLEDGE;

        size = sizeof(struct sync_command);
        ret = sys_ipc(IPC_SEND_SYNC, id, size, (char *) &ipc_sync_cmd);
        if (ret != SYS_E_DONE) {
            printf("sys_ipc(IPC_SEND_SYNC, %d) failed! Exiting...\n", id);
            goto err;
        }

        if (id == id_smart) {
            smart_ready = true;
        }
        if (id == id_usb) {
            usb_ready = true;
        }
        if (id == id_sdio) {
            sdio_ready = true;
        }

    } while ((smart_ready == false)
             || (usb_ready == false)
             || (sdio_ready == false));
    printf("All tasks have finished their initialization, continuing...\n");

    /*******************************************
     * End of full task end_of_init synchronization
     *******************************************/

    /*******************************************
     * Ask smart for key injection and
     * get back key hash
     *******************************************/


    /* Then Syncrhonize with smart */
    size = sizeof(struct sync_command);

    printf("sending end_of_init synchronization to smart\n");
    ipc_sync_cmd.magic = MAGIC_CRYPTO_INJECT_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    ret = sys_ipc(IPC_SEND_SYNC, id_smart, size, (char *) &ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_SEND_SYNC, id_smart) failed! Exiting...\n");
        goto err;
    }

    id = id_smart;
    size = sizeof(struct sync_command_data);

    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char *) &ipc_sync_cmd_data);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_RECV_SYNC) failed! Exiting...\n");
        goto err;
    }

    if (ipc_sync_cmd_data.magic == MAGIC_CRYPTO_INJECT_RESP
        && ipc_sync_cmd_data.state == SYNC_DONE) {
        printf("key injection done from smart. Hash received.\n");
	/* Check size overflow */
	if(ipc_sync_cmd_data.data_size > sizeof(CBC_ESSIV_h_key)){
		printf("Received CBC_ESSIV_h_key size overflow!\n");
		goto err;
	}
        memcpy(CBC_ESSIV_h_key, &ipc_sync_cmd_data.data.u8,
               ipc_sync_cmd_data.data_size);
        CBC_ESSIV_h_key_initialized = true;
#if CONFIG_SMARTCARD_DEBUG
        printf("hash received:\n");
        hexdump(CBC_ESSIV_h_key, 32);
#endif
    } else {
        goto err;
    }
    cryp_init_dma(my_cryptin_handler, my_cryptout_handler, dma_in_desc,
                  dma_out_desc);

    /*******************************************
     * Here, the key injection is done. This means that the authentication phase
     * is terminated (this is required for the key injection to be complete).
     * In order to ensure that smart has not been corrupted and that the user
     * has validated his passphrase, we ask pin to confirm this state.
     *******************************************/
    size = sizeof(struct sync_command);
    ipc_sync_cmd_data.magic = MAGIC_AUTH_STATE_PASSED;
    ipc_sync_cmd_data.state = SYNC_WAIT;

    if ((sys_ipc(IPC_SEND_SYNC, id_pin, size, (char*)&ipc_sync_cmd_data)) != SYS_E_DONE) {
        printf("err: unable to request state confirmation from PIN\n");
        goto err;
    }

    /* and wait for receiving... */
    id = id_pin;
    size = sizeof(struct sync_command);
    if ((sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data)) != SYS_E_DONE) {
        printf("err: unable to request state confirmation from PIN\n");
        goto err;
    }
    if (   ipc_sync_cmd_data.magic != MAGIC_AUTH_STATE_PASSED
        || ipc_sync_cmd_data.state != SYNC_ACKNOWLEDGE) {
        printf("Pin didn't acknowledge that we are in post authentication phase!\n");
        goto err;
    }

    printf("PIN has confirmed that we are in post-authentication phase. Continuing...\n");


    /*******************************************
     * cryptography initialization done.
     * Let start 2nd pase (SDIO/Crypto/USB runtime)
     *******************************************/

    size = sizeof(struct sync_command);

    printf("sending end_of_cryp synchronization to sdio\n");
    ipc_sync_cmd.magic = MAGIC_TASK_STATE_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    /* First inform SDIO block that everything is ready... */
    ret = sys_ipc(IPC_SEND_SYNC, id_sdio, size, (char *) &ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_SEND_SYNC, id_sdio) failed! Exiting...\n");
        goto err;
    }

    printf("sending end_of_cryp to sdio done.\n");


    printf("sending end_of_cryp synchronization to usb\n");
    ipc_sync_cmd.magic = MAGIC_TASK_STATE_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    /* First inform SDIO block that everything is ready... */
    ret = sys_ipc(IPC_SEND_SYNC, id_usb, size, (char *) &ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_SEND_SYNC, id_sdio) failed! Exiting...\n");
        goto err;
    }

    printf("sending end_of_cryp to usb done.\n");


    /********************************************************
     * Syncrhonize tasks: waiting for both SDIO and USB to acknowledge
     * their services initialization
     *******************************************************/
    /* 2 receptions are waited: one from usb, one from sdio, in whatever
     * order */

    printf("waiting for end_of_cryp response from USB & SDIO\n");

    id = ANY_APP;
    size = sizeof(struct sync_command);


    for (uint8_t i = 0; i < 2; ++i) {
        id = ANY_APP;
        size = sizeof(struct sync_command);

        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char *) &ipc_sync_cmd);

        if (ret == SYS_E_DONE) {
            if (id == id_usb
                && ipc_sync_cmd.magic == MAGIC_TASK_STATE_RESP
                && ipc_sync_cmd.state == SYNC_READY) {
                printf("USB module is ready\n");
            } else if (id == id_sdio
                       && ipc_sync_cmd.magic == MAGIC_TASK_STATE_RESP
                       && ipc_sync_cmd.state == SYNC_READY) {
                printf("SDIO module is ready\n");
            } else {
                printf("received msg from id %d ??\n", id);
                i--;
            }
        }
        else{
            goto err;
        }
    }

    /* now that both tasks have acknowledge their initialization phase, we can
     * unlock them and wait them to send us their DMA SHM.
     * This acknowledgement ensure that all three SDIO, CRYTO and DMA_SHM are
     * syncrhonous at each time of the initialization automaton.
     */
    ipc_sync_cmd.magic = MAGIC_TASK_STATE_RESP;
    ipc_sync_cmd.state = SYNC_ACKNOWLEDGE;
    sys_ipc(IPC_SEND_SYNC, id_sdio, sizeof(struct sync_command),
            (char *) &ipc_sync_cmd);
    sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(struct sync_command),
            (char *) &ipc_sync_cmd);



    /*******************************************
     * Syncrhonizing DMA SHM buffer address with USB and SDIO, through IPC
     ******************************************/
    /* 2 receptions are waited: one from usb, one from sdio, in whatever
     * order */
    for (uint8_t i = 0; i < 2; ++i) {
        id = ANY_APP;
        size = sizeof(struct sync_command_data);

        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char *) &ipc_sync_cmd_data);
        if (ret == SYS_E_DONE) {
            if (id == id_usb
                && ipc_sync_cmd_data.magic == MAGIC_DMA_SHM_INFO_CMD) {
                shms_tab[ID_USB].address = ipc_sync_cmd_data.data.u32[0];
                shms_tab[ID_USB].size =
                    (uint16_t) ipc_sync_cmd_data.data.u32[1];
                printf("received DMA SHM info from USB: @: %x, size: %d\n",
                       shms_tab[ID_USB].address, shms_tab[ID_USB].size);
            } else if (id == id_sdio &&
                       ipc_sync_cmd_data.magic == MAGIC_DMA_SHM_INFO_CMD) {
                shms_tab[ID_SDIO].address = ipc_sync_cmd_data.data.u32[0];
                shms_tab[ID_SDIO].size =
                    (uint16_t) ipc_sync_cmd_data.data.u32[1];
                printf("received DMA SHM info from SDIO: @: %x, size: %d\n",
                       shms_tab[ID_SDIO].address, shms_tab[ID_SDIO].size);
            } else {
                printf("received msg from id %d ??\n", id);
            }
        }
        else{
            goto err;
        }
    }
    /* now that both tasks have sent their SHM, we can acknowledge both of them,
     * starting with SDIO (the backend) and finishing with USB (the frontend) */
    ipc_sync_cmd.magic = MAGIC_DMA_SHM_INFO_RESP;
    ipc_sync_cmd.state = SYNC_ACKNOWLEDGE;
    if ((ret = sys_ipc(IPC_SEND_SYNC, id_sdio, sizeof(struct sync_command),
            (char *) &ipc_sync_cmd)) != SYS_E_DONE) {
        printf("unable to acknowledge SDIO\n");
        goto err;
    }
    
    if ((ret = sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(struct sync_command),
            (char *) &ipc_sync_cmd)) != SYS_E_DONE) {
        printf("unable to acknowledge USB\n");
        goto err;
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
    t_ipc_command ipc_mainloop_cmd;

    memset((void *) &ipc_mainloop_cmd, 0, sizeof(t_ipc_command));
    logsize_t ipcsize = sizeof(ipc_mainloop_cmd);

    struct dataplane_command dataplane_command_rw = {
        .magic = MAGIC_INVALID,
        .sector_address = 0,
        .num_sectors = 0
    };
    struct dataplane_command dataplane_command_ack = {
        .magic = MAGIC_DATA_WR_DMA_ACK,
        .sector_address = 0,
        .num_sectors = 0
    };
    uint8_t sinker = 0;

    //logsize_t ipcsize = 0;

    // Default mode is encryption
#ifdef CONFIG_AES256_CBC_ESSIV
    cryp_init_user(KEY_256, NULL, 0, AES_CBC, ENCRYPT);
#else
#ifdef CONFIG_TDES_CBC_ESSIV
    cryp_init_user(KEY_192, NULL, 0, TDES_CBC, ENCRYPT);
#else
#error "No FDE algorithm has been selected ..."
#endif
#endif

    while (1) {
        /* requests can come from USB, SDIO, or SMART */
        sinker = ANY_APP;
        ipcsize = sizeof(ipc_mainloop_cmd);
        // wait for read or write request from USB

        ret = sys_ipc(IPC_RECV_SYNC, &sinker, &ipcsize, (char *) &ipc_mainloop_cmd);
        if(ret != SYS_E_DONE) {
            goto err;
        }

        switch (ipc_mainloop_cmd.magic) {


            case MAGIC_STORAGE_SCSI_BLOCK_SIZE_CMD:
                {
                    /***************************************************
                     * SDIO/USB block size synchronization
                     **************************************************/
                    if (sinker != id_usb) {
                        printf
                            ("block size request command only allowed from USB app\n");
                        continue;
                    }
                    /*
                     * INFO: this line makes a copy of the structure. Not impacting here (init phase) but
                     * should not be used in the dataplane, as it will impact the performances
                     */
                    ipc_sync_cmd_data = ipc_mainloop_cmd.sync_cmd_data;
                    /*
                     * By now, request is sent 'as is' to SDIO. Nevertheless, it would be possible
                     * to clean the struct content to avoid any data leak before transfering the content
                     * to sdio task, behavioring like a filter.
                     */
                    sys_ipc(IPC_SEND_SYNC, id_sdio,
                            sizeof(struct sync_command_data),
                            (char *) &ipc_sync_cmd_data);

                    id = id_sdio;
                    size = sizeof(struct sync_command_data);

                    ret = sys_ipc(IPC_RECV_SYNC, &id, &size,
                            (char *) &ipc_sync_cmd_data);
                    if(ret != SYS_E_DONE) {
                       goto err;
                    }
                    /* Save the block sizes (SDIO and SCSI) since we will need it later */
                    sdio_block_size = ipc_sync_cmd_data.data.u32[0];
                    /* Override the SCSI block size and number */
                    /* FIXME: use a uint64_t to avoid overflows */
                    ipc_sync_cmd_data.data.u32[1] =
                        (ipc_sync_cmd_data.data.u32[1] / scsi_block_size) *
                        ipc_sync_cmd_data.data.u32[0];
                    ipc_sync_cmd_data.data.u32[0] = scsi_block_size;


                    /* now that SDIO has returned,... */
                    /* 1) update our sd_serial global buffer using the card serial id (CID of the card on 128 bits) */
                    /* 2) return usefull infos to USB (without serial and
                     * any potential other leak) */
                    if(sizeof(sd_serial) < (4*sizeof(uint32_t))){
                        /* CID is on 128 bits per SD standard */
                        goto err;
		    }
		    memcpy(sd_serial, &(ipc_sync_cmd_data.data.u32[2]), 4*sizeof(uint32_t));

                  /* Now unlock the SDCard */

                  /* contact smart for the password */
                        ipc_sync_cmd_data.magic = MAGIC_STORAGE_PASSWD;
                        ipc_sync_cmd_data.data_size = (uint8_t) 0;

                        ret =
                            sys_ipc(IPC_SEND_SYNC, id_smart,
                                    sizeof(struct sync_command),
                                    (char *) &ipc_sync_cmd_data);
                        if (ret != SYS_E_DONE) {
                            printf("%s: unable to send ipc to smart! ret=%d\n",
                                    __func__, ret);
                            goto err;
                        }

                        id = id_smart;
                        size = sizeof(struct sync_command_data);
                        sys_ipc(IPC_RECV_SYNC, &id, &size,
                                (char *) &ipc_sync_cmd_data);
                        if (ret != SYS_E_DONE) {
                            printf
                                ("%s: unable to receive ipc from smart! ret=%d\n",
                                 __func__, ret);
                            goto err;
                        }
                        //sanity checks 
                        if(size>16) {
                              printf("Damned wrong unlocking data\n");
                              goto err;
                        }
                  /* Derive the SDIO passwd from the cleartext sent */
                        {
                           uint8_t pwd[16];
                           unlocking_passwd_derivation(pwd, sd_serial,16, 
                                            ipc_sync_cmd_data.data.u8+4,
                                            ipc_sync_cmd_data.data.u32[0]);
                          memcpy(pwd,ipc_sync_cmd_data.data.u8+4,16);
                          ipc_sync_data.data.u32[0]=16;
                          memset(pwd,0,16);//cleanup 
                        }
                  /*  give SDIO the computed password*/

                        //For the time being resquest is just forwarded to SDIO
                        id = id_sdio;
                        size = sizeof(struct sync_command_data);
                        ipc_sync_cmd_data.magic=MAGIC_STORAGE_PASSWD;
                          
                        ret = sys_ipc(IPC_SEND_SYNC, &id, &size,
                            (char *) &ipc_sync_cmd_data);
                        if(ret != SYS_E_DONE) {
                          goto err;
                        }
                        //Wait for SDIO to ack the unlocking
  
                        id = id_sdio;
                        size = sizeof(struct sync_command_data);
                        sys_ipc(IPC_RECV_SYNC, &id, &size,
                                (char *) &ipc_sync_cmd_data);
                        if (ret != SYS_E_DONE) {
                            printf
                                ("%s: unable to receive ipc from sdio! ret=%d\n",
                                 __func__, ret);
                            goto err;
                        }
                        //Check values returned here to confirm unlocking 
                      


                    /* Now zeroize the IPC structure to avoid info leak to USB task */
                    memset(&(ipc_sync_cmd_data.data.u32[2]), 0x0, 6*sizeof(uint32_t));
                    
                    ret = sys_ipc(IPC_SEND_SYNC, id_usb,
                            sizeof(struct sync_command_data),
                            (char *) &ipc_sync_cmd_data);
                    if(ret != SYS_E_DONE) {
                       goto err;
                    }
                    break;
                }

                  
            case MAGIC_STORAGE_SCSI_BLOCK_NUM_CMD:
                {
                    /***************************************************
                     * SDIO/USB block number synchronization
                     **************************************************/

                    if (sinker != id_usb) {
                        printf
                            ("block num request command only allowed from USB app\n");
                        continue;
                    }
                    /* Get the block size */
                    struct sync_command_data ipc_sync_get_block_size = { 0 };
                    ipc_sync_get_block_size.magic =
                        MAGIC_STORAGE_SCSI_BLOCK_SIZE_CMD;
                    ret = sys_ipc(IPC_SEND_SYNC, id_sdio,
                            sizeof(struct sync_command_data),
                            (char *) &ipc_sync_get_block_size);
                    if(ret != SYS_E_DONE) {
                       goto err;
                    }

                    id = id_smart;
                    size = sizeof(struct sync_command_data);
                    ret = sys_ipc(IPC_RECV_SYNC, &id, &size,
                            (char *) &ipc_sync_get_block_size);
                    if(ret != SYS_E_DONE) {
                       goto err;
                    }

                    sdio_block_size = ipc_sync_cmd_data.data.u32[0];

                    /*
                     * INFO: this line makes a copy of the structure. Not impacting here (init phase) but
                     * should not be used in the dataplane, as it will impact the performances
                     */
                    ipc_sync_cmd_data = ipc_mainloop_cmd.sync_cmd_data;
                    /*
                     * By now, request is sent 'as is' to SDIO. Nevertheless, it would be possible
                     * to clean the struct content to avoid any data leak before transfering the content
                     * to sdio task, behavioring like a filter.
                     */
                    ret = sys_ipc(IPC_SEND_SYNC, id_sdio,
                            sizeof(struct sync_command_data),
                            (char *) &ipc_sync_cmd_data);
                    if(ret != SYS_E_DONE) {
                       goto err;
                    }

                    id = id_sdio;
                    size = sizeof(struct sync_command_data);

                    ret = sys_ipc(IPC_RECV_SYNC, &id, &size,
                            (char *) &ipc_sync_cmd_data);
                    if(ret != SYS_E_DONE) {
                       goto err;
                    }

                    /* for PIN, we give SCSI block size to get the correct size info */
                    ret = sys_ipc(IPC_SEND_SYNC, id_smart,
                            sizeof(struct sync_command_data),
                            (char *) &ipc_sync_cmd_data);
                    if(ret != SYS_E_DONE) {
                       goto err;
                    }

                    /* Override the SCSI block number */
                    /* FIXME: use a uint64_t to avoid overflows */
                    ipc_sync_cmd_data.data.u32[1] =
                        (ipc_sync_cmd_data.data.u32[1] / scsi_block_size) *
                        ipc_sync_get_block_size.data.u32[0];

                    /* now that SDIO has returned, let's return to USB */
                    memset(&(ipc_sync_cmd_data.data.u32[2]), 0x0, 6*sizeof(uint32_t));
                    ret = sys_ipc(IPC_SEND_SYNC, id_usb,
                            sizeof(struct sync_command_data),
                            (char *) &ipc_sync_cmd_data);
                    if(ret != SYS_E_DONE) {
                       goto err;
                    }

                    break;
                }

            case MAGIC_DATA_WR_DMA_REQ:
                {
                    /***************************************************
                     * Write mode automaton
                     **************************************************/
                    if (sinker != id_usb) {
                        printf
                            ("data wr DMA request command only allowed from USB app\n");
                        continue;
                    }
                    dataplane_command_rw = ipc_mainloop_cmd.dataplane_cmd;
                    struct dataplane_command sdio_dataplane_command_rw =
                        dataplane_command_rw;
                    uint32_t scsi_num_sectors =
                        dataplane_command_rw.num_sectors;
                    uint32_t scsi_sector_address =
                        dataplane_command_rw.sector_address;

                    uint64_t tmp = scsi_num_sectors;

                    tmp *= scsi_block_size;
                    tmp /= sdio_block_size;

                    if (tmp > 0xffffffff) {
                        printf
                            ("PANIC! scsi num sectors calculation generated overflow !!!\n");
                        goto err;
                    }
                    sdio_dataplane_command_rw.num_sectors = (uint32_t) tmp;

                    tmp = dataplane_command_rw.sector_address;
                    tmp *= scsi_block_size;
                    tmp /= sdio_block_size;

                    if (tmp > 0xffffffff) {
                        printf
                            ("PANIC! scsi sector adress calculation generated overflow !!!\n");
                        goto err;
                    }
                    sdio_dataplane_command_rw.sector_address = (uint32_t) tmp;

                    /* Ask smart to reinject the key (only for AES) */
#ifdef CONFIG_AES256_CBC_ESSIV
                    //write plane, first exec DMA, then ask SDIO for writing
                    //
                    if (cryp_get_dir() == DECRYPT) {
#if CRYPTO_DEBUG
                        printf("===> Asking for reinjection!\n");
#endif
                        /* When switching from DECRYPT to ENCRYPT, we have to inject the key again */
                        id = id_smart;
                        size = sizeof(struct sync_command);
                        ipc_sync_cmd_data.magic = MAGIC_CRYPTO_INJECT_CMD;
                        ipc_sync_cmd_data.data.u8[0] = ENCRYPT;
                        ipc_sync_cmd_data.data_size = (uint8_t) 1;

                        ret =
                            sys_ipc(IPC_SEND_SYNC, id_smart,
                                    sizeof(struct sync_command),
                                    (char *) &ipc_sync_cmd_data);
                        if (ret != SYS_E_DONE) {
                            printf("%s: unable to send ipc to smart! ret=%d\n",
                                    __func__, ret);
                            goto err;
                        }

                        sys_ipc(IPC_RECV_SYNC, &id, &size,
                                (char *) &ipc_sync_cmd_data);
                        if (ret != SYS_E_DONE) {
                            printf
                                ("%s: unable to receive ipc from smart! ret=%d\n",
                                 __func__, ret);
                            goto err;
                        }
#if CRYPTO_DEBUG
                        printf("===> Key reinjection done!\n");
#endif
                    }
#endif


                    /********* ENCRYPTION LOGIC ************************************************************/
                    /* We have to split our encryption in multiple subencryptions to deal with IV modification on the crypto block size boundaries
                     * boundaries.
                     */
                    if ((scsi_block_size == 0) || (sdio_block_size == 0)) {
                        printf
                            ("Error: DMA WR request while the block sizes have not been read!\n");
                        goto err;
                    }
                    uint32_t num_cryp_blocks = scsi_num_sectors;
                    uint32_t usb_address = shms_tab[ID_USB].address;
                    uint32_t sdio_address = shms_tab[ID_SDIO].address;
                    unsigned int i;

                    /* [RB] FIXME: sanity checks on the USB and SDIO buffer sizes that must be compliant! */
                    for (i = 0; i < num_cryp_blocks; i++) {
#ifdef CONFIG_AES256_CBC_ESSIV
                        uint8_t curr_essiv_iv[16] = { 0 };
                        cbc_essiv_iv_derivation((scsi_sector_address + i), sd_serial, sizeof(sd_serial),
                                                curr_essiv_iv, 16);
 DMA_WR_XFR_AGAIN:
                        cryp_init_user(KEY_256, curr_essiv_iv, 16, AES_CBC,
                                       ENCRYPT);
#else
#ifdef CONFIG_TDES_CBC_ESSIV
                        uint8_t curr_essiv_iv[8] = { 0 };
                        cbc_essiv_iv_derivation((scsi_sector_address + i), sd_serial, sizeof(sd_serial),
                                                curr_essiv_iv, 8);
 DMA_WR_XFR_AGAIN:
                        cryp_init_user(KEY_192, curr_essiv_iv, 8, TDES_CBC,
                                       ENCRYPT);
#else
#error "No FDE algorithm has been selected ..."
#endif
#endif
                        status_reg.dmain_fifo_err = status_reg.dmain_dm_err =
                            status_reg.dmain_tr_err = false;
                        status_reg.dmaout_fifo_err = status_reg.dmaout_dm_err =
                            status_reg.dmaout_tr_err = false;
                        status_reg.dmaout_done = status_reg.dmain_done = false;
                        cryp_do_dma((const uint8_t *) usb_address,
                                    (const uint8_t *) sdio_address,
                                    scsi_block_size, dma_in_desc, dma_out_desc);
                        while (status_reg.dmaout_done == false) {
                            /* Do we have an error? If yes, try again the DMA transfer, if no continue to wait */
                            bool    dma_error = status_reg.dmaout_fifo_err ||
                                status_reg.dmaout_dm_err ||
                                status_reg.dmaout_tr_err;
                            if (dma_error == true) {
#if CRYPTO_DEBUG
                                printf
                                    ("CRYP DMA WR out error ... Trying again\n");
#endif
                                cryp_flush_fifos();
                                goto DMA_WR_XFR_AGAIN;
                            }
                            continue;
                        }
                        cryp_wait_for_emtpy_fifos();
                        usb_address += scsi_block_size;
                        sdio_address += scsi_block_size;
                    }
                    /****************************************************************************************/
#if CRYPTO_DEBUG
                    printf("[write] CRYP DMA has finished ! %d\n",
                           shms_tab[ID_USB].size);
#endif
                    // request DMA transfer to SDIO block device (IPC)


                    ret =
                        sys_ipc(IPC_SEND_SYNC, id_sdio,
                                sizeof(struct dataplane_command),
                                (const char *) &sdio_dataplane_command_rw);

                    if (ret != SYS_E_DONE) {
                        printf("%s: unable to send ipc from sdio! ret=%d\n",
                                __func__, ret);
                        goto err;
                    }
                    // wait for SDIO task acknowledge (IPC)
                    sinker = id_sdio;
                    ipcsize = sizeof(struct dataplane_command);

                    ret =
                        sys_ipc(IPC_RECV_SYNC, &sinker, &ipcsize,
                                (char *) &dataplane_command_ack);

                    if (ret != SYS_E_DONE) {
                        printf("%s: unable to receive ipc from sdio! ret=%d\n",
                                __func__, ret);
                        goto err;
                    }
#if CRYPTO_DEBUG
                    printf("[write] received ipc from sdio (%d)\n", sinker);
#endif
                    // set ack magic for write ack
                    dataplane_command_ack.magic = MAGIC_DATA_WR_DMA_ACK;
                    // acknowledge to USB: data has been written to disk (IPC)
                    ret =
                        sys_ipc(IPC_SEND_SYNC, id_usb,
                                sizeof(struct dataplane_command),
                                (const char *) &dataplane_command_ack);

                    if (ret != SYS_E_DONE) {
                        printf("%s: unable to send ipc back to usb! ret=%d\n",
                               __func__, ret);
                        goto err;
                    }

                    break;
                }


            case MAGIC_DATA_RD_DMA_REQ:
                {
                    /***************************************************
                     * Read mode automaton
                     **************************************************/
                    if (sinker != id_usb) {
                        printf
                            ("data rd DMA request command only allowed from USB app\n");
                        goto err;
                    }
                    dataplane_command_rw = ipc_mainloop_cmd.dataplane_cmd;

                    cryp_wait_for_emtpy_fifos();
                    // first ask SDIO to load data to its own buffer from the SDCard
                    struct dataplane_command sdio_dataplane_command_rw =
                        dataplane_command_rw;
                    uint32_t scsi_num_sectors =
                        dataplane_command_rw.num_sectors;
                    uint32_t scsi_sector_address =
                        dataplane_command_rw.sector_address;

                    uint64_t tmp = scsi_num_sectors;

                    tmp *= scsi_block_size;
                    tmp /= sdio_block_size;

                    if (tmp > 0xffffffff) {
                        printf
                            ("PANIC! scsi num sectors calculation generated overflow !!!\n");
                        goto err;
                    }
                    sdio_dataplane_command_rw.num_sectors = (uint32_t) tmp;

                    tmp = dataplane_command_rw.sector_address;
                    tmp *= scsi_block_size;
                    tmp /= sdio_block_size;
                    if (tmp > 0xffffffff) {
                        printf
                            ("PANIC! scsi sector adress calculation generated overflow !!!\n");
                        goto err;
                    }
                    sdio_dataplane_command_rw.sector_address = (uint32_t) tmp;

                    ret =
                        sys_ipc(IPC_SEND_SYNC, id_sdio,
                                sizeof(struct dataplane_command),
                                (const char *) &sdio_dataplane_command_rw);

                    if (ret != SYS_E_DONE) {
                        printf("%s: unable to send ipc to sdio! ret=%d\n",
                               __func__, ret);
                        goto err;
                    }
                    // wait for SDIO task acknowledge (IPC)
                    sinker = id_sdio;
                    ipcsize = sizeof(struct dataplane_command);

                    ret =
                        sys_ipc(IPC_RECV_SYNC, &sinker, &ipcsize,
                                (char *) &dataplane_command_ack);

                    if (ret != SYS_E_DONE) {
                        printf("%s: unable to receive ipc from sdio! ret=%d\n",
                               __func__, ret);
                        goto err;
                    }
#if CRYPTO_DEBUG
                    printf("[read] received ipc from sdio (%d): data loaded\n",
                           sinker);
#endif

#ifdef CONFIG_AES256_CBC_ESSIV
                    /* Prepare the Key (only for AES) */
                    if (cryp_get_dir() == ENCRYPT) {
                        /* When switching from ENCRYPT to DECRYPT, we only have to prepare the key!
                         * We only have to do the key preparation once when multiple decryptions are done.
                         */
#if CRYPTO_DEBUG
                        printf("[read] Preparing AES key\n");
#endif
                        cryp_set_mode(AES_KEY_PREPARE);
                    }
#endif

                    /********* DECRYPTION LOGIC ************************************************************/
                    /* We have to split our decryption in multiple subdecryptions to deal with IV modification on the crypto block size boundaries
                     * boundaries.
                     */
                    if ((scsi_block_size == 0) || (sdio_block_size == 0)) {
                        printf
                            ("Error: DMA DR request while the block sizes have not been read!\n");
                        goto err;
                    }
                    uint32_t num_cryp_blocks = scsi_num_sectors;
                    uint32_t usb_address = shms_tab[ID_USB].address;
                    uint32_t sdio_address = shms_tab[ID_SDIO].address;
                    unsigned int i;

                    /* [RB] FIXME: sanity checks on the USB and SDIO buffer sizes that must be compliant! */
                    for (i = 0; i < num_cryp_blocks; i++) {
#ifdef CONFIG_AES256_CBC_ESSIV
                        uint8_t curr_essiv_iv[16] = { 0 };
                        cbc_essiv_iv_derivation((scsi_sector_address + i), sd_serial, sizeof(sd_serial),
                                                curr_essiv_iv, 16);
 DMA_RD_XFR_AGAIN:
                        cryp_init_user(KEY_256, curr_essiv_iv, 16, AES_CBC,
                                       DECRYPT);
#else
#ifdef CONFIG_TDES_CBC_ESSIV
                        uint8_t curr_essiv_iv[8] = { 0 };
                        cbc_essiv_iv_derivation((scsi_sector_address + i), sd_serial, sizeof(sd_serial),
                                                curr_essiv_iv, 8);
 DMA_RD_XFR_AGAIN:
                        cryp_init_user(KEY_192, curr_essiv_iv, 8, TDES_CBC,
                                       DECRYPT);
#else
#error "No FDE algorithm has been selected ..."
#endif
#endif
                        status_reg.dmain_fifo_err = status_reg.dmain_dm_err =
                            status_reg.dmain_tr_err = false;
                        status_reg.dmaout_fifo_err = status_reg.dmaout_dm_err =
                            status_reg.dmaout_tr_err = false;
                        status_reg.dmaout_done = status_reg.dmain_done = false;
                        cryp_do_dma((const uint8_t *) sdio_address,
                                    (const uint8_t *) usb_address,
                                    scsi_block_size, dma_in_desc, dma_out_desc);
                        while (status_reg.dmaout_done == false) {
                            bool    dma_error = status_reg.dmaout_fifo_err ||
                                status_reg.dmaout_dm_err ||
                                status_reg.dmaout_tr_err;
                            if (dma_error == true) {
#if CRYPTO_DEBUG
                                printf
                                    ("CRYP DMA RD out error ... Trying again\n");
#endif
                                cryp_flush_fifos();
                                goto DMA_RD_XFR_AGAIN;
                            }
                            continue;
                        }
                        cryp_wait_for_emtpy_fifos();
                        usb_address += scsi_block_size;
                        sdio_address += scsi_block_size;
                    }
                    /****************************************************************************************/


#if CRYPTO_DEBUG
                    printf("[read] CRYP DMA has finished !\n");
#endif
                    // set ack magic for read ack
                    dataplane_command_ack.magic = MAGIC_DATA_RD_DMA_ACK;

                    // acknowledge to USB: data has been written to disk (IPC)
                    ret =
                        sys_ipc(IPC_SEND_SYNC, id_usb,
                                sizeof(struct dataplane_command),
                                (const char *) &dataplane_command_ack);

                    if (ret != SYS_E_DONE) {
                        printf("%s: unable to send ipc to usb! ret=%d\n",
                               __func__, ret);
                        goto err;
                    }
                    break;

                }


            case MAGIC_STORAGE_EJECTED:
                {
                    /***************************************************
                     * SDIO mass-storage device ejected
                     **************************************************/
                    if (sinker != id_sdio) {
                        printf
                            ("ejected storage event command only allowed from SDIO app\n");
                        continue;
                    }
                    ret = sys_ipc(IPC_SEND_SYNC, id_smart, sizeof(t_ipc_command),
                            (const char *) &ipc_mainloop_cmd);
                    if(ret != SYS_E_DONE) {
                       goto err;
                    }

                    break;
                }

                /* Reboot request */
            case MAGIC_REBOOT_REQUEST:
                {
                    /* anyone can requst reboot event on error */
                    ret =
                        sys_ipc(IPC_SEND_SYNC, id_smart,
                                sizeof(t_ipc_command),
                                (const char *) &ipc_mainloop_cmd);
                    if(ret != SYS_E_DONE) {
                        goto err;
                    }
                    break;
                }


            default:
                {
                    /***************************************************
                     * Invalid request. Returning invalid to sender
                     **************************************************/
                    if(sinker == id_usb) {
                        printf("invalid request from USB %x!\n",ipc_mainloop_cmd.magic);
          	    }
                    if(sinker == id_sdio) {
                       printf("invalid request from SDIO %x!\n",ipc_mainloop_cmd.magic);
                    }
                    // returning INVALID magic to USB
                    ipc_mainloop_cmd.magic = MAGIC_INVALID;

                    // acknowledge to USB: data has been written to disk (IPC)
                    ret = sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(t_ipc_command),
                            (const char *) &ipc_mainloop_cmd);
                    if(ret != SYS_E_DONE) {
                       goto err;
                    }

                    break;

                }
        }


    }

err_init:
    while (1) {
        sys_yield();
    }
err:
    /* to be replaced by reset request IPC */
    ask_reboot();
    while (1) {
        sys_yield();
    }

}
