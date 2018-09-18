#include "libdma.h"
#include "libdma_regs.h"
#include "api/print.h"
#include "main.h"

extern uint32_t num_dma_in_it;
extern uint32_t num_dma_out_it;
extern status_reg_t status_reg;

void my_cryptin_handler(uint8_t irq, uint32_t status)
{
    num_dma_in_it++;
    irq = irq;

#if 0
    if (get_reg_value(&status, DMA_HISR_FEIFx_Msk(DMA2_STREAM_CRYP_IN),
                      DMA_HISR_FEIFx_Pos(DMA2_STREAM_CRYP_IN))) {
        status_reg.dmain_fifo_err = true;
    }
#endif
    if (get_reg_value(&status, DMA_HISR_DMEIFx_Msk(DMA2_STREAM_CRYP_IN),
                      DMA_HISR_DMEIFx_Pos(DMA2_STREAM_CRYP_IN))) {
        status_reg.dmain_dm_err = true;
    }
    if (get_reg_value(&status, DMA_HISR_TEIFx_Msk(DMA2_STREAM_CRYP_IN),
                      DMA_HISR_TEIFx_Pos(DMA2_STREAM_CRYP_IN))) {
        status_reg.dmain_tr_err = true;
    }
    if (get_reg_value(&status, DMA_HISR_HTIFx_Msk(DMA2_STREAM_CRYP_IN),
                      DMA_HISR_HTIFx_Pos(DMA2_STREAM_CRYP_IN))) {
        status_reg.dmain_hdone = true;
    }
    if (get_reg_value(&status, DMA_HISR_TCIFx_Msk(DMA2_STREAM_CRYP_IN),
                      DMA_HISR_TCIFx_Pos(DMA2_STREAM_CRYP_IN))) {
        status_reg.dmain_done = true;
    }
}

void my_cryptout_handler(uint8_t irq, uint32_t status)
{
    irq = irq;
    num_dma_out_it++;
#if 0
    if (get_reg_value(&status, DMA_HISR_FEIFx_Msk(DMA2_STREAM_CRYP_OUT),
                      DMA_HISR_FEIFx_Pos(DMA2_STREAM_CRYP_OUT))) {
        status_reg.dmain_fifo_err = true;
    }
#endif
    if (get_reg_value(&status, DMA_HISR_DMEIFx_Msk(DMA2_STREAM_CRYP_OUT),
                      DMA_HISR_DMEIFx_Pos(DMA2_STREAM_CRYP_OUT))) {
        status_reg.dmaout_dm_err = true;
    }
    if (get_reg_value(&status, DMA_HISR_TEIFx_Msk(DMA2_STREAM_CRYP_OUT),
                      DMA_HISR_TEIFx_Pos(DMA2_STREAM_CRYP_OUT))) {
        status_reg.dmaout_tr_err = true;
    }
    if (get_reg_value(&status, DMA_HISR_HTIFx_Msk(DMA2_STREAM_CRYP_OUT),
                      DMA_HISR_HTIFx_Pos(DMA2_STREAM_CRYP_OUT))) {
        status_reg.dmaout_hdone = true;
    }
    if (get_reg_value(&status, DMA_HISR_TCIFx_Msk(DMA2_STREAM_CRYP_OUT),
                      DMA_HISR_TCIFx_Pos(DMA2_STREAM_CRYP_OUT))) {
        status_reg.dmaout_done = true;
    }
}
