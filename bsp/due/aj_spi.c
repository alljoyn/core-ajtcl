/**
 * @file SPI functionality
 */
/******************************************************************************
 * Copyright (c) 2014, AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

/******************************************************************************
 * Any time in this file there is a comment including:
    ioport_***, pio_***, pmc_***, spi_***, sysclk_***

 * note that the API associated with it may be subject to this Atmel license:
 * (information about it is also at www.atmel.com/asf)
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel microcontroller product.
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN
 * NO EVENT SHALL ATMEL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "aj_target.h"
#include "aj_wsl_target.h"
#include "aj_status.h"
#include "aj_wsl_spi.h"
#include "aj_wsl_htc.h"
#include "aj_buf.h"
#include "aj_wsl_tasks.h"



void AJ_WSL_SPI_CHIP_SPI_ISR(uint32_t id, uint32_t mask);

/*
 * Configure the SPI hardware, including SPI clock speed, mode, delays, chip select pins
 * It uses values listed in
 */
void AJ_WSL_SPI_InitializeSPIController(void)
{
    /*
     * Configure the hardware to enable SPI and some output pins
     */
    {
        pmc_enable_periph_clk(ID_PIOA);
        pmc_enable_periph_clk(ID_PIOB);
        pmc_enable_periph_clk(ID_PIOC);
        pmc_enable_periph_clk(ID_PIOD);


        // make all of these pins controlled by the right I/O controller
        pio_configure_pin_group(PIOA, 0xFFFFFFFF, PIO_TYPE_PIO_PERIPH_A);
        pio_configure_pin_group(PIOB, 0xFFFFFFFF, PIO_TYPE_PIO_PERIPH_B);
        pio_configure_pin_group(PIOC, 0xFFFFFFFF, PIO_TYPE_PIO_PERIPH_C);
        pio_configure_pin_group(PIOD, 0xFFFFFFFF, PIO_TYPE_PIO_PERIPH_D);


        /*
         * Reset the device by toggling the CHIP_POWER
         */
        ioport_set_pin_dir(AJ_WSL_SPI_CHIP_POWER_PIN, IOPORT_DIR_OUTPUT);
        ioport_set_pin_level(AJ_WSL_SPI_CHIP_POWER_PIN, IOPORT_PIN_LEVEL_LOW);
        AJ_Sleep(10);
        ioport_set_pin_level(AJ_WSL_SPI_CHIP_POWER_PIN, IOPORT_PIN_LEVEL_HIGH);


        /*
         * Reset the device by toggling the CHIP_PWD# signal
         */
        ioport_set_pin_dir(AJ_WSL_SPI_CHIP_PWD_PIN, IOPORT_DIR_OUTPUT);
        ioport_set_pin_level(AJ_WSL_SPI_CHIP_PWD_PIN, IOPORT_PIN_LEVEL_LOW);
        AJ_Sleep(10);
        ioport_set_pin_level(AJ_WSL_SPI_CHIP_PWD_PIN, IOPORT_PIN_LEVEL_HIGH);

        /* configure the pin that detects SPI data ready from the target chip */
        ioport_set_pin_dir(AJ_WSL_SPI_CHIP_SPI_INT_PIN, IOPORT_DIR_INPUT);
        ioport_set_pin_sense_mode(AJ_WSL_SPI_CHIP_SPI_INT_PIN, IOPORT_SENSE_LEVEL_LOW);

        pio_handler_set(PIOC, ID_PIOC, AJ_WSL_SPI_CHIP_SPI_INT_BIT, (PIO_PULLUP | PIO_IT_FALL_EDGE), &AJ_WSL_SPI_CHIP_SPI_ISR);
        pio_handler_set_priority(PIOD, (IRQn_Type) ID_PIOC, 0xB);
        pio_enable_interrupt(PIOC, AJ_WSL_SPI_CHIP_SPI_INT_BIT);
    }

    spi_enable_clock(AJ_WSL_SPI_DEVICE);
    spi_reset(AJ_WSL_SPI_DEVICE);
    spi_set_lastxfer(AJ_WSL_SPI_DEVICE);
    spi_set_master_mode(AJ_WSL_SPI_DEVICE);
    spi_disable_mode_fault_detect(AJ_WSL_SPI_DEVICE);
    spi_set_peripheral_chip_select_value(AJ_WSL_SPI_DEVICE, AJ_WSL_SPI_DEVICE_NPCS);
    spi_set_clock_polarity(AJ_WSL_SPI_DEVICE, AJ_WSL_SPI_DEVICE_NPCS, AJ_WSL_SPI_CLOCK_POLARITY);
    spi_set_clock_phase(AJ_WSL_SPI_DEVICE, AJ_WSL_SPI_DEVICE_NPCS, AJ_WSL_SPI_CLOCK_PHASE);
    spi_set_bits_per_transfer(AJ_WSL_SPI_DEVICE, AJ_WSL_SPI_DEVICE_NPCS, SPI_CSR_BITS_8_BIT);
    spi_set_baudrate_div(AJ_WSL_SPI_DEVICE, AJ_WSL_SPI_DEVICE_NPCS, (sysclk_get_cpu_hz() / AJ_WSL_SPI_CLOCK_RATE));
    spi_set_transfer_delay(AJ_WSL_SPI_DEVICE, AJ_WSL_SPI_DEVICE_NPCS, AJ_WSL_SPI_DELAY_BEFORE_CLOCK, AJ_WSL_SPI_DELAY_BETWEEN_TRANSFERS);
    spi_set_fixed_peripheral_select(AJ_WSL_SPI_DEVICE);
    spi_configure_cs_behavior(AJ_WSL_SPI_DEVICE, AJ_WSL_SPI_DEVICE_NPCS, SPI_CS_RISE_FORCED);

    spi_enable_interrupt(AJ_WSL_SPI_DEVICE, SPI_IER_TDRE | SPI_IER_RDRF);
    spi_enable(AJ_WSL_SPI_DEVICE);
}

void AJ_WSL_SPI_ShutdownSPIController(void)
{
    spi_disable(AJ_WSL_SPI_DEVICE);
    spi_disable_interrupt(AJ_WSL_SPI_DEVICE, 0xFFFFFFFF);
}

aj_spi_status AJ_SPI_READ(Spi* p_spi, uint8_t* us_data, uint8_t* p_pcs)
{
    aj_spi_status status;
    uint16_t data;
    status = spi_read(p_spi, &data, p_pcs);
    AJ_ASSERT(status == SPI_OK);
    *us_data = data & 0xFF;
    //    AJ_InfoPrintf(("=R= %02x\n", (*us_data) & 0xFF));
    return status;
}

aj_spi_status AJ_SPI_WRITE(Spi* p_spi, uint16_t us_data, uint8_t uc_pcs, uint8_t uc_last)
{
    aj_spi_status status;
//    AJ_InfoPrintf(("=WRITE= %x\n", us_data));
    status = spi_write(p_spi, us_data, uc_pcs, uc_last);
    AJ_ASSERT(status == SPI_OK);
    return status;
}

/*
 *  These routines are specific to the hardware target, so they should exist in an  aj_target_wsl_spi.c
 */


/** TX interrupt occurred */
volatile uint8_t g_b_spi_interrupt_tx_ready = false;
/** RX interrupt occurred */
volatile uint8_t g_b_spi_interrupt_rx_ready = false;

/**
 * SPI interrupt service routine
 */
void AJ_WSL_SPI_ISR(void)
{
    uint32_t status = spi_read_status(AJ_WSL_SPI_DEVICE);

    if (status & SPI_SR_TDRE) {
        //g_b_spi_interrupt_tx_ready = true;
        spi_disable_interrupt(AJ_WSL_SPI_DEVICE, SPI_IDR_TDRE);
    }

    if (status & SPI_SR_RDRF) {
        //g_b_spi_interrupt_rx_ready = true;
        spi_disable_interrupt(AJ_WSL_SPI_DEVICE, SPI_IDR_RDRF);
    }
}

volatile uint8_t g_b_spi_interrupt_data_ready = false;

/**
 * ISR that handles the target chip asserting a data ready signal.
 */
void AJ_WSL_SPI_CHIP_SPI_ISR(uint32_t id, uint32_t mask)
{
    if (ID_PIOC != id || AJ_WSL_SPI_CHIP_SPI_INT_BIT != mask) {
        return;
    }
    pio_disable_interrupt(PIOC, AJ_WSL_SPI_CHIP_SPI_INT_BIT);
    if (mask & AJ_WSL_SPI_CHIP_SPI_INT_BIT) {
        g_b_spi_interrupt_data_ready = TRUE;
        AJ_ResumeTask(AJ_WSL_MBoxListenHandle, TRUE);
    }
    pio_enable_interrupt(PIOC, AJ_WSL_SPI_CHIP_SPI_INT_BIT);
}


