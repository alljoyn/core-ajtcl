/**
 * @file
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

/* Indicated portions of this file are subject to the copyright rights and
 * license from Nordic Semiconductor ASA set forth just below:
 *
 * Copyright (c) 2014, Nordic Semiconductor ASA
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "aj_target.h"
#include "aj_status.h"
#include "aj_serial.h"
#include "aj_serial_rx.h"
#include "aj_serial_tx.h"

#include "aj_serio.h"
#include "aj_debug.h"

#ifdef AJ_SERIAL_CONNECTION

#include <SPI.h>

/* Nordic Semiconductor ASA headers */
#include "../BLE/lib_aci.h"
#include "../BLE/aci_setup.h"

#include "uart_over_ble.h"
#include "btle_services.h"

#ifdef AJ_DEBUG_SERIAL_TARGET
#define AJ_DebugDumpSerialRX(a, b, c) AJ_DumpBytes(a, b, c)
#define AJ_DebugDumpSerialTX(a, b, c) AJ_DumpBytes(a, b, c)
#else
#define AJ_DebugDumpSerialRX(a, b, c)
#define AJ_DebugDumpSerialTX(a, b, c)
#endif

#define FRAME_DELIMITER 0xC0

static void aci_loop(void);

/* Start Nordic Semiconductor ASA UART emulation variables */
static services_pipe_type_mapping_t
    services_pipe_type_mapping[NUMBER_OF_PIPES] = SERVICES_PIPE_TYPE_MAPPING_CONTENT;

/* Store the setup for the nRF8001 in the flash of the Arduino to save on RAM */
static hal_aci_data_t setup_msgs[NB_SETUP_MESSAGES] PROGMEM = SETUP_MESSAGES_CONTENT;

static struct aci_state_t aci_state;
static hal_aci_evt_t aci_data;
static bool timing_change_done          = false;
static uart_over_ble_t uart_over_ble;
/* End Nordic Semiconductor ASA UART emulation variables */

static AJ_SerIORxCompleteFunc RecvCB;
static AJ_SerIOTxCompleteFunc SendCB;

/**
 * global function pointer for serial transmit funciton
 */
AJ_SerialTxFunc g_AJ_TX;

static struct {
    uint8_t* data;
    uint32_t len;
    uint8_t* pos;
} tx_buf = { NULL, 0, NULL }, rx_buf = { NULL, 0, NULL };

/* Start Nordic Semiconductor ASA UART emulation utilities */
static void uart_over_ble_init(void)
{
    AJ_Printf("uart_over_ble_init\n");
    uart_over_ble.uart_rts_local = true;
}

static bool uart_process_control_point_rx(uint8_t*byte, uint8_t length)
{
    bool status = false;
    aci_ll_conn_params_t*conn_params;

    if (lib_aci_is_pipe_available(&aci_state, PIPE_UART_OVER_BTLE_UART_CONTROL_POINT_TX)) {

        AJ_Printf("CTL: %x\n", *byte);
        switch (*byte) {
        /*
           Queues a ACI Disconnect to the nRF8001 when this packet is received.
           May cause some of the UART packets being sent to be dropped
         */
        case UART_OVER_BLE_DISCONNECT:
            /*
               Parameters:
               None
             */
            lib_aci_disconnect(&aci_state, ACI_REASON_TERMINATE);
            status = true;
            break;

        /*
           Queues an ACI Change Timing to the nRF8001
         */
        case UART_OVER_BLE_LINK_TIMING_REQ:
            /*
               Parameters:
               Connection interval min: 2 bytes
               Connection interval max: 2 bytes
               Slave latency:           2 bytes
               Timeout:                 2 bytes
               Same format as Peripheral Preferred Connection Parameters (See nRFgo studio -> nRF8001 Configuration -> GAP Settings
               Refer to the ACI Change Timing Request in the nRF8001 Product Specifications
             */
            conn_params = (aci_ll_conn_params_t*)(byte + 1);
            lib_aci_change_timing(conn_params->min_conn_interval,
                                  conn_params->max_conn_interval,
                                  conn_params->slave_latency,
                                  conn_params->timeout_mult);
            status = true;
            break;

        /*
           Clears the RTS of the UART over BLE
         */
        case UART_OVER_BLE_TRANSMIT_STOP:
            /*
               Parameters:
               None
             */
            uart_over_ble.uart_rts_local = false;
            status = true;
            break;

        /*
           Set the RTS of the UART over BLE
         */
        case UART_OVER_BLE_TRANSMIT_OK:
            /*
               Parameters:
               None
             */
            uart_over_ble.uart_rts_local = true;
            status = true;
            break;
        }
    }
    return status;
}
/* End Nordic Semiconductor ASA UART emulation utilities */

/**
 * Interrupt handler for data arriving on the UART
 */
static void readBytesFromUart(uint8_t* data, uint32_t len)
{
    static uint8_t ReadingMsg = FALSE;

    // if there is data ready,
    AJ_Printf("readBytesFromUart: %d\n", len);
    AJ_ASSERT(rx_buf.data != NULL);
    while (len) {
        if (rx_buf.pos >= rx_buf.data + rx_buf.len) {
            // throw data away until we see a new frame
            if (*data == FRAME_DELIMITER) {
                ReadingMsg = FALSE;
                rx_buf.pos = rx_buf.data;
            }
            data++;
            len--;
            continue;
        }

        *(rx_buf.pos++) = *data;

        if (*data == FRAME_DELIMITER) {
            if (ReadingMsg == TRUE) {
                uint8_t*buf = rx_buf.data;
                uint32_t cnt = rx_buf.pos - rx_buf.data;
                rx_buf.pos = rx_buf.data = NULL;
                rx_buf.len = 0;
                ReadingMsg = FALSE;
                RecvCB(buf, cnt);
            } else {
                ReadingMsg = TRUE;
            }
        }
        data++;
        len--;
    }
}

/* This function sets up a buffer for us to fill with RX data */
void AJ_RX(uint8_t* buf, uint32_t len)
{
    //AJ_Printf("AJ_RX: %d\n", len);
    AJ_ASSERT(buf != NULL);
    rx_buf.data = buf;
    rx_buf.pos = buf;
    rx_buf.len = len;
}

void AJ_PauseRX()
{
    // Disable RX IRQ
}

void AJ_ResumeRX()
{
    // Enable RX IRQ
}

static void runTx()
{
    uint32_t len = tx_buf.len - (tx_buf.pos - tx_buf.data);

    if (len) {
        AJ_Printf("runTx: (%d) %d\n", len, aci_state.data_credit_available);
    }

    if (!tx_buf.data || !tx_buf.pos || !tx_buf.len || !len || !aci_state.data_credit_available) {
        return;
    }

    while (lib_aci_is_pipe_available(&aci_state, PIPE_UART_OVER_BTLE_UART_TX_TX) &&
           len && (aci_state.data_credit_available >= 1)) {
        uint32_t send_len = len > ACI_PIPE_TX_DATA_MAX_LEN ? ACI_PIPE_TX_DATA_MAX_LEN : len;
        int status;

        status = lib_aci_send_data(PIPE_UART_OVER_BTLE_UART_TX_TX, tx_buf.pos, send_len);
        if (status) {
            aci_state.data_credit_available--;
            tx_buf.pos += send_len;
            len -= send_len;
        } else {
            break;
        }
    }
    AJ_Printf("Tx (credits: %d)\n", aci_state.data_credit_available);
}

/* This function is requesting us to send data over our UART */
void __AJ_TX(uint8_t* buf, uint32_t len)
{
    //AJ_Printf("__AJ_TX: %d\n", len);
    tx_buf.data = buf;
    tx_buf.pos = buf;
    tx_buf.len = len;

    runTx();
}

void AJ_TX(uint8_t* buf, uint32_t len)
{
    //AJ_Printf("AJ_TX: %d\n", len);
    g_AJ_TX(buf, len); // should call the inner implementation
}

void AJ_PauseTX()
{
    // Disable TX IRQ
}

void AJ_ResumeTX()
{
    // Enable TX IRQ
}


#define AJ_SERIAL_WINDOW_SIZE   2
#define AJ_SERIAL_PACKET_SIZE   512 + AJ_SERIAL_HDR_LEN


AJ_Status AJ_Serial_Up()
{
    AJ_Status status;

    AJ_Printf("AJ_Serial_Up\n");
    status =  AJ_SerialIOInit(NULL);
    if (status == AJ_OK) {
        return AJ_SerialInit(NULL, 15000, AJ_SERIAL_WINDOW_SIZE, AJ_SERIAL_PACKET_SIZE);
    }
    return status;
}


/**
 * This function initialized the UART piece of the transport.
 */
AJ_Status AJ_SerialTargetInit(const char* ttyName, uint16_t bitRate)
{
    AJ_Printf("AJ_SerialTargetInit %s\n", ttyName);

    return AJ_OK;
}


AJ_Status AJ_SerialIOEnable(uint32_t direction, uint8_t enable)
{
    AJ_Printf("AJ_SerialIOEnable -->%d: %d\n", direction, enable);
    //AJ_Status status = AJ_ERR_DISALLOWED;
    AJ_Status status = AJ_OK;

    if (direction == AJ_SERIO_RX) {
        if (enable) {
        } else {
        }
    } else if (direction == AJ_SERIO_TX) {
        if (enable) {
        } else {
        }
    }

    return status;
}

void AJ_SetRxCB(AJ_SerIORxCompleteFunc rx_cb)
{
    AJ_Printf("AJ_SetRxCB\n");
    RecvCB = rx_cb;
}

void AJ_SetTxCB(AJ_SerIOTxCompleteFunc tx_cb)
{
    AJ_Printf("AJ_SetTxCB\n");
    SendCB = tx_cb;
}

void AJ_SetTxSerialTransmit(AJ_SerialTxFunc tx_func)
{
    AJ_Printf("AJ_SetTxSerialTransmit\n");
    g_AJ_TX = tx_func;
}


AJ_Status AJ_SerialIOInit(AJ_SerIOConfig* config)
{
    AJ_Printf("BTLE setup\n");

    /* Start Nordic Semiconductor ASA BTLE Shield Initialization */
    /**
       Point ACI data structures to the the setup data that the nRFgo studio generated for the nRF8001
     */
    aci_state.aci_setup_info.services_pipe_type_mapping = &services_pipe_type_mapping[0];
    aci_state.aci_setup_info.number_of_pipes    = NUMBER_OF_PIPES;
    aci_state.aci_setup_info.setup_msgs         = setup_msgs;
    aci_state.aci_setup_info.num_setup_msgs     = NB_SETUP_MESSAGES;

    /*
       Tell the ACI library, the MCU to nRF8001 pin connections.
       The Active pin is optional and can be marked UNUSED
     */
    aci_state.aci_pins.board_name = BOARD_DEFAULT; //See board.h for details REDBEARLAB_SHIELD_V1_1 or BOARD_DEFAULT
    aci_state.aci_pins.reqn_pin   = 9; //SS for Nordic board, 9 for REDBEARLAB_SHIELD_V1_1
    aci_state.aci_pins.rdyn_pin   = 8; //3 for Nordic board, 8 for REDBEARLAB_SHIELD_V1_1
    aci_state.aci_pins.mosi_pin   = MOSI;
    aci_state.aci_pins.miso_pin   = MISO;
    aci_state.aci_pins.sck_pin    = SCK;

    aci_state.aci_pins.spi_clock_divider      = 42; // Divide SPI clock down to 2MHz
    aci_state.aci_pins.reset_pin              = 4; //4 for Nordic board, UNUSED for REDBEARLAB_SHIELD_V1_1
    aci_state.aci_pins.active_pin             = UNUSED;
    aci_state.aci_pins.optional_chip_sel_pin  = 10;

    aci_state.aci_pins.interface_is_interrupt = false; //Interrupts still not available in Chipkit
    aci_state.aci_pins.interrupt_number       = 1;

    lib_aci_init(&aci_state, false);
    /* End Nordic Semiconductor ASA BTLE Shield Initialization */

    AJ_SetSioCheck(aci_loop);

    return AJ_OK;
}

AJ_Status AJ_SerialIOShutdown(void)
{
    AJ_Printf("AJ_SerialIOShutdown\n");
    return AJ_OK;
}

/* Define how assert should function in the BLE library */
void __ble_assert(const char*file, uint16_t line)
{
    AJ_Printf("BLE ERROR %s: %d\n", file, line);
    AJ_ASSERT(0);
}

/* Start Nordic Semiconductor ASA Arduino processing loop */
/* Must be called periodically to service Arduino BLE shield */
static void aci_loop()
{
    static bool setup_required = false;

    // We enter the if statement only when there is a ACI event available to be processed
    if (lib_aci_event_get(&aci_state, &aci_data)) {
        aci_evt_t* aci_evt;
        aci_evt = &aci_data.evt;

        switch (aci_evt->evt_opcode) {
        /**
           As soon as you reset the nRF8001 you will get an ACI Device Started Event
         */
        case ACI_EVT_DEVICE_STARTED:
            {
                aci_state.data_credit_total = aci_evt->params.device_started.credit_available;
                switch (aci_evt->params.device_started.device_mode) {
                case ACI_DEVICE_SETUP:
                    /**
                       When the device is in the setup mode
                     */
                    AJ_Printf("Evt Device Started: Setup\n");
                    setup_required = true;
                    break;

                case ACI_DEVICE_STANDBY:
                    AJ_Printf("Evt Device Started: Standby\n");
                    //Looking for an BLE Central by sending radio advertisements
                    //When an BLE Central connects to us we will get an ACI_EVT_CONNECTED event from the nRF8001
                    if (aci_evt->params.device_started.hw_error) {
                        delay(20); //Magic number used to make sure the HW error event is handled correctly.
                    } else {
                        lib_aci_connect(180 /* in seconds */, 0x0050 /* advertising interval 50ms*/);
                        AJ_Printf("Advertising started\n");
                    }
                    break;
                }
            }
            break; //ACI Device Started Event

        case ACI_EVT_CMD_RSP:
            //If an ACI command response event comes with an error -> stop
            if (ACI_STATUS_SUCCESS != aci_evt->params.cmd_rsp.cmd_status) {
                //ACI ReadDynamicData and ACI WriteDynamicData will have status codes of
                //TRANSACTION_CONTINUE and TRANSACTION_COMPLETE
                //all other ACI commands will have status code of ACI_STATUS_SCUCCESS for a successful command
                AJ_Printf("ACI Command %x\n", aci_evt->params.cmd_rsp.cmd_opcode);
                AJ_Printf("Evt Cmd respone: Status %x\n", aci_evt->params.cmd_rsp.cmd_status);
            }
            if (ACI_CMD_GET_DEVICE_VERSION == aci_evt->params.cmd_rsp.cmd_opcode) {
                //Store the version and configuration information of the nRF8001 in the Hardware Revision String Characteristic
                lib_aci_set_local_data(&aci_state, PIPE_DEVICE_INFORMATION_HARDWARE_REVISION_STRING_SET,
                                       (uint8_t*)&(aci_evt->params.cmd_rsp.params.get_device_version),
                                       sizeof(aci_evt_cmd_rsp_params_get_device_version_t));
            }
            break;

        case ACI_EVT_CONNECTED:
            AJ_Printf("Evt Connected (credits: %d)\n", aci_state.data_credit_total);
            uart_over_ble_init();
            timing_change_done              = false;
            aci_state.data_credit_available = aci_state.data_credit_total;

            /*
               Get the device version of the nRF8001 and store it in the Hardware Revision String
             */
            lib_aci_device_version();
            runTx();
            break;

        case ACI_EVT_PIPE_STATUS:
            AJ_Printf("Evt Pipe Status\n");
            if (lib_aci_is_pipe_available(&aci_state, PIPE_UART_OVER_BTLE_UART_TX_TX) && (false == timing_change_done)) {
                lib_aci_change_timing_GAP_PPCP(); // change the timing on the link as specified in the nRFgo studio -> nRF8001 conf. -> GAP.
                                                  // Used to increase or decrease bandwidth
                timing_change_done = true;
            }
            runTx();
            break;

        case ACI_EVT_TIMING:
            AJ_Printf("Evt link connection interval changed\n");
            lib_aci_set_local_data(&aci_state,
                                   PIPE_UART_OVER_BTLE_UART_LINK_TIMING_CURRENT_SET,
                                   (uint8_t*)&(aci_evt->params.timing.conn_rf_interval), /* Byte aligned */
                                   PIPE_UART_OVER_BTLE_UART_LINK_TIMING_CURRENT_SET_MAX_SIZE);
            break;

        case ACI_EVT_DISCONNECTED:
            AJ_Printf("Evt Disconnected/Advertising timed out\n");
            lib_aci_connect(180 /* in seconds */, 0x0100 /* advertising interval 100ms*/);
            AJ_Printf("Advertising started\n");
            break;

        case ACI_EVT_DATA_RECEIVED:
            AJ_Printf("Rx Pipe Number: %d\n", aci_evt->params.data_received.rx_data.pipe_number);
            if (PIPE_UART_OVER_BTLE_UART_RX_RX == aci_evt->params.data_received.rx_data.pipe_number) {
                readBytesFromUart(aci_evt->params.data_received.rx_data.aci_data, aci_evt->len - 2);
            }
            if (PIPE_UART_OVER_BTLE_UART_CONTROL_POINT_RX == aci_evt->params.data_received.rx_data.pipe_number) {
                //Subtract for Opcode and Pipe number
                uart_process_control_point_rx(&aci_evt->params.data_received.rx_data.aci_data[0], aci_evt->len - 2);
            }
            break;

        case ACI_EVT_DATA_CREDIT:
            aci_state.data_credit_available = aci_state.data_credit_available + aci_evt->params.data_credit.credit;
            AJ_Printf("Evt Data Credit (credits: %d)\n", aci_state.data_credit_available);

            runTx();

            if (tx_buf.data && (tx_buf.pos >= tx_buf.data + tx_buf.len)) {
                uint8_t* buf = tx_buf.data;
                uint32_t len = tx_buf.pos - tx_buf.data;

                /* Reset Tx data structure */
                tx_buf.data = tx_buf.pos = NULL;
                tx_buf.len = 0;

                /* Acknowledge Send completion to upper layer */
                SendCB(buf, len);
            }
            break;

        case ACI_EVT_PIPE_ERROR:
            //See the appendix in the nRF8001 Product Specication for details on the error codes
            AJ_Printf("ACI Evt Pipe Error: Pipe #: %d\n", aci_evt->params.pipe_error.pipe_number);
            AJ_Printf("  Pipe Error Code: 0x%x\n", aci_evt->params.pipe_error.error_code);

            //Increment the credit available as the data packet was not sent.
            //The pipe error also represents the Attribute protocol Error Response sent from the peer and that should not be counted
            //for the credit.
            if (ACI_STATUS_ERROR_PEER_ATT_ERROR != aci_evt->params.pipe_error.error_code) {
                aci_state.data_credit_available++;
                runTx();
            }
            break;

        case ACI_EVT_HW_ERROR:
            {
                uint8_t filename[21];
                uint8_t counter = 0;

                if (sizeof(filename) > (aci_evt->len - 3)) {
                    while (counter <= (aci_evt->len - 3)) {
                        filename[counter] = aci_evt->params.hw_error.file_name[counter];
                        counter++;
                    }
                }
                filename[counter] = '\0';
                AJ_Printf("HW error:%s @ line %d\n", filename, aci_evt->params.hw_error.line_num);
                lib_aci_connect(180 /* in seconds */, 0x0050 /* advertising interval 50ms*/);
                AJ_Printf("Advertising started\n");
            }
            break;

        }
    }

    /* setup_required is set to true when the device starts up and enters setup mode.
     * It indicates that do_aci_setup() should be called. The flag should be cleared if
     * do_aci_setup() returns ACI_STATUS_TRANSACTION_COMPLETE.
     */
    if (setup_required) {
        if (SETUP_SUCCESS == do_aci_setup(&aci_state)) {
            setup_required = false;
        }
    }
}
/* End Nordic Semiconductor ASA Arduino processing loop */

#endif
