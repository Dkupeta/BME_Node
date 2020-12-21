/*
 * lorawan.h
 *
 *  Created on: Dec 21, 2020
 *      Author: dkupe
 */

/*
 * LoRaWAN.h - Library header file for LoRaWAN protocol,
 * uses RFM95W module.
*/

#ifndef INC_LORAWAN_H_
#define INC_LORAWAN_H_


#include "rfm95.h"

typedef struct lorawan
{
  rfm95_t *rfm95;
  uint8_t *NwkSkey;
  uint8_t *AppSkey;
  uint8_t *DevAddr;
} lorawan_t;

void lorawan_init(lorawan_t *lorawan, rfm95_t *rfm95);
void lorawan_set_keys(lorawan_t *lorawan, uint8_t NwkSkey[], uint8_t AppSkey[], uint8_t DevAddr[]);
uint32_t lorawan_send_data(lorawan_t *lorawan, uint8_t *data, unsigned len, uint16_t frame_counter_up); // returns freqency



#endif /* INC_LORAWAN_H_ */
