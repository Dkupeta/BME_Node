/*
 * rfm95.h
 *
 *  Created on: Dec 21, 2020
 *      Author: dkupe
 */

#ifndef INC_RFM95_H_
#define INC_RFM95_H_


// this generated file includes all necessary stm32 device headers
#include "main.h"

typedef int8_t (*rfm95_com_fptr_t)(uint8_t nss_pin_id, uint8_t reg_addr, uint8_t *data, uint16_t len);
typedef uint8_t (*rfm95_pin_fptr_t)(uint8_t pin_id);
typedef void (*rfm95_delay_fptr_t)(uint32_t ms);

typedef struct rfm95
{
  uint8_t dio0_pin_id;
  uint8_t dio5_pin_id;
  uint8_t nss_pin_id;
  rfm95_com_fptr_t spi_write;
  rfm95_com_fptr_t spi_read;
  rfm95_pin_fptr_t pin_read;
  rfm95_delay_fptr_t delay;
} rfm95_t;

uint8_t rfm95_init(rfm95_t *dev, uint32_t seed);
uint32_t rfm95_send(rfm95_t *dev, uint8_t *buffer, uint32_t len);

uint8_t rfm95_write(rfm95_t *dev, uint8_t addr, uint8_t data); // returns old register value
uint8_t rfm95_read(rfm95_t *dev, uint8_t addr);


#endif /* INC_RFM95_H_ */
