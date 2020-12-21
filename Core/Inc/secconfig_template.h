/*
 * secconfig_template.h
 *
 *  Created on: Dec 21, 2020
 *      Author: dkupe
 */


#ifndef INC_SECCONFIG_TEMPLATE_H_
#define INC_SECCONFIG_TEMPLATE_H_

// Information from The Things Network, device configuration ACTIVATION METHOD: ABP, msb left
unsigned char NwkSkey[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char AppSkey[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char DevAddr[4] = { 0x00, 0x00, 0x00, 0x00 };

#endif  INC_SECCONFIG_TEMPLATE_H_

/*
  secconfig.h
  configuration file with security information, not shared on the internet.

  THIS IS AN EXAMPLE FILE, PLEASE RENAME TO secconfig.h
  and replace data with the device values you created with your TTN account

  @author  Leo Korbee (c), Leo.Korbee@xs4all.nl
  @website iot-lab.org
  @license Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
*/


