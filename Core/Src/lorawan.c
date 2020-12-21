/*
 * lorawan.c
 *
 *  Created on: Dec 21, 2020
 *      Author: dkupe
 */

#include <string.h>
#include "lorawan.h"

// security stuff:
static void lorawan_encrypt_payload(lorawan_t *lorawan, uint8_t *data, unsigned len, uint16_t frame_counter, unsigned char direction);
static void lorawan_calculate_mic(lorawan_t *lorawan, uint8_t *data, uint8_t *final_mic, unsigned len, uint16_t frame_counter, unsigned char direction);
static void lorawan_generate_keys(lorawan_t *lorawan, uint8_t *k1, uint8_t *k2);
static void lorawan_shift_left(lorawan_t *lorawan, uint8_t *data);
static void lorawan_xor(lorawan_t *lorawan, uint8_t *new_data, uint8_t *old_data);
static void lorawan_aes_encrypt(lorawan_t *lorawan, uint8_t *data, uint8_t *key);
static void lorawan_aes_add_round_key(lorawan_t *lorawan, uint8_t *round_key, uint8_t (*state)[4]);
static uint8_t lorawan_aes_sub_byte(lorawan_t *lorawan, uint8_t byte);
static void lorawan_aes_shift_rows(lorawan_t *lorawan, uint8_t (*state)[4]);
static void lorawan_aes_mix_columns(lorawan_t *lorawan, uint8_t (*state)[4]);
static void lorawan_aes_calculate_round_key(lorawan_t *lorawan, uint8_t round, uint8_t *round_key);

// for AES encryption
static const unsigned char S_Table[16][16] = {
  {0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76},
  {0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0},
  {0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15},
  {0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75},
  {0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84},
  {0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF},
  {0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8},
  {0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2},
  {0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73},
  {0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB},
  {0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79},
  {0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08},
  {0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A},
  {0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E},
  {0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF},
  {0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16}
};

void lorawan_init(lorawan_t *lorawan, rfm95_t *rfm95)
{
	lorawan->rfm95 = rfm95;
}

void lorawan_set_keys(lorawan_t *lorawan, uint8_t NwkSkey[], uint8_t AppSkey[], uint8_t DevAddr[])
{
	lorawan->AppSkey = AppSkey;
	lorawan->DevAddr = DevAddr;
	lorawan->NwkSkey = NwkSkey;
}


/*
*****************************************************************************************
* Description : Function contstructs a LoRaWAN package and sends it
*
* Arguments   : *Data pointer to the array of data that will be transmitted
*               Data_Length nuber of bytes to be transmitted
*               Frame_Counter_Up  Frame counter of upstream frames
*
*****************************************************************************************
*/

// Had issues with RAM when RFM_Data[64] from Send_Data() and
// Block_A[16] from Encrypt_Payload() where allocated on the stack
// at the same time. Moving to global and share solved it.
// Works because the arrays are never used at the same time
// and always get initialized with new data

unsigned char Buffer[64];

uint32_t lorawan_send_data(lorawan_t *lorawan, uint8_t *data, unsigned len, uint16_t frame_counter_up)
{
	unsigned char i;

	//test flag::if data[i] == i dont dont send but print
	int is_test = 1;
	for(i = 0; i < len; i++)
	{
		if(data[i] != i)
		{
			is_test = 0;
			break;
		}
	}

	//Dir of frame is up
	unsigned char Direction = 0x00;

	//shared RAM with Encrypt payload()
	unsigned char *RFM_Data = Buffer;
	unsigned char RFM_Package_Length;

	unsigned char MIC[4];

	  /*
	    @leo:
	    https://hackmd.io/s/S1kg6Ymo-

	    7â€¦5 bits   4â€¦2 bits   1â€¦0 bits
	    MType       RFU         Major

	    MType   Description
	    000   (0x00) Join Request
	    001   (0x20) Join Accept
	    010   (0x40) Unconfirmed Data Up
	    011   (0x60) Unconfirmed Data Down
	    100   (0x80) Confirmed Data Up
	    101   (0xA0) Confirmed Data Down
	    110   (0xC0) RFU
	    111   (0xE0) Proprietary
	  */

	unsigned char Mac_Header = 0x40;

	//confirmed data up
	//unsigned char Mac_Header = 0x80;

	unsigned char Frame_Control = 0x00;
	unsigned char Frame_Port = 0x01;

	//encrypt the data
	lorawan_encrypt_payload(lorawan, data, len, frame_counter_up, Direction);

	//built the radio package
	RFM_Data[0] = Mac_Header;

	RFM_Data[1] = lorawan->DevAddr[3];
	RFM_Data[2] = lorawan->DevAddr[2];
	RFM_Data[3] = lorawan->DevAddr[1];
	RFM_Data[4] = lorawan->DevAddr[0];

	RFM_Data[5] = Frame_Control;

	RFM_Data[6] = (frame_counter_up & 0x00FF);
	RFM_Data[7] = ((frame_counter_up >> 8) & 0x00FF);

	RFM_Data[8] = Frame_Port;

	//set current package length
	RFM_Package_Length = 9;

	//load data
	for(i = 0; i < len; i++)
	{
		RFM_Data[RFM_Package_Length + i] = data[i];
	}

	//add data length to package length
	RFM_Package_Length = RFM_Package_Length + len;

	//calculate MIC
	lorawan_calculate_mic(lorawan, RFM_Data, MIC, RFM_Package_Length, frame_counter_up, Direction);

	//load MIC in package
	for(i = o; i < 4; i++)
	{
		RFM_Data[i + RFM_Package_Length] = MIC[i];
	}

	//add MIC length to RFM package length
	RFM_Package_Length += 4;

	//print test pack
	if(is_test)
	{
		putstr("encrypted: ");
		for(i = 0; i < RFM_Package_Length; i++)
		{
			puthex(RFM_Data[i]);
		}
		return 0;
	}

	//send package
	return rfm95_send(lorawan->rfm95, RFM_Data, RFM_Package_Length);
}

/*
 * *****************************
 * Encryption
 * *****************************
 */
void lorawan_encryption_payload()
{
	unsigned char i = 0x00;
	unsigned char j;
	unsigned char Number_of_Blocks = 0x00;
	unsigned char Incomplete_Block_Size = 0x00;

	//shared RAM with Send_Data()
	unsigned char *Block_A = Buffer;

}




























