#include <stdio.h>
#include "aes-128_enc.h"

int main(int argc, char*argv[]){
    const uint8_t init_key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,
                            0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    // uint8_t first_round_key[16] ;
    // next_aes128_round_key(init_key,first_round_key,0);
    // int i;
    // for(i=0; i<16 ; i++){
    //     printf("%x ,",first_round_key[i]);
    // } 

    // printf("\n");
    // uint8_t buf[16];
    // prev_aes128_round_key(first_round_key,buf,0);
    // for(i=0; i<16 ; i++){
    //     printf("%x ,",buf[i]);
    // } 
    // printf("\n");
    // for(i=0; i<16 ; i++){
    //     printf("%x ,",init_key[i]);
    // }
    // printf("\n");
    uint8_t t[256][16];
    int i;
    int sum = 0;
    for( i = 0; i < 256; i++){
        t[i][0] =(uint8_t) i;
        int j;
        for(j = 1; i<16 ; i++){
            t[i][j] = (i + j) % 256;
        }
    }
    for(i = 0 ; i < 256 ; i++){
        aes128_enc(t[i],init_key,4,0);
    }
    for( i=0; i<256 ; i++){
        int j;
        for(j=0; j<16 ; j++){
            sum ^= t[i][j];
        }
    }    
    printf("s = %d\n",sum );
    
    return 0 ;
}