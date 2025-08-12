
#ifndef __DNP3_UTILS_H__
#define __DNP3_UTILS_H__

#include <stdbool.h>    // for bool
#include <stdint.h>     // for uint8_t, uint16_t, uint32_t, uint64_t
#include <stddef.h>     // for sizet_t, NULL

// ARRAY QUEUE
#define BUFFER_QUEUE_SIZE 4

// u32queue
typedef struct {
    uint32_t data[BUFFER_QUEUE_SIZE];
    uint8_t index; // Se usa uint8_t para el índice
} u32queue_t;

// Array queue functions 
void add_queue_u32(u32queue_t* queue, uint32_t new_data);
bool contains_queue_u32(const u32queue_t* queue, uint32_t value_to_find, uint8_t *const found_index);



#endif // __DNP3_UTILS_H__
