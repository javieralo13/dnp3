/*
 * dnp3_utils.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "dnp3_utils.h"

/*
 * Remplazado en "t2OnNewFlow memset('\0')" 
 * 
void init_queue_u32(u32queue_t* queue) { //  
    for (int i = 0; i < BUFFER_QUEUE_SIZE; i++) {
        queue->data[i] = 0;
    }
    queue->index = 0;
}
*/

void add_queue_u32(u32queue_t* queue, uint32_t new_data) {
    queue->data[queue->index] = new_data;
    queue->index = (queue->index + 1) % BUFFER_QUEUE_SIZE;
}

bool contains_queue_u32(const u32queue_t* queue, uint32_t value_to_find, uint8_t *const found_index) {
    for (int i = 0; i < BUFFER_QUEUE_SIZE; i++) {
        if (queue->data[i] == value_to_find) {
            if (found_index != NULL) {
                *found_index = i;
            }            
            return true;
        }
    }
    return false;
}

//TODO  Remove an element from the front void dequeue() 
