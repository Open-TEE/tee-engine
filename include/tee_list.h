/*****************************************************************************
** Copyright (C) 2013 ICRI.                                                 **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/

#ifndef __TEE_LIST_H__
#define __TEE_LIST_H__

/*!
 * \brief The list_head struct
 *  Can be embedded into any structure to provide double linked list capabilities
 */
struct list_head {
	struct list_head *prev;
	struct list_head *next;
};

/*!
 * Initialize a linked list
 */
#define INIT_LIST(list)                                                                            \
	do {                                                                                       \
		(list)->prev = (list);                                                             \
		(list)->next = (list);                                                             \
	} while (0)

/*!
 * \brief Get the pointer to the structure based on an element in that structure
 * \param ptr The position of the list_head entry in the data structure
 * \param type The type of structure that the struct list_head is embedded in
 * \param element The name of the struct list_head entry in the data structure
 * \returns A pointer to the data structure
 * \code
 *  struct my_data {
 *      int num;
 *      int data;
 *      struct list_head list;
 *      void *other;
 *  };
 *
 *  struct list_head *pos, ;
 *  struct my_data *element;
 *
 *   LIST_FOR_EACH(pos, &pool.list) {
 *      element = LIST_ENTRY(pos, struct my_data, list);
 */
#define LIST_ENTRY(ptr, type, element)                                                             \
	((type *)(void *)((char *)(ptr) - (unsigned long)(&((type *)0)->element)))

/*!
 *  \brief Iterate over a list
 *  \param pos a struct list_head entry point to the current entry
 *  \param head The main list to iterating over
 */
#define LIST_FOR_EACH(pos, head) for ((pos) = (head)->next; (pos) != (head); (pos) = (pos)->next)

/*!
 *  \brief Iterate over a list backwards
 *  \param pos a struct list_head entry point to the current entry
 *  \param head The main list to iterating over
 */
#define LIST_FOR_EACH_PREV(pos, head)                                                              \
	for ((pos) = (head)->prev; (pos) != (head); (pos) = (pos)->prev)

/*!
 *  \brief Iterate over a list safely, this allows elements to be removed or added in the loop
 *  \param pos a struct list_head entry point to the current entry
 *  \param la a struct list_head entry used for look ahead to ensure safety
 *  \param head The main list to iterating over
 */
#define LIST_FOR_EACH_SAFE(pos, la, head)                                                          \
	for ((pos) = (head)->next, (la) = (pos)->next; (pos) != (head);                            \
	     (pos) = (la), (la) = (pos)->next)

/*!
 * \brief list_is_empty
 *  Determine if a list is empty
 * \param head The start of the list
 * \return True if the list is empty.
 */
int list_is_empty(struct list_head *head);

/*!
 * \brief list_add_after
 *  Add elements to the list in a stack like way. LIFO
 * \param ele The element to add
 * \param after The list to add it to
 */
void list_add_after(struct list_head *ele, struct list_head *after);

/*!
 * \brief list_add_before
 *  Add elements to the list in a queue like fashion
 * \param ele The element to be added to the list
 * \param before The list entry to be added before
 */
void list_add_before(struct list_head *ele, struct list_head *before);

/*!
 * \brief list_unlink
 *  Delete an entry from the list. This does not free the element, that is left to the caller to do.
 * \param element The element to be removed from the list
 */
void list_unlink(struct list_head *element);

/*!
 * \brief list_move_after
 *  Move an entry from one list location to another, or between lists
 * \param from The list entry to be moved
 * \param to Where to move it
 */
void list_move_after(struct list_head *from, struct list_head *to);

/*!
 * \brief list_move_before
 *  Move an entry from one list location to another, or between lists
 * \param from The list entry location to move from
 * \param to The location to move to
 */
void list_move_before(struct list_head *from, struct list_head *to);

#endif
