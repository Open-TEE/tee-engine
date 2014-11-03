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

#include "tee_list.h"

static void list_add_between(struct list_head *ele, struct list_head *prev, struct list_head *next)
{
	prev->next = ele;
	ele->prev = prev;
	ele->next = next;
	next->prev = ele;
}

static void list_remove_between(struct list_head *start, struct list_head *end)
{
	start->next = end;
	end->prev = start;
}

int list_is_empty(struct list_head *head)
{
	return head->next == head;
}

void list_add_after(struct list_head *ele, struct list_head *after)
{
	list_add_between(ele, after, after->next);
}

void list_add_before(struct list_head *ele, struct list_head *before)
{
	list_add_between(ele, before->prev, before);
}

void list_unlink(struct list_head *element)
{
	list_remove_between(element->prev, element->next);
	element->prev = 0;
	element->next = 0;
}

void list_move_after(struct list_head *from, struct list_head *to)
{
	list_remove_between(from->prev, from->next);
	list_add_after(from, to);
}

void list_move_before(struct list_head *from, struct list_head *to)
{
	list_remove_between(from->prev, from->next);
	list_add_before(from, to);
}
