/*  Copyright (c) 2006-2008, Philip Busch <broesel@studcs.uni-sb.de>
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef LIST_H
#define LIST_H

#include <assert.h>

#define list_get_next_node(list, link) ((link)->next == *(list) ? NULL : (link)->next)
#define list_get_prev_node(list, link) ((link) == *(list) ? NULL : (link)->prev)

//#define MAX_POOL_NODE 50000000
#define MAX_POOL_NODE 9000000
#define MAX_POOL_FLOW MAX_POOL_NODE/2

typedef struct node_l node_l;
struct node_l {
	node_l *prev;
	node_l *next;
	void *data;
};

typedef struct _data {
	int n;
	char str[1024];
} data;

void list_alloc_node_no_malloc(void *data);
node_l *list_alloc_node(void *);
node_l *list_get_first_node(node_l **);
node_l *list_get_last_node(node_l **);
void list_prepend_node(node_l **, node_l *);
void list_append_node(node_l **, node_l *);
void list_unlink(node_l **, node_l *);
node_l *list_pop_first_node(node_l **);
node_l * list_search(node_l **list,node_l *node_to_find,int cmp(void *, void *));

void allocNodelPool(void);
int getNodel(void);
void releaseNodel(node_l* f);
void freeNodelPool(void);
#endif  /* ! _LIST_H */
