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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "list.h"

extern node_l static_node;

extern node_l *nodel_aux;
node_l *nodel_pool_free=NULL;
node_l *nodel_pool_used=NULL;
int free_nodes;

pthread_mutex_t sem_pool_node = PTHREAD_MUTEX_INITIALIZER;

node_l *list_get_first_node(node_l **list)
{
	assert(list != NULL);

	return(*list);
}


node_l *list_get_last_node(node_l **list)
{
	assert(list != NULL);

	if(*list == NULL) {
		return(NULL);
	} else {
		return((*list)->prev);
	}
}


node_l *list_alloc_node(void *data)
{
	node_l *n = NULL;

	if((n = malloc(sizeof(node_l))) != NULL) {
		n->data = data;
	}

	return(n);
}

void list_alloc_node_no_malloc(void *data)
{
	
	static_node.data = data;
	
}

void list_prepend_node(node_l **list,
                       node_l  *node)
{
	assert(list != NULL);
	assert(node != NULL);
	node_l *here=*list;
	if(*list == NULL) {
		node->prev = node;
		node->next = node;
		*list = node;
	} else {
		assert(here != NULL);

		node->prev = here->prev;
		node->next = here;
		here->prev = node;
		if(node->prev!=NULL)
			node->prev->next = node;

		if(here == *list) {
			*list = node;
		}
	}
}
void list_append_node(node_l **list,
			node_l *node)
{
	assert(list!=NULL);
	assert(node != NULL);
	list_prepend_node(list,node);
	*list=(*list)->next;
}

void list_append_node2(node_l **list,
			node_l *node, node_l *last_node)
{
	assert(list!=NULL);
	assert(node != NULL);
	if(last_node!=NULL){
		last_node->prev=node;
		node->next=last_node;
	}
	else{
		list_prepend_node(list,node);	
		*list=(*list)->next;
	}

//	list_prepend_node(list,node);
//	*list=(*list)->next;

}

node_l * list_search(node_l **list,node_l *node_to_find,int cmp(void *, void *))
{
	node_l *n;

	assert(list != NULL);

	n = *list;

	while(n != NULL) {
		//printf("n:%p n->data:%p\n",n,n->data);
		if(cmp(n->data,node_to_find->data)==0)
			return n;
		   
		n = list_get_next_node(list, n);
	}

	return NULL;
}

void list_unlink(node_l **list,
                 node_l  *node)
{
	assert(list != NULL);
	assert(node != NULL);

	if(node->next == node) {
		*list = NULL;
	} else {
		if(node->prev!=NULL)
			node->prev->next = node->next;
		if(node->next!=NULL)
			node->next->prev = node->prev;

		if(*list == node)
			*list = node->next;
	}

	node->next = NULL;
	node->prev = NULL;
}

node_l *list_pop_first_node(node_l **list)
{
	node_l *n;

	assert(list != NULL);

	n = list_get_first_node(list);

	if(n != NULL)
		list_unlink(list, n);

	return(n);
}

node_l *nl;

void allocNodelPool(void)
{
	int i=0;
	node_l *n=NULL;
	nl=malloc(sizeof(node_l)*MAX_POOL_NODE);
	bzero(nl,sizeof(node_l)*MAX_POOL_NODE);
	assert(nl!=NULL);
	for(i=0;i<MAX_POOL_NODE;i++)
	{
		n=list_alloc_node(nl+i);
		list_prepend_node(&nodel_pool_free,n);
	}
	free_nodes=MAX_POOL_NODE;
}


int getNodel(void)
{

	pthread_mutex_lock(&sem_pool_node);

	node_l *n=list_pop_first_node(&nodel_pool_free);
	if(nodel_pool_free==NULL){
		printf("pool Nodos vacío\n");
		return -1;
	}
	list_append_node(&nodel_pool_used,n);
	assert(n!=NULL);
	nodel_aux=n->data;
	free_nodes--;
	pthread_mutex_unlock(&sem_pool_node);

	return 0;
	
}

void releaseNodel(node_l* f)
{

	assert(f!=NULL);
	pthread_mutex_lock(&sem_pool_node);

	node_l *n=list_pop_first_node(&nodel_pool_used);
	n->data=(void*)f;
	list_append_node(&nodel_pool_free,n);
	free_nodes++;
	pthread_mutex_unlock(&sem_pool_node);


}

void freeNodelPool(void)
{
	node_l *n=NULL;
	while(nodel_pool_free!=NULL)
	{
		n=list_pop_first_node(&nodel_pool_free);
		free(n);
	}

	while(nodel_pool_used!=NULL)
	{
		n=list_pop_first_node(&nodel_pool_used);
		free(n);
	}
	free(nl);
}
