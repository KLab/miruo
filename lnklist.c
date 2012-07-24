#include <stdio.h>
#include <stdlib.h>
#include "lnklist.h"

struct lnklist_node {
	struct lnklist_node *next;
	struct lnklist_node *prev;
	void *data;
};

struct lnklist {
	struct lnklist_node *head;
	struct lnklist_node *tail;
	struct lnklist_node *iter;
	int size;
};

static const struct lnklist_node LNKLIST_ITER_UNDERFLOW = {NULL, NULL, NULL};

#ifdef __LNKLIST_DEBUG__
int
main(int argc, char *argv[]) {
	struct lnklist *list;
	int count;

	list = lnklist_create();
	for(count = 0; count < 10000; count++) {
		lnklist_add(list, malloc(100), lnklist_size(list));
	}
	for(count = 1000; count < 2000; count++) {
		lnklist_add(list, malloc(100), lnklist_size(list));
	}
	for(count = 3000; count < 4000; count++) {
		lnklist_add(list, malloc(100), lnklist_size(list));
	}
	for(count = 7000; count < 8000; count++) {
		lnklist_add(list, malloc(100), lnklist_size(list));
	}
	for(count = 10000; count < 11000; count++) {
		lnklist_add(list, malloc(100), lnklist_size(list));
	}
	for(count = 14000; count < 15000; count++) {
		lnklist_add(list, malloc(100), lnklist_size(list));
	}
	fprintf(stderr, "lnklist_size(): %zd\n", lnklist_size(list));
	lnklist_iter_init(list);
	while(lnklist_iter_hasnext(list)) {
		free(lnklist_iter_remove_next(list));
	}
	fprintf(stderr, "lnklist_size(): %zd\n", lnklist_size(list));
	lnklist_destroy(list);
	return 0;
}
#endif

struct lnklist *
lnklist_create(void) {
	struct lnklist *obj;

	obj = (struct lnklist *)malloc(sizeof(struct lnklist));
	if(obj) {
		obj->head = NULL;
		obj->tail = NULL;
		obj->iter = (struct lnklist_node *)&LNKLIST_ITER_UNDERFLOW;
		obj->size = 0;
	}
	return obj;
}

void
lnklist_destroy(struct lnklist *obj) {
	lnklist_destroy_with_destructor(obj, NULL);
}

void
lnklist_destroy_with_destructor(struct lnklist *obj, void (*destructor)(void *)) {
	lnklist_iter_init(obj);
	while(lnklist_iter_hasnext(obj)) {
		destructor ? destructor(lnklist_iter_remove_next(obj)) : lnklist_iter_remove_next(obj);
	}
	free(obj);
}

ssize_t
lnklist_size(struct lnklist *obj) {
	return obj ? obj->size : -1;
}

void *
lnklist_add(struct lnklist *obj, void *data, int index) {
	struct lnklist_node *node, *ptr;
	int offset;

	if(!obj || obj->size < index) {
		return NULL;
	}
	node = (struct lnklist_node *)malloc(sizeof(struct lnklist_node));
	if(!node) {
		return NULL;
	}
	node->data = data;
	if(index == 0 || index < obj->size / 2) {
		ptr = obj->head;
		for(offset = 0; offset < index; offset++) {
			ptr = ptr->next;
		}
		node->prev = ptr ? ptr->prev : NULL;
		node->next = ptr;
	}
	else {
		ptr = obj->tail;
		for(offset = obj->size - 1; offset > index; offset--) {
			ptr = ptr->prev;
		}
		node->prev = ptr;
		node->next = ptr ? ptr->next : NULL;
	}
	if(node->next) {
		node->next->prev = node;
	}
	else {
		obj->tail = node;
	}
	if(node->prev) {
		node->prev->next = node;
	}
	else {
		obj->head = node;
	}
	obj->size++;
	return node->data;
}

void *
lnklist_add_tail(struct lnklist *obj, void *data) {
	return obj ? lnklist_add(obj, data, obj->size) : NULL;
}

void *
lnklist_remove(struct lnklist *obj, int index) {
	struct lnklist_node *ptr;
	int offset;
	void *data;

	if(!obj || obj->size <= index) {
		return NULL;
	}
	if(index < obj->size / 2) {
		ptr = obj->head;
		for(offset = 0; offset < index; offset++) {
			ptr = ptr->next;
		}
	}
	else {
		ptr = obj->tail;
		for(offset = obj->size - 1; offset > index; offset--) {
			ptr = ptr->prev;
		}
	}
	if(ptr->prev) {
		ptr->prev->next = ptr->next;
	}
	else {
		obj->head = ptr->next;
		if(obj->head) {
			obj->head->prev = NULL;
		}
	}
	if(ptr->next) {
		ptr->next->prev = ptr->prev;
	}
	else {
		obj->tail = ptr->prev;
		if(obj->tail) {
			obj->tail->next = NULL;
		}
	}
	data = ptr->data;
	free(ptr);
	obj->size--;
	return data;
}

void *
lnklist_get(struct lnklist *obj, int index) {
	struct lnklist_node *ptr;
	int offset;

	if(!obj || obj->size <= index) {
		return NULL;
	}
	if(index < obj->size / 2) {
		ptr = obj->head;
		for(offset = 0; offset < index; offset++) {
			ptr = ptr->next;
		}
	}
	else {
		ptr = obj->tail;
		for(offset = obj->size - 1; offset > index; offset--) {
			ptr = ptr->prev;
		}
	}
	return ptr->data;
}

void
lnklist_iter_init(struct lnklist *obj) {
	if(obj) {
		obj->iter = (struct lnklist_node *)&LNKLIST_ITER_UNDERFLOW;
	}
}

int
lnklist_iter_hasnext(struct lnklist *obj) {
	struct lnklist_node *next;

	if(!obj || !obj->iter) {
		return 0;
	}
	next = (obj->iter == &LNKLIST_ITER_UNDERFLOW) ? obj->head : obj->iter->next;
	return next ? 1 : 0;
}

void *
lnklist_iter_next(struct lnklist *obj) {
	if(!obj || !obj->iter) {
		return NULL;
	}
	obj->iter = (obj->iter == &LNKLIST_ITER_UNDERFLOW) ? obj->head : obj->iter->next;
	return obj->iter ? obj->iter->data : NULL;
}

void *
lnklist_iter_remove(struct lnklist *obj) {
	struct lnklist_node *ptr;
	void *data;

	if(!obj || !obj->iter || obj->iter == &LNKLIST_ITER_UNDERFLOW) {
		return NULL;
	}
	ptr = obj->iter;
	if(ptr->prev) {
		ptr->prev->next = ptr->next;
		obj->iter = ptr->prev;
	}
	else {
		obj->head = ptr->next;
		if(obj->head) {
			obj->head->prev = NULL;
		}
		obj->iter = (struct lnklist_node *)&LNKLIST_ITER_UNDERFLOW;
	}
	if(ptr->next) {
		ptr->next->prev = ptr->prev;
	}
	else {
		obj->tail = ptr->prev;
		if(obj->tail) {
			obj->tail->next = NULL;
		}
	}
	data = ptr->data;
	free(ptr);
	obj->size--;
	return data;
}

void *
lnklist_iter_remove_next(struct lnklist *obj) {
	struct lnklist_node *ptr;
	void *data;

	if(!obj || !obj->iter) {
		return NULL;
	}
	ptr = (obj->iter == &LNKLIST_ITER_UNDERFLOW) ? obj->head : obj->iter->next;
	if(!ptr) {
		return NULL;
	}
	if(ptr->prev) {
		ptr->prev->next = ptr->next;
	}
	else {
		obj->head = ptr->next;
		if(obj->head) {
			obj->head->prev = NULL;
		}
	}
	if(ptr->next) {
		ptr->next->prev = ptr->prev;
	}
	else {
		obj->tail = ptr->prev;
		if(obj->tail) {
			obj->tail->next = NULL;
		}
	}
	data = ptr->data;
	free(ptr);
	obj->size--;
	return data;
}
