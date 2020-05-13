#ifndef TCP_SESS_COUNT_LIST_H
#define TCP_SESS_COUNT_LIST_H

/// @brief Реализация самого простого списка

struct list_node
{
     void *data;
     struct list_node *next;
};

typedef struct list_node list_node_t;

list_node_t* list_create(void *data);
void list_destroy(list_node_t **list);

list_node_t* list_insert_begin(list_node_t *list, void *data);
list_node_t* list_insert_end(list_node_t *list, void *data);
list_node_t* list_insert_after(list_node_t *node, void *data);
void list_remove(list_node_t **list, list_node_t *node);
void list_remove_by_data(list_node_t **list, void *data);
list_node_t* list_find_node(list_node_t *list, list_node_t *node);
list_node_t* list_find_by_data(list_node_t *list, void *data);

/// @brief Поиск в списке с помощью ф-ции компаратора
/// @details int(*func)(void*,const void*) - первый параметр для сравнения взятый из списка, второй параметр переданный в параметре data
/// компаратор возвращает 1 - если если нашли нужный элемент, 0 - если не нашли
list_node_t* list_find(list_node_t *list, int(*func)(void*, const void*), const void *data);

#endif //TCP_SESS_COUNT_LIST_H
