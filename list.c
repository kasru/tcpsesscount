#include <stdlib.h>
#include <string.h>

#include "list.h"

list_node_t* list_create(void *data)
{
     list_node_t *node = malloc(sizeof(list_node_t));
     if (node)
     {
          node->next = NULL;
          node->data = data;
     }
     return node;
}

void list_destroy(list_node_t **list)
{
     if (!list) return;
     while (*list != NULL)
     {
          list_remove(list, *list);
     }
}

list_node_t* list_insert_begin(list_node_t *list, void *data)
{
     list_node_t *new_node = list_create(data);
     if (new_node)
     {
          new_node->next = list;
     }
     return new_node;
}

list_node_t* list_insert_end(list_node_t *list, void *data)
{
     list_node_t *new_node = list_create(data);
     if (new_node)
     {
          for (list_node_t *it = list; it; it = it->next)
          {
               if (!it->next)
               {
                    it->next = new_node;
                    break;
               }
          }
     }
     return new_node;
}

list_node_t* list_insert_after(list_node_t *node, void *data)
{
     list_node_t *new_node = list_create(data);
     if (new_node)
     {
          new_node->next = node->next;
          node->next = new_node;
     }
     return new_node;
}

void list_remove(list_node_t **list, list_node_t *node)
{
     list_node_t *tmp = NULL;
     if (list == NULL || *list == NULL || node == NULL) return;

     if (*list == node)
     {
          *list = (*list)->next;
          free(node);
          node = NULL;
     }
     else
     {
          tmp = *list;
          while (tmp->next && tmp->next != node) tmp = tmp->next;
          if (tmp->next)
          {
               tmp->next = node->next;
               free(node);
               node = NULL;
          }
     }
}

void list_remove_by_data(list_node_t **list, void *data)
{
     if (list == NULL || *list == NULL || data == NULL) return;
     list_remove(list, list_find_by_data(*list, data));
}

list_node_t* list_find_node(list_node_t *list, list_node_t *node)
{
     while (list)
     {
          if (list == node) break;
          list = list->next;
     }
     return list;
}

list_node_t* list_find_by_data(list_node_t *list, void *data)
{
     while (list)
     {
          if (list->data == data) break;
          list = list->next;
     }
     return list;
}

list_node_t* list_find(list_node_t *list, int(*func)(void*, const void*), const void *data)
{
     if (!func) return NULL;
     while (list)
     {
          if (func(list->data, data)) break;
          list = list->next;
     }
     return list;
}
