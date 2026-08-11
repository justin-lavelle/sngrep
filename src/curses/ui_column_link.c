/**************************************************************************
 **
 ** sngrep - SIP Messages flow viewer
 **
 ** Copyright (C) 2013-2026 Ivan Alonso (Kaian)
 ** Copyright (C) 2013-2026 Irontec SL. All rights reserved.
 **
 ** This program is free software: you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, either version 3 of the License, or
 ** (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **
 ****************************************************************************/
/**
 * @file ui_column_link.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in ui_column_link.h
 */

#include <stdlib.h>
#include <string.h>
#include "ui_column_link.h"
#include "util.h"
#include "vector.h"
#include "group.h"

/**
 * Ui Structure definition for Column Link panel
 */
ui_t ui_column_link = {
    .type = PANEL_COLUMN_LINK,
    .panel = NULL,
    .create = column_link_create,
    .destroy = column_link_destroy,
    .draw = column_link_draw,
    .handle_key = column_link_handle_key
};

static void
column_link_rebuild_entries(column_link_info_t *info);

void
column_link_create(ui_t *ui)
{
    column_link_info_t *info;

    ui_panel_create(ui, 20, 72);

    info = sng_malloc(sizeof(column_link_info_t));
    info->entries = vector_create(8, 8);
    vector_set_destroyer(info->entries, vector_generic_destroyer);
    info->cur = 0;
    info->scroll = 0;
    info->pending = -1;
    info->parent_flow = NULL;

    set_panel_userptr(ui->panel, (void *) info);

    wattron(ui->win, COLOR_PAIR(CP_BLUE_ON_DEF));
    title_foot_box(ui->panel);
    wattroff(ui->win, COLOR_PAIR(CP_BLUE_ON_DEF));
    mvwprintw(ui->win, 1, 2, "Link Multi-homed Columns");
}

void
column_link_destroy(ui_t *ui)
{
    column_link_info_t *info = column_link_info(ui);

    if (info) {
        vector_destroy(info->entries);
        sng_free(info);
    }
    ui_panel_destroy(ui);
}

column_link_info_t *
column_link_info(ui_t *ui)
{
    return (column_link_info_t *) panel_userptr(ui->panel);
}

void
column_link_set_flow(ui_t *ui, ui_t *flow_ui)
{
    column_link_info_t *info = column_link_info(ui);

    info->parent_flow = flow_ui;
    info->cur = 0;
    info->scroll = 0;
    info->pending = -1;
    column_link_rebuild_entries(info);
}

static void
column_link_rebuild_entries(column_link_info_t *info)
{
    call_flow_info_t *flow;
    call_flow_column_t *col, *sc, *dc;
    column_link_entry_t *e, *ei, *ej;
    sip_msg_t *msg = NULL;
    char *traffic;
    int i, n, si, di;

    if (!info->parent_flow)
        return;

    flow = call_flow_info(info->parent_flow);
    if (!flow)
        return;

    vector_clear(info->entries);

    n = vector_count(flow->columns);
    if (n <= 0)
        return;

    traffic = sng_malloc((size_t) n * (size_t) n);

    /* traffic[i][j] = 1 if any message was exchanged between columns i and j */
    while ((msg = call_group_get_next_msg(flow->group, msg))) {
        sc = call_flow_column_get(info->parent_flow, msg->call->callid, msg->packet->src);
        dc = call_flow_column_get(info->parent_flow, msg->call->callid, msg->packet->dst);
        si = vector_index(flow->columns, sc);
        di = vector_index(flow->columns, dc);
        if (si >= 0 && di >= 0) {
            traffic[si * n + di] = 1;
            traffic[di * n + si] = 1;
        }
    }

    for (i = 0; i < n; i++) {
        col = vector_item(flow->columns, i);
        e = sng_malloc(sizeof(column_link_entry_t));
        e->addr = col->addr;
        e->column = col;
        snprintf(e->label, sizeof(e->label), "%s:%u", col->addr.ip, col->addr.port);
        e->linked_to = call_flow_column_link_get(col->addr);
        e->suggested = 0;
        vector_append(info->entries, e);
    }

    /* Suggest only adjacent column pairs with no traffic between them */
    for (i = 0; i < n - 1; i++) {
        ei = vector_item(info->entries, i);
        ej = vector_item(info->entries, i + 1);
        if (ei->linked_to || ej->linked_to)
            continue;
        if (!traffic[i * n + (i + 1)]) {
            ei->suggested = 1;
            ej->suggested = 1;
        }
    }

    sng_free(traffic);

    if (info->cur >= vector_count(info->entries))
        info->cur = vector_count(info->entries) - 1;
    if (info->cur < 0)
        info->cur = 0;
}

int
column_link_draw(ui_t *ui)
{
    column_link_info_t *info = column_link_info(ui);
    column_link_entry_t *e;
    WINDOW *win = ui->win;
    int i, row, visible;
    char status[64];

    werase(win);
    wattron(win, COLOR_PAIR(CP_BLUE_ON_DEF));
    title_foot_box(ui->panel);
    wattroff(win, COLOR_PAIR(CP_BLUE_ON_DEF));

    mvwprintw(win, 1, 2, "Link Multi-homed Columns");
    mvwprintw(win, 3, 2, "%-28s %s", "Endpoint", "Status");
    mvwhline(win, 4, 1, ACS_HLINE, ui->width - 2);

    visible = ui->height - 8;
    if (visible < 1)
        visible = 1;

    if (info->cur < info->scroll)
        info->scroll = info->cur;
    if (info->cur >= info->scroll + visible)
        info->scroll = info->cur - visible + 1;

    for (i = info->scroll; i < vector_count(info->entries)
         && i < info->scroll + visible; i++) {
        e = vector_item(info->entries, i);
        row = 5 + (i - info->scroll);

        if (i == info->cur)
            wattron(win, A_REVERSE);
        if (i == info->pending)
            wattron(win, A_BOLD);

        status[0] = '\0';
        if (e->linked_to) {
            snprintf(status, sizeof(status), "linked -> %s:%u",
                     e->linked_to->ip, e->linked_to->port);
        } else if (e->suggested) {
            snprintf(status, sizeof(status), "* suggested (adjacent, no traffic)");
        }

        mvwprintw(win, row, 2, "%-28s %-38s", e->label, status);
        wattroff(win, A_REVERSE | A_BOLD);
    }

    mvwprintw(win, ui->height - 2, 2,
              "Enter: select/link   u: unlink   *: suggestion   Esc: close");
    return 0;
}

int
column_link_handle_key(ui_t *ui, int key)
{
    column_link_info_t *info = column_link_info(ui);
    column_link_entry_t *e, *first, *other;
    int n = vector_count(info->entries);
    int action = -1;

    if (n <= 0)
        return KEY_NOT_HANDLED;

    while ((action = key_find_action(key, action)) != ERR) {
        switch (action) {
            case ACTION_DOWN:
                info->cur = (info->cur + 1) % n;
                break;
            case ACTION_UP:
                info->cur = (info->cur - 1 + n) % n;
                break;
            case ACTION_CONFIRM:
            case ACTION_SELECT:
                e = vector_item(info->entries, info->cur);
                if (info->pending == -1) {
                    if (!e->linked_to)
                        info->pending = info->cur;
                } else if (info->pending != info->cur) {
                    first = vector_item(info->entries, info->pending);
                    call_flow_column_link_add(first->addr, e->addr);
                    info->pending = -1;
                    column_link_rebuild_entries(info);
                }
                break;
            case ACTION_DELETE:
            case ACTION_CLEAR:
                e = vector_item(info->entries, info->cur);
                if (e->linked_to) {
                    call_flow_column_link_remove(e->addr);
                    column_link_rebuild_entries(info);
                }
                break;
            case ACTION_PREV_SCREEN:
            case ACTION_COLUMN_LINK:
                ui_destroy(ui);
                return KEY_HANDLED;
            default:
                continue;
        }
        break;
    }

    if (action != ERR)
        return KEY_HANDLED;

    /* Keys not mapped through the action table */
    switch (key) {
        case 'u':
        case 'U':
            e = vector_item(info->entries, info->cur);
            if (e->linked_to) {
                call_flow_column_link_remove(e->addr);
                column_link_rebuild_entries(info);
            }
            return KEY_HANDLED;
        case '*':
            /* Link highlighted entry with its adjacent suggested neighbor */
            e = vector_item(info->entries, info->cur);
            if (e->suggested && !e->linked_to) {
                other = NULL;
                if (info->cur > 0) {
                    other = vector_item(info->entries, info->cur - 1);
                    if (!other->suggested || other->linked_to)
                        other = NULL;
                }
                if (!other && info->cur + 1 < n) {
                    other = vector_item(info->entries, info->cur + 1);
                    if (!other->suggested || other->linked_to)
                        other = NULL;
                }
                if (other) {
                    call_flow_column_link_add(e->addr, other->addr);
                    column_link_rebuild_entries(info);
                }
            }
            return KEY_HANDLED;
        default:
            return KEY_NOT_HANDLED;
    }
}
