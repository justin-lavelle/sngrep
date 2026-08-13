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
 * @file ui_call_flow.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in ui_call_flow.h
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include "capture.h"
#include "ui_manager.h"
#include "ui_call_flow.h"
#include "ui_call_raw.h"
#include "ui_msg_diff.h"
#include "ui_save.h"
#include "util.h"
#include "vector.h"
#include "option.h"

#define METHOD_MAXLEN 80

/**
 * Find union-find root for column linking
 */
static int
call_flow_link_find(int *parent, int x)
{
    while (parent[x] != x)
        x = parent[x];
    return x;
}

/**
 * Union two column indices for linking
 */
static void
call_flow_link_union(int *parent, int a, int b)
{
    int ra = call_flow_link_find(parent, a);
    int rb = call_flow_link_find(parent, b);
    if (ra != rb)
        parent[rb] = ra;
}

/**
 * Check whether two addresses are directly linked
 */
static int
call_flow_addr_pair_linked(call_flow_info_t *info, address_t a, address_t b)
{
    vector_iter_t it;
    call_flow_link_t *link;

    if (!info->column_links)
        return 0;

    it = vector_iterator(info->column_links);
    while ((link = vector_iterator_next(&it))) {
        if ((addressport_equals(link->addr1, a) && addressport_equals(link->addr2, b)) ||
            (addressport_equals(link->addr1, b) && addressport_equals(link->addr2, a))) {
            return 1;
        }
    }
    return 0;
}

/**
 * Assign packed display positions from column link groups
 */
static void
call_flow_columns_assign_disppos(call_flow_info_t *info)
{
    int i, n, next_pos;
    int *parent, *root_disp;
    call_flow_column_t *col_i;
    call_flow_link_t *link;
    vector_iter_t it;

    n = vector_count(info->columns);
    if (n == 0)
        return;

    parent = sng_malloc(sizeof(int) * n);
    root_disp = sng_malloc(sizeof(int) * n);
    for (i = 0; i < n; i++) {
        parent[i] = i;
        root_disp[i] = -1;
    }

    if (info->column_links) {
        it = vector_iterator(info->column_links);
        while ((link = vector_iterator_next(&it))) {
            int idx1 = -1, idx2 = -1;
            for (i = 0; i < n; i++) {
                col_i = vector_item(info->columns, i);
                if (addressport_equals(col_i->addr, link->addr1))
                    idx1 = i;
                if (addressport_equals(col_i->addr, link->addr2))
                    idx2 = i;
            }
            if (idx1 >= 0 && idx2 >= 0)
                call_flow_link_union(parent, idx1, idx2);
        }
    }

    next_pos = 0;
    for (i = 0; i < n; i++) {
        int root = call_flow_link_find(parent, i);
        if (root_disp[root] < 0)
            root_disp[root] = next_pos++;
        col_i = vector_item(info->columns, i);
        col_i->disppos = root_disp[root];
    }

    sng_free(parent);
    sng_free(root_disp);
}

/**
 * True when any SIP message travels between the two column addresses
 */
static int
call_flow_columns_have_messages(call_flow_info_t *info, call_flow_column_t *a,
                                call_flow_column_t *b)
{
    sip_msg_t *msg = NULL;

    while ((msg = call_group_get_next_msg(info->group, msg))) {
        if ((addressport_equals(msg->packet->src, a->addr) &&
             addressport_equals(msg->packet->dst, b->addr)) ||
            (addressport_equals(msg->packet->src, b->addr) &&
             addressport_equals(msg->packet->dst, a->addr))) {
            return 1;
        }
    }
    return 0;
}

/**
 * Mark adjacent columns that have no traffic between them as suggested
 */
static void
call_flow_link_mark_suggestions(call_flow_info_t *info, int *suggested, int col_count)
{
    int i;

    memset(suggested, 0, sizeof(int) * col_count);
    for (i = 0; i < col_count - 1; i++) {
        call_flow_column_t *a = vector_item(info->columns, i);
        call_flow_column_t *b = vector_item(info->columns, i + 1);
        if (!call_flow_columns_have_messages(info, a, b) &&
            !call_flow_addr_pair_linked(info, a->addr, b->addr)) {
            suggested[i] = 1;
            suggested[i + 1] = 1;
        }
    }
}

/**
 * Auto-accept all suggested adjacent column links into column_links
 */
static void
call_flow_apply_suggested_links(call_flow_info_t *info)
{
    int i, n;

    if (!info || !info->column_links)
        return;

    n = vector_count(info->columns);
    for (i = 0; i < n - 1; i++) {
        call_flow_column_t *a = vector_item(info->columns, i);
        call_flow_column_t *b = vector_item(info->columns, i + 1);
        if (!call_flow_columns_have_messages(info, a, b) &&
            !call_flow_addr_pair_linked(info, a->addr, b->addr)) {
            call_flow_link_t *link = sng_malloc(sizeof(call_flow_link_t));
            link->addr1 = a->addr;
            link->addr2 = b->addr;
            vector_append(info->column_links, link);
        }
    }
}

/**
 * Leave linked compress mode so suggestion links are not re-applied on draw
 */
static void
call_flow_disable_linked_mode(void)
{
    if (setting_has_value(SETTING_CF_SPLITCALLID, "linked"))
        setting_set_value(SETTING_CF_SPLITCALLID, SETTING_OFF);
}

//! Max ports aggregated under one IP in a linked header
#define CF_LINK_MAX_PORTS 16
//! Max distinct IPs shown in a linked column header
#define CF_LINK_MAX_IPS   8
//! Default separator line width under a column header
#define CF_COL_SEP_WIDTH  20

/**
 * Print a column header label centered on the vertical guide
 */
static void
call_flow_print_centered_label(WINDOW *win, int line, int vline_x, const char *text)
{
    int len;
    int x;

    if (!text)
        return;

    len = (int) strlen(text);
    x = vline_x - len / 2;
    if (x < 0)
        x = 0;
    mvwprintw(win, line, x, "%s", text);
}

/**
 * One IP with one or more ports for a linked column header
 */
struct call_flow_link_header_ip {
    char ip[ADDRESSLEN];
    char label[MAX_SETTING_LEN];
    uint16_t ports[CF_LINK_MAX_PORTS];
    int port_count;
    int transport;
};

/**
 * Lowercase transport name for column headers
 */
static const char *
call_flow_transport_str(int transport)
{
    switch (transport) {
        case PACKET_SIP_UDP:
            return "udp";
        case PACKET_SIP_TCP:
            return "tcp";
        case PACKET_SIP_TLS:
            return "tls";
        case PACKET_SIP_WS:
            return "ws";
        case PACKET_SIP_WSS:
            return "wss";
        case PACKET_RTP:
            return "rtp";
        case PACKET_RTCP:
            return "rtcp";
        default:
            return "";
    }
}

/**
 * Color pair for a SIP transport protocol label
 */
static int
call_flow_protocol_color(int transport)
{
    /* Default / cycled-back mode: light gray for all protocols */
    if (!setting_has_value(SETTING_CF_PROTOCOL_COLOR, "proto"))
        return CP_PROTO_GRAY_ON_DEF;

    switch (transport) {
        case PACKET_SIP_UDP:
            return CP_PROTO_UDP_ON_DEF;
        case PACKET_SIP_TCP:
            return CP_PROTO_TCP_ON_DEF;
        case PACKET_SIP_TLS:
            return CP_PROTO_TLS_ON_DEF;
        case PACKET_SIP_WS:
            return CP_PROTO_WS_ON_DEF;
        case PACKET_SIP_WSS:
            return CP_PROTO_WSS_ON_DEF;
        default:
            return CP_PROTO_GRAY_ON_DEF;
    }
}

/**
 * Draw "(proto)" at x,y. Only the name inside parentheses uses protocol color.
 * @return printed width, or 0 if protocol display is off / unknown
 */
static int
call_flow_print_protocol_label(WINDOW *win, int y, int x, int transport,
                               int arrow_color, int bright)
{
    const char *proto;
    int cp, plen;
    attr_t attrs;
    short pair;

    if (!setting_enabled(SETTING_CF_PROTOCOL))
        return 0;

    proto = call_flow_transport_str(transport);
    if (!proto[0])
        return 0;

    cp = call_flow_protocol_color(transport);
    plen = (int) strlen(proto);

    /* Keep current arrow attrs for '(' */
    mvwaddch(win, y, x, '(');

    /* Protocol name uses dedicated color; bold when arrow is selected */
    wattr_get(win, &attrs, &pair, NULL);
    wattrset(win, COLOR_PAIR(cp) | (bright ? A_BOLD : A_NORMAL));
    mvwprintw(win, y, x + 1, "%s", proto);
    wattr_set(win, attrs, pair, NULL);

    mvwaddch(win, y, x + 1 + plen, ')');
    /* Ensure arrow color remains active for following tip characters */
    wattron(win, COLOR_PAIR(arrow_color));

    return plen + 2;
}

/**
 * Count how many columns share a display position
 */
static int
call_flow_disppos_count(call_flow_info_t *info, int disppos)
{
    int count = 0;
    vector_iter_t it = vector_iterator(info->columns);
    call_flow_column_t *col;

    while ((col = vector_iterator_next(&it))) {
        if (col->disppos == disppos)
            count++;
    }
    return count;
}

/**
 * Build stacked header lines for all columns sharing disppos.
 * Same IP merges ports as ip:port1|port2; different IPs are separate lines.
 * @return number of header lines written into lines[]
 */
static int
call_flow_linked_header_lines(call_flow_info_t *info, int disppos,
                              char lines[][MAX_SETTING_LEN], int max_lines)
{
    struct call_flow_link_header_ip ips[CF_LINK_MAX_IPS];
    int ip_count = 0;
    int i, j;
    vector_iter_t it;
    call_flow_column_t *col;

    memset(ips, 0, sizeof(ips));

    it = vector_iterator(info->columns);
    while ((col = vector_iterator_next(&it))) {
        int ip_idx = -1;

        if (col->disppos != disppos)
            continue;

        for (i = 0; i < ip_count; i++) {
            if (!strcmp(ips[i].ip, col->addr.ip)) {
                ip_idx = i;
                break;
            }
        }

        if (ip_idx < 0) {
            if (ip_count >= CF_LINK_MAX_IPS || ip_count >= max_lines)
                continue;
            ip_idx = ip_count++;
            sng_strncpy(ips[ip_idx].ip, col->addr.ip, sizeof(ips[ip_idx].ip));
            ips[ip_idx].transport = col->transport;
            if (setting_enabled(SETTING_DISPLAY_ALIAS))
                sng_strncpy(ips[ip_idx].label, get_alias_value(col->addr.ip),
                            sizeof(ips[ip_idx].label));
            else
                sng_strncpy(ips[ip_idx].label, col->addr.ip, sizeof(ips[ip_idx].label));
        }

        if (!col->addr.port)
            continue;

        for (j = 0; j < ips[ip_idx].port_count; j++) {
            if (ips[ip_idx].ports[j] == col->addr.port)
                break;
        }
        if (j == ips[ip_idx].port_count && ips[ip_idx].port_count < CF_LINK_MAX_PORTS)
            ips[ip_idx].ports[ips[ip_idx].port_count++] = col->addr.port;
    }

    for (i = 0; i < ip_count; i++) {
        char portbuf[MAX_SETTING_LEN];
        size_t plen = 0;
        portbuf[0] = '\0';

        for (j = 0; j < ips[i].port_count; j++) {
            plen += snprintf(portbuf + plen, sizeof(portbuf) - plen, "%s%u",
                             j ? "|" : "", ips[i].ports[j]);
            if (plen >= sizeof(portbuf))
                break;
        }

        if (ips[i].port_count > 0) {
            snprintf(lines[i], MAX_SETTING_LEN, "%s:%s", ips[i].label, portbuf);
        } else {
            snprintf(lines[i], MAX_SETTING_LEN, "%s", ips[i].label);
        }
    }

    return ip_count;
}

/**
 * Draw a vertical column guide; double-line for linked columns
 */
static void
call_flow_draw_column_vline(WINDOW *win, int y, int x, int height, int linked)
{
    int row;

    if (!linked) {
        mvwvline(win, y, x, ACS_VLINE, height);
        return;
    }

    for (row = 0; row < height; row++)
        mvwprintw(win, y + row, x, "║");
}

/**
 * Place flow window under the multi-line column header area
 */
static void
call_flow_layout_flow_win(ui_t *ui, call_flow_info_t *info)
{
    int header_rows = info->header_rows > 0 ? info->header_rows : 1;
    int flow_start = 3 + header_rows;
    int flow_height = ui->height - flow_start - 2;

    if (flow_height < 1)
        flow_height = 1;

    wresize(info->flow_win, flow_height, ui->width - 2);
    mvwin(info->flow_win, flow_start, 0);
    info->scroll = ui_set_scrollbar(info->flow_win, SB_VERTICAL, SB_LEFT);
}

/**
 * Format column label as used in the flow header / link menu
 */
static void
call_flow_column_label(call_flow_column_t *column, char *out, size_t outsize)
{
    const char *host;

    if (setting_enabled(SETTING_CF_SPLITCALLID) || !column->addr.port) {
        snprintf(out, outsize, "%s", column->alias);
        return;
    }

    if (setting_enabled(SETTING_DISPLAY_ALIAS))
        host = column->alias;
    else
        host = column->addr.ip;

    if (strlen(host) > 15) {
        snprintf(out, outsize, "..%.*s:%u",
                 (int) outsize - 8, host + strlen(host) - 13, column->addr.port);
    } else {
        snprintf(out, outsize, "%s:%u", host, column->addr.port);
    }
}

/***
 *
 * Some basic ascii art of this panel.
 *
 * +--------------------------------------------------------+
 * |                     Title                              |
 * |   addr1  addr2  addr3  addr4 | Selected Raw Message    |
 * |   -----  -----  -----  ----- | preview                 |
 * | Tmst|      |      |      |   |                         |
 * | Tmst|----->|      |      |   |                         |
 * | Tmst|      |----->|      |   |                         |
 * | Tmst|      |<-----|      |   |                         |
 * | Tmst|      |      |----->|   |                         |
 * | Tmst|<-----|      |      |   |                         |
 * | Tmst|      |----->|      |   |                         |
 * | Tmst|      |<-----|      |   |                         |
 * | Tmst|      |------------>|   |                         |
 * | Tmst|      |<------------|   |                         |
 * |     |      |      |      |   |                         |
 * |     |      |      |      |   |                         |
 * |     |      |      |      |   |                         |
 * | Useful hotkeys                                         |
 * +--------------------------------------------------------+
 *
 */

/**
 * Ui Structure definition for Call Flow panel
 */
ui_t ui_call_flow = {
    .type = PANEL_CALL_FLOW,
    .panel = NULL,
    .create = call_flow_create,
    .destroy = call_flow_destroy,
    .redraw = call_flow_redraw,
    .draw = call_flow_draw,
    .handle_key = call_flow_handle_key,
    .help = call_flow_help
};

void
call_flow_create(ui_t *ui)
{
    // Create a new panel to fill all the screen
    ui_panel_create(ui, LINES, COLS);

    // Initialize Call List specific data
    call_flow_info_t *info = malloc(sizeof(call_flow_info_t));
    memset(info, 0, sizeof(call_flow_info_t));

    // Display timestamp next to each arrow
    info->arrowtime = true;
    info->header_rows = 1;

    // Calculate available printable area for messages
    info->flow_win = subwin(ui->win, ui->height - 6, ui->width - 2, 4, 0);
    info->scroll = ui_set_scrollbar(info->flow_win, SB_VERTICAL, SB_LEFT);

    // Create vectors for columns and flow arrows
    info->columns = vector_create(2, 1);
    info->arrows = vector_create(20, 5);
    vector_set_sorter(info->arrows, call_flow_arrow_sorter);
    info->column_links = vector_create(0, 2);
    vector_set_destroyer(info->column_links, vector_generic_destroyer);

    // Store it into panel userptr
    set_panel_userptr(ui->panel, (void*) info);
}

void
call_flow_destroy(ui_t *ui)
{
    call_flow_info_t *info;

    // Free the panel information
    if ((info = call_flow_info(ui))) {
        // Delete panel columns
        vector_destroy_items(info->columns);
        // Delete panel arrows
        vector_destroy_items(info->arrows);
        // Delete column links
        vector_destroy_items(info->column_links);
        // Delete panel windows
        delwin(info->flow_win);
        delwin(info->raw_win);
        // Delete displayed call group
        call_group_destroy(info->group);
        // Free panel info
        free(info);
    }
    ui_panel_destroy(ui);
}

call_flow_info_t *
call_flow_info(ui_t *ui)
{
    return (call_flow_info_t*) panel_userptr(ui->panel);
}

bool
call_flow_redraw(ui_t *ui)
{
    int maxx, maxy;

    // Get panel information
    call_flow_info_t *info = call_flow_info(ui);
    // Get current screen dimensions
    getmaxyx(stdscr, maxy, maxx);

    // Change the main window size
    wresize(ui->win, maxy, maxx);

    // Store new size
    ui->width = maxx;
    ui->height = maxy;

    // Recalculate flow window under the header area
    call_flow_layout_flow_win(ui, info);

    // Force flow redraw
    call_flow_draw(ui);

    // Check if any of the group has changed
    // return call_group_has_changed(info->group);
    return 0;
}

int
call_flow_draw(ui_t *ui)
{
    char title[256];

    // Get panel information
    call_flow_info_t *info = call_flow_info(ui);

    // Get window of main panel
    werase(ui->win);

    // Set title
    if (info->group->callid) {
        sprintf(title, "Extended Call flow for %.125s", info->group->callid);
    } else if (call_group_count(info->group) == 1) {
        sip_call_t *call = call_group_get_next(info->group, NULL);
        sprintf(title, "Call flow for %.125s", call->callid);
    } else {
        sprintf(title, "Call flow for %d dialogs", call_group_count(info->group));
    }

    // Print color mode in title
    if (setting_has_value(SETTING_COLORMODE, "request"))
        strcat(title, " (Color by Request/Response)");
    if (setting_has_value(SETTING_COLORMODE, "callid"))
        strcat(title, " (Color by Call-Id)");
    if (setting_has_value(SETTING_COLORMODE, "cseq"))
        strcat(title, " (Color by CSeq)");

    // Draw panel title
    ui_set_title(ui, title);

    // Show some keybinding
    call_flow_draw_footer(ui);

    // Redraw columns
    call_flow_draw_columns(ui);

    // Redraw arrows
    call_flow_draw_arrows(ui);

    // Redraw preview
    call_flow_draw_preview(ui);

    // Draw the scrollbar
    vector_iter_t it = vector_iterator(info->darrows);
    call_flow_arrow_t *arrow = NULL;
    info->scroll.max = info->scroll.pos = 0;
    while ((arrow = vector_iterator_next(&it))) {
        // Store current position arrow
        if (vector_iterator_current(&it) == info->first_arrow) {
            info->scroll.pos = info->scroll.max;
        }
        info->scroll.max += call_flow_arrow_height(ui, arrow);
    }
    ui_scrollbar_draw(info->scroll);

    // Redraw flow win
    wnoutrefresh(info->flow_win);
    return 0;
}

void
call_flow_draw_footer(ui_t *ui)
{
    const char *keybindings[] = {
        key_action_key_str(ACTION_PREV_SCREEN), "Calls List",
        key_action_key_str(ACTION_CONFIRM), "Raw",
        key_action_key_str(ACTION_SELECT), "Compare",
        key_action_key_str(ACTION_SHOW_HELP), "Help",
        key_action_key_str(ACTION_SDP_INFO), "SDP",
        key_action_key_str(ACTION_TOGGLE_MEDIA), "RTP",
        key_action_key_str(ACTION_SHOW_FLOW_EX), "Extended",
        key_action_key_str(ACTION_COMPRESS), "Compressed",
        key_action_key_str(ACTION_LINK_COLUMNS), "Link",
        key_action_key_str(ACTION_TOGGLE_PROTOCOL), "Proto",
        key_action_key_str(ACTION_SHOW_RAW), "Raw",
        key_action_key_str(ACTION_CYCLE_COLOR), "Colour by",
        key_action_key_str(ACTION_INCREASE_RAW), "Increase Raw"
    };

    ui_draw_bindings(ui, keybindings, 26);
}

int
call_flow_draw_columns(ui_t *ui)
{
    call_flow_info_t *info;
    call_flow_column_t *column;
    sip_call_t *call = NULL;
    rtp_stream_t *stream;
    sip_msg_t *msg = NULL;
    vector_iter_t streams;
    vector_iter_t columns;
    char coltext[MAX_SETTING_LEN];
    address_t addr;

    // Get panel information
    info = call_flow_info(ui);

    // In extended call flow, columns can have multiple call-ids
    if (info->group->callid) {
        info->maxcallids = call_group_count(info->group);
    } else {
        info->maxcallids = 2;
    }

    // Load columns
    while((msg = call_group_get_next_msg(info->group, msg))) {
        call_flow_column_add(ui, msg->call->callid, msg->packet->src, msg->packet->type);
        call_flow_column_add(ui, msg->call->callid, msg->packet->dst, msg->packet->type);
    }

    // Add RTP columns FIXME Really
    if (!setting_disabled(SETTING_CF_MEDIA)) {
        while ((call = call_group_get_next(info->group, call)) ) {
            streams = vector_iterator(call->streams);

            while ((stream = vector_iterator_next(&streams))) {
                if (stream->type == PACKET_RTP && stream_get_count(stream)) {
                    addr = stream->src;
                    addr.port = 0;
                    call_flow_column_add(ui, NULL, addr, PACKET_RTP);
                    addr = stream->dst;
                    addr.port = 0;
                    call_flow_column_add(ui, NULL, addr, PACKET_RTP);
                }
            }
        }
    }

    // Draw columns
    if (setting_has_value(SETTING_CF_SPLITCALLID, "linked"))
        call_flow_apply_suggested_links(info);
    call_flow_columns_assign_disppos(info);

    /* Determine how many stacked address rows the tallest linked column needs */
    info->header_rows = 1;
    columns = vector_iterator(info->columns);
    while ((column = vector_iterator_next(&columns))) {
        char lines[CF_LINK_MAX_IPS][MAX_SETTING_LEN];
        int rows;

        if (call_flow_disppos_count(info, column->disppos) <= 1)
            continue;
        rows = call_flow_linked_header_lines(info, column->disppos, lines, CF_LINK_MAX_IPS);
        if (rows > info->header_rows)
            info->header_rows = rows;
    }
    call_flow_layout_flow_win(ui, info);

    columns = vector_iterator(info->columns);
    while ((column = vector_iterator_next(&columns))) {
        int linked;
        int sep_line;
        int label_base;
        int vline_x;

        // Only draw one vertical line / header per display position
        if (column->colpos > 0) {
            call_flow_column_t *prev;
            int skip = 0;
            vector_iter_t check = vector_iterator(info->columns);
            while ((prev = vector_iterator_next(&check))) {
                if (prev->colpos >= column->colpos)
                    break;
                if (prev->disppos == column->disppos) {
                    skip = 1;
                    break;
                }
            }
            if (skip)
                continue;
        }

        linked = call_flow_disppos_count(info, column->disppos) > 1;
        sep_line = 2 + info->header_rows;
        label_base = sep_line - info->header_rows;
        vline_x = 20 + 30 * column->disppos;

        call_flow_draw_column_vline(info->flow_win, 0, vline_x,
                                    getmaxy(info->flow_win), linked);

        // Set bold to this address if it's local
        if (setting_enabled(SETTING_CF_LOCALHIGHLIGHT)) {
            if (address_is_local(column->addr))
                wattron(ui->win, A_BOLD);
        }

        if (linked) {
            char lines[CF_LINK_MAX_IPS][MAX_SETTING_LEN];
            int rows = call_flow_linked_header_lines(info, column->disppos, lines, CF_LINK_MAX_IPS);
            int row;
            int max_len = 0;
            int sep_width, sep_x;

            /* Bottom-align stacked labels, each centered on the column guide */
            for (row = 0; row < rows; row++) {
                int len = (int) strlen(lines[row]);
                if (len > max_len)
                    max_len = len;
                call_flow_print_centered_label(ui->win, sep_line - rows + row,
                                               vline_x, lines[row]);
            }

            sep_width = max_len > CF_COL_SEP_WIDTH ? max_len : CF_COL_SEP_WIDTH;
            if (sep_width % 2 == 0)
                sep_width++; /* keep an odd width so the tee sits on center */
            sep_x = vline_x - sep_width / 2;
            if (sep_x < 0) {
                sep_width += sep_x;
                sep_x = 0;
            }
            mvwhline(ui->win, sep_line, sep_x, ACS_HLINE, sep_width);
            mvwprintw(ui->win, sep_line, vline_x, "╥");
        } else {
            int sep_x = vline_x - CF_COL_SEP_WIDTH / 2;

            call_flow_column_label(column, coltext, sizeof(coltext));
            call_flow_print_centered_label(ui->win, label_base + info->header_rows - 1,
                                           vline_x, coltext);
            mvwhline(ui->win, sep_line, sep_x, ACS_HLINE, CF_COL_SEP_WIDTH);
            mvwaddch(ui->win, sep_line, vline_x, ACS_TTEE);
        }
        wattroff(ui->win, A_BOLD);
    }

    return 0;
}

void
call_flow_draw_arrows(ui_t *ui)
{
    call_flow_info_t *info;
    call_flow_arrow_t *arrow = NULL;
    int cline = 0;

    // Get panel information
    info = call_flow_info(ui);

    // Create pending SIP arrows
    sip_msg_t *msg = NULL;
    while ((msg = call_group_get_next_msg(info->group, msg))) {
        if (!call_flow_arrow_find(ui, msg)) {
            arrow = call_flow_arrow_create(ui, msg, CF_ARROW_SIP);
            vector_append(info->arrows, arrow);
        }
    }
    // Create pending RTP arrows
    rtp_stream_t *stream = NULL;
    while ((stream = call_group_get_next_stream(info->group, stream))) {
        if(stream->telephone_event && setting_enabled(SETTING_TELEPHONE_EVENT)) {
            vector_iter_t it = vector_iterator(stream->events);
            rtp_event_t *event = NULL;
            while ((event = vector_iterator_next(&it))) {
                if (!call_flow_arrow_find(ui, event)) {
                    arrow = call_flow_arrow_create(ui, event, CF_ARROW_EVENT);
                    vector_append(info->arrows, arrow);
                }
            }
        } else {
            if (!call_flow_arrow_find(ui, stream)) {
                arrow = call_flow_arrow_create(ui, stream, CF_ARROW_RTP);
                vector_append(info->arrows, arrow);
            }
        }
    }

    // Copy displayed arrows
    // vector_destroy(info->darrows);
    //info->darrows = vector_copy_if(info->arrows, call_flow_arrow_filter);
    info->darrows = info->arrows;

    // If no active call, use the fist one (if exists)
    if (info->cur_arrow == -1 && vector_count(info->darrows)) {
        info->cur_arrow = info->first_arrow = 0;
    }

    // Draw arrows
    vector_iter_t it = vector_iterator(info->darrows);
    vector_iterator_set_current(&it, info->first_arrow - 1);
    vector_iterator_set_filter(&it, call_flow_arrow_filter);
    while ((arrow = vector_iterator_next(&it))) {
        // Stop if we have reached the bottom of the screen
        if (cline >= getmaxy(info->flow_win))
            break;
        // Draw arrow
        cline += call_flow_draw_arrow(ui, arrow, cline);
    }
}

int
call_flow_draw_arrow(ui_t *ui, call_flow_arrow_t *arrow, int line)
{
    if (arrow->type == CF_ARROW_SIP) {
        return call_flow_draw_message(ui, arrow, line);
    } else if (arrow->type == CF_ARROW_EVENT) {
        return call_flow_draw_event(ui, arrow, line);
    } else {
        return call_flow_draw_rtp_stream(ui, arrow, line);
    }
}

void
call_flow_draw_preview(ui_t *ui)
{
    call_flow_arrow_t *arrow = NULL;
    call_flow_info_t *info;

    // Check if not displaying raw has been requested
    if (setting_disabled(SETTING_CF_FORCERAW))
        return;

    // Get panel information
    info = call_flow_info(ui);

    // Draw current arrow preview
    if ((arrow = vector_item(info->darrows, info->cur_arrow))) {
        if (arrow->type == CF_ARROW_SIP) {
            call_flow_draw_raw(ui, arrow->item);
        } else if (arrow->type == CF_ARROW_EVENT) {
            call_flow_draw_raw_event(ui, arrow->item);
        } else {
            call_flow_draw_raw_rtcp(ui, arrow->item);
        }
    }
}

int
call_flow_draw_message(ui_t *ui, call_flow_arrow_t *arrow, int cline)
{
    call_flow_info_t *info;
    WINDOW *flow_win;
    sdp_media_t *media;
    const char *callid;
    char msg_method[SIP_ATTR_MAXLEN];
    char msg_time[80];
    address_t src;
    address_t dst;
    char method[METHOD_MAXLEN + 1];
    char delta[25] = "";
    int flowh;
    char mediastr[40];
    sip_msg_t *msg = arrow->item;
    vector_iter_t medias;
    int color = 0;
    int msglen;
    int aline = cline + 1;

    // Initialize method
    memset(method, 0, sizeof(method));

    // Get panel information
    info = call_flow_info(ui);

    // Get the messages window
    flow_win = info->flow_win;
    flowh = getmaxx(flow_win);

    // Store arrow start line
    arrow->line = cline;

    // Calculate how many lines this message requires
    arrow->height = call_flow_arrow_height(ui, arrow);

    // Check this message fits on the panel
    if (cline > flowh + arrow->height)
        return 0;

    // For extended, use xcallid nstead
    callid = msg->call->callid;
    src = msg->packet->src;
    dst = msg->packet->dst;
    media = vector_first(msg->medias);
    msg_get_attribute(msg, SIP_ATTR_METHOD, msg_method);
    timeval_to_time(msg_get_time(msg), msg_time);

    // Get Message method (include extra info)
    snprintf(method, METHOD_MAXLEN, "%.*s", METHOD_MAXLEN-1, msg_method);

    // If message has sdp information
    if (msg_has_sdp(msg) && setting_has_value(SETTING_CF_SDP_INFO, "off")) {
        // Show sdp tag in title
        snprintf(method, METHOD_MAXLEN, "%.*s (SDP)", METHOD_MAXLEN-7, msg_method );
    }

    // If message has sdp information
    if (setting_has_value(SETTING_CF_SDP_INFO, "compressed")) {
        // Show sdp tag in title
        if (msg_has_sdp(msg)) {
            snprintf(method, METHOD_MAXLEN, "%.*s (SDP)", 12, msg_method);
        } else {
            snprintf(method, METHOD_MAXLEN, "%.*s", 17, msg_method);
        }
    }

    if (msg_has_sdp(msg) && setting_has_value(SETTING_CF_SDP_INFO, "first")) {
        snprintf(method, METHOD_MAXLEN, "%.3s (%s:%u)",
		 msg_method,
		 media->address.ip,
		 media->address.port);
    }

    if (msg_has_sdp(msg) && setting_has_value(SETTING_CF_SDP_INFO, "full")) {
        snprintf(method, METHOD_MAXLEN, "%.3s (%s)", msg_method, media->address.ip);
    }

    // Draw message type or status and line
    msglen = (strlen(method) > 24) ? 24 : strlen(method);

    // Get origin and destination column
    arrow->scolumn = call_flow_column_get(ui, callid, src);
    arrow->dcolumn = call_flow_column_get(ui, callid, dst);

    // Determine start and end position of the arrow line
    int startpos, endpos;
    if (arrow->scolumn->disppos == arrow->dcolumn->disppos) {
        arrow->dir = CF_ARROW_SPIRAL;
        startpos = 19 + 30 * arrow->dcolumn->disppos;
        endpos = 20 + 30 * arrow->scolumn->disppos;
    } else if (arrow->scolumn->disppos < arrow->dcolumn->disppos) {
        arrow->dir = CF_ARROW_RIGHT;
        startpos = 20 + 30 * arrow->scolumn->disppos;
        endpos = 20 + 30 * arrow->dcolumn->disppos;
    } else {
        arrow->dir = CF_ARROW_LEFT;
        startpos = 20 + 30 * arrow->dcolumn->disppos;
        endpos = 20 + 30 * arrow->scolumn->disppos;
    }
    int distance = abs(endpos - startpos) - 3;

    // Highlight current message
    int bright = 0;
    if (arrow == vector_item(info->darrows, info->cur_arrow)) {
        bright = 1;
        if (setting_has_value(SETTING_CF_HIGHTLIGHT, "reverse")) {
            wattron(flow_win, A_REVERSE);
        }
        if (setting_has_value(SETTING_CF_HIGHTLIGHT, "bold")) {
            wattron(flow_win, A_BOLD);
        }
        if (setting_has_value(SETTING_CF_HIGHTLIGHT, "reversebold")) {
            wattron(flow_win, A_REVERSE);
            wattron(flow_win, A_BOLD);
        }
    }

    // Color the message {
    if (setting_has_value(SETTING_COLORMODE, "request")) {
        // Color by request / response
        color = (msg_is_request(msg)) ? CP_RED_ON_DEF : CP_GREEN_ON_DEF;
    } else if (setting_has_value(SETTING_COLORMODE, "callid")) {
        // Color by call-id
        color = call_group_color(info->group, msg->call);
    } else if (setting_has_value(SETTING_COLORMODE, "cseq")) {
        // Color by CSeq within the same call
        color = msg->cseq % 7 + 1;
    }

    // Print arrow in the same line than message
    if (setting_has_value(SETTING_CF_SDP_INFO, "compressed")) {
        aline = cline;
    }

    // Turn on the message color
    wattron(flow_win, COLOR_PAIR(color));

    // Clear the line
    mvwprintw(flow_win, cline, startpos + 2, "%*s", distance, "");

    // Draw method
    if (arrow->dir == CF_ARROW_SPIRAL) {
        mvwprintw(flow_win, cline, startpos + 5, "%.26s", method);
    } else {
        mvwprintw(flow_win, cline, startpos + distance / 2 - msglen / 2 + 2, "%.26s", method);
    }

    // Draw media information
    if (msg_has_sdp(msg) && setting_has_value(SETTING_CF_SDP_INFO, "full")) {
        medias = vector_iterator(msg->medias);
        while ((media = vector_iterator_next(&medias))) {
            sprintf(mediastr, "%s %d (%s)",
                    media->type,
                    media->address.port,
                    media_get_prefered_format(media));
            if (arrow->dir == CF_ARROW_SPIRAL) {
                mvwprintw(flow_win, cline + 1, startpos + 5, "%s", mediastr);
            } else {
                mvwprintw(flow_win, cline + 1, startpos + distance / 2 - strlen(mediastr) / 2 + 2, "%s", mediastr);
            }
            cline++;
            aline++;
        }
    }

    if (arrow->dir != CF_ARROW_SPIRAL) {
        if (arrow == call_flow_arrow_selected(ui)) {
            mvwhline(flow_win, aline, startpos + 2, '=', distance);
        } else {
            mvwhline(flow_win, aline, startpos + 2, ACS_HLINE, distance);
        }
    }

    // Write the arrow at the end of the message (two arrows if this is a retrans)
    if (arrow->dir == CF_ARROW_SPIRAL) {
        mvwaddch(flow_win, aline, startpos + 2, '<');
        if (msg->retrans) {
            mvwaddch(flow_win, aline, startpos + 3, '<');
            mvwaddch(flow_win, aline, startpos + 4, '<');
        }
        // If multiple lines are available, print a spiral icon
        if (aline != cline) {
            mvwaddch(flow_win, aline, startpos + 3, ACS_LRCORNER);
            mvwaddch(flow_win, aline - 1, startpos + 3, ACS_URCORNER);
            mvwaddch(flow_win, aline - 1, startpos + 2, ACS_HLINE);
        }
        call_flow_print_protocol_label(flow_win, aline, startpos + (msg->retrans ? 5 : 3),
                                       msg->packet->type, color, bright);
    } else if (arrow->dir == CF_ARROW_RIGHT) {
        if (setting_enabled(SETTING_CF_PROTOCOL)) {
            const char *proto = call_flow_transport_str(msg->packet->type);
            if (proto[0]) {
                int plen = (int) strlen(proto) + 2;
                int tip = msg->retrans ? 4 : 2;
                if (endpos - tip - plen > startpos + 2)
                    call_flow_print_protocol_label(flow_win, aline, endpos - tip - plen,
                                                   msg->packet->type, color, bright);
            }
        }
        mvwaddch(flow_win, aline, endpos - 2, '>');
        if (msg->retrans) {
            mvwaddch(flow_win, aline, endpos - 3, '>');
            mvwaddch(flow_win, aline, endpos - 4, '>');
        }
    } else {
        mvwaddch(flow_win, aline, startpos + 2, '<');
        if (msg->retrans) {
            mvwaddch(flow_win, aline, startpos + 3, '<');
            mvwaddch(flow_win, aline, startpos + 4, '<');
        }
        if (setting_enabled(SETTING_CF_PROTOCOL)) {
            const char *proto = call_flow_transport_str(msg->packet->type);
            if (proto[0]) {
                int tip = msg->retrans ? 5 : 3;
                if (startpos + tip + (int) strlen(proto) + 2 < endpos - 2)
                    call_flow_print_protocol_label(flow_win, aline, startpos + tip,
                                                   msg->packet->type, color, bright);
            }
        }
    }

    if (setting_has_value(SETTING_CF_SDP_INFO, "compressed"))
        mvwprintw(flow_win, cline, startpos + distance / 2 - msglen / 2 + 2, " %.26s ", method);

    // Turn off colors
    wattroff(flow_win, COLOR_PAIR(CP_RED_ON_DEF));
    wattroff(flow_win, COLOR_PAIR(CP_GREEN_ON_DEF));
    wattroff(flow_win, COLOR_PAIR(CP_CYAN_ON_DEF));
    wattroff(flow_win, COLOR_PAIR(CP_YELLOW_ON_DEF));
    wattroff(flow_win, A_BOLD | A_REVERSE);

    // Print timestamp
    if (info->arrowtime) {
        if (arrow == call_flow_arrow_selected(ui))
            wattron(flow_win, COLOR_PAIR(CP_CYAN_ON_DEF));

        if (arrow == vector_item(info->darrows, info->cur_arrow)) {
            wattron(flow_win, A_BOLD);
            mvwprintw(flow_win, cline, 2, "%s", msg_time);
            wattroff(flow_win, A_BOLD);
        } else {
            mvwprintw(flow_win, cline, 2, "%s", msg_time);
        }

        // Print delta from selected message
        if (!setting_has_value(SETTING_CF_SDP_INFO, "compressed")) {
            if (info->selected == -1) {
                if (setting_enabled(SETTING_CF_DELTA)) {
                    struct timeval selts, curts;
                    selts = msg_get_time(call_group_get_prev_msg(info->group, msg));
                    curts = msg_get_time(msg);
                    timeval_to_delta(selts, curts, delta);
                }
            } else if (arrow == vector_item(info->darrows, info->cur_arrow)) {
                struct timeval selts, curts;
                selts = msg_get_time(call_flow_arrow_message(call_flow_arrow_selected(ui)));
                curts = msg_get_time(msg);
                timeval_to_delta(selts, curts, delta);
            }

            if (strlen(delta)) {
                wattron(flow_win, COLOR_PAIR(CP_CYAN_ON_DEF));
                mvwprintw(flow_win, cline - 1 , 2, "%15s", delta);
            }
            wattroff(flow_win, COLOR_PAIR(CP_CYAN_ON_DEF));
        }
    }
    wattroff(flow_win, COLOR_PAIR(CP_CYAN_ON_DEF));

    return arrow->height;
}


int
call_flow_draw_rtp_stream(ui_t *ui, call_flow_arrow_t *arrow, int cline)
{
    call_flow_info_t *info;
    WINDOW *win;
    char text[50], time[20];
    int height;
    rtp_stream_t *stream = arrow->item;
    sip_msg_t *msg;
    sip_call_t *call;
    call_flow_arrow_t *msgarrow;
    address_t addr;

    // Get panel information
    info = call_flow_info(ui);
    // Get the messages window
    win = info->flow_win;
    height = getmaxy(win);

    // Store arrow start line
    arrow->line = cline;

    // Calculate how many lines this message requires
    arrow->height = call_flow_arrow_height(ui, arrow);

    // Check this media fits on the panel
    if (cline > height + arrow->height)
        return 0;

    // Get arrow text
    sprintf(text, "RTP (%s) %d", stream_get_format(stream), stream_get_count(stream));

    // Get message data
    call = stream->media->msg->call;

    /**
     * This logic will try to use the same columns for the stream representation
     * that are used in the SIP messages that configured the streams in their SDP
     * if they share the same IP addresses.
     */
    // Message with Stream destination configured in SDP content
    msg = stream->media->msg;

    // If message and stream share the same IP address
    if (address_equals(msg->packet->src, stream->dst)) {
        // Reuse the msg arrow columns as destination column
        if ((msgarrow = call_flow_arrow_find(ui, msg))) {
            // Get origin and destination column
            arrow->dcolumn = call_flow_column_get(ui, msg->call->callid, msg->packet->src);
        }
    }

    // fallback: Just use any column that have the destination IP printed
    if (!arrow->dcolumn) {
        // FIXME figure a better way to find ignoring port :(
        addr = stream->dst; addr.port = 0;
        arrow->dcolumn = call_flow_column_get(ui, 0, addr);
    }

    /**
     * For source address of the stream, first try to find a message that have
     * the stream source configured in their SDP as destination and then apply
     * the same previous logic address: if IP address matches, reuse message
     * column, othwerise any column with the source IP will be used.
     */
    // Message with Stream source configured in SDP content
    msg = call_msg_with_media(call, stream->src);

    // Try to find a message with configured SDP matching the source of this stream
    if (msg && address_equals(msg->packet->src, stream->src)) {
        // Reuse the msg arrow columns as destination column
        if ((msgarrow = call_flow_arrow_find(ui, msg))) {
            // Get origin and destination column
            arrow->scolumn = call_flow_column_get(ui, msg->call->callid, msg->packet->src);
        }
    }

    // Prefer message that configured this stream rather than any column
    if (!arrow->scolumn) {
        msg = stream->media->msg;
        // If message and stream share the same IP address
        if (address_equals(msg->packet->dst, stream->src)) {
            // Reuse the msg arrow columns as destination column
            if ((msgarrow = call_flow_arrow_find(ui, msg))) {
                arrow->scolumn = call_flow_column_get(ui, msg->call->callid, msg->packet->dst);
            }
        }
    }

    // fallback: Just use any column that have the soruce IP printed
    if (!arrow->scolumn) {
        // FIXME figure a better way to find ignoring port :(
        addr = stream->src; addr.port = 0;
        arrow->scolumn = call_flow_column_get(ui, 0, addr);
    }

    // Determine start and end position of the arrow line
    int startpos, endpos;
    if (arrow->scolumn->disppos < arrow->dcolumn->disppos) {
        arrow->dir= CF_ARROW_RIGHT;
        startpos = 20 + 30 * arrow->scolumn->disppos;
        endpos = 20 + 30 * arrow->dcolumn->disppos;
    } else {
        arrow->dir = CF_ARROW_LEFT;
        startpos = 20 + 30 * arrow->dcolumn->disppos;
        endpos = 20 + 30 * arrow->scolumn->disppos;
    }
    int distance = 0;

    if (startpos != endpos) {
        // In compressed mode, we display the src and dst port inside the arrow
        // so fixup the stard and end position
        if (!setting_has_value(SETTING_CF_SDP_INFO, "compressed")) {
            startpos += 5;
            endpos -= 5;
        }
        distance = abs(endpos - startpos) - 4 + 1;
    } else {
        // Fix port positions
        startpos -= 2;
        endpos += 2;
        distance = 1;

        // Fix arrow direction based on ports
        if (stream->src.port < stream->dst.port) {
            arrow->dir = CF_ARROW_RIGHT;
        } else {
            arrow->dir = CF_ARROW_LEFT;
        }
    }

    // Highlight current message
    if (arrow == vector_item(info->darrows, info->cur_arrow)) {
        if (setting_has_value(SETTING_CF_HIGHTLIGHT, "reverse")) {
            wattron(win, A_REVERSE);
        }
        if (setting_has_value(SETTING_CF_HIGHTLIGHT, "bold")) {
            wattron(win, A_BOLD);
        }
        if (setting_has_value(SETTING_CF_HIGHTLIGHT, "reversebold")) {
            wattron(win, A_REVERSE);
            wattron(win, A_BOLD);
        }
    }

    // Check if displayed stream is active
    int active = stream_is_active(stream);

    // Clear the line
    mvwprintw(win, cline, startpos + 2, "%*s", distance, "");
    // Draw RTP arrow text
    mvwprintw(win, cline, startpos + (distance) / 2 - strlen(text) / 2 + 2, "%s", text);

    if (!setting_has_value(SETTING_CF_SDP_INFO, "compressed"))
        cline++;

    // Draw line between columns
    if (active)
        mvwhline(win, cline, startpos + 2, '-', distance);
    else
        mvwhline(win, cline, startpos + 2, ACS_HLINE, distance);

    // Write the arrow at the end of the message (two arrows if this is a retrans)
    if (arrow->dir == CF_ARROW_RIGHT) {
        if (!setting_has_value(SETTING_CF_SDP_INFO, "compressed")) {
            mvwprintw(win, cline, startpos - 4, "%d", stream->src.port);
            mvwprintw(win, cline, endpos, "%d", stream->dst.port);
        }
        mvwaddch(win, cline, endpos - 2, '>');
        if (active) {
            arrow->rtp_count = stream_get_count(stream);
            arrow->rtp_ind_pos = (arrow->rtp_ind_pos + 1) % distance;
            mvwaddch(win, cline, startpos + arrow->rtp_ind_pos + 2, '>');
        }
    } else {
        if (!setting_has_value(SETTING_CF_SDP_INFO, "compressed")) {
            mvwprintw(win, cline, endpos, "%d", stream->src.port);
            mvwprintw(win, cline, startpos - 4, "%d", stream->dst.port);
        }
        mvwaddch(win, cline, startpos + 2, '<');
        if (active) {
            arrow->rtp_count = stream_get_count(stream);
            arrow->rtp_ind_pos = (arrow->rtp_ind_pos + 1) % distance;
            mvwaddch(win, cline, endpos - arrow->rtp_ind_pos - 2, '<');
        }
    }

    if (setting_has_value(SETTING_CF_SDP_INFO, "compressed"))
        mvwprintw(win, cline, startpos + (distance) / 2 - strlen(text) / 2 + 2, " %s ", text);

    wattroff(win, A_BOLD | A_REVERSE);

    // Print timestamp
    if (info->arrowtime) {
        timeval_to_time(stream->time, time);
        if (arrow == vector_item(info->darrows, info->cur_arrow)) {
            wattron(win, A_BOLD);
            mvwprintw(win, cline, 2, "%s", time);
            wattroff(win, A_BOLD);
        } else {
            mvwprintw(win, cline, 2, "%s", time);
        }

    }

    return arrow->height;
}

int
call_flow_draw_event(ui_t *ui, call_flow_arrow_t *arrow, int cline)
{
    call_flow_info_t *info;
    WINDOW *win;
    char text[50], time[20];
    int height;
    rtp_event_t *event = arrow->item;
    rtp_stream_t *stream = event->stream;
    sip_msg_t *msg;
    sip_call_t *call;
    call_flow_arrow_t *msgarrow;
    address_t addr;
    packet_t *packet = NULL;

    // Get panel information
    info = call_flow_info(ui);
    // Get the messages window
    win = info->flow_win;
    height = getmaxy(win);

    // Store arrow start line
    arrow->line = cline;

    // Calculate how many lines this message requires
    arrow->height = call_flow_arrow_height(ui, arrow);

    // Check this media fits on the panel
    if (cline > height + arrow->height)
        return 0;

    if (event->error == TELEPHONE_EVENT_SHORT) {
        sprintf(text, "TelEvt (pkt too short)");
    } else if (event->error == TELEPHONE_EVENT_WRONG_VERSION) {
        sprintf(text, "TelEvt (wrong RTP version)");
    } else if (event->error == TELEPHONE_EVENT_UNKNOWN) {
        sprintf(text, "TelEvt (unknown)");
    } else if (event->end) {
        sprintf(text, "TelEvt DTMF:%c (end)", event->dtmf);
    } else {
        sprintf(text, "TelEvt DTMF:%c", event->dtmf);
    }

    // Get message data
    call = stream->media->msg->call;

    /**
     * This logic will try to use the same columns for the stream representation
     * that are used in the SIP messages that configured the streams in their SDP
     * if they share the same IP addresses.
     */
    // Message with Stream destination configured in SDP content
    msg = stream->media->msg;

    // If message and stream share the same IP address
    if (address_equals(msg->packet->src, stream->dst)) {
        // Reuse the msg arrow columns as destination column
        if ((msgarrow = call_flow_arrow_find(ui, msg))) {
            // Get origin and destination column
            arrow->dcolumn = call_flow_column_get(ui, msg->call->callid, msg->packet->src);
        }
    }

    // fallback: Just use any column that have the destination IP printed
    if (!arrow->dcolumn) {
        // FIXME figure a better way to find ignoring port :(
        addr = stream->dst; addr.port = 0;
        arrow->dcolumn = call_flow_column_get(ui, 0, addr);
    }

    /**
     * For source address of the stream, first try to find a message that have
     * the stream source configured in their SDP as destination and then apply
     * the same previous logic address: if IP address matches, reuse message
     * column, othwerise any column with the source IP will be used.
     */
    // Message with Stream source configured in SDP content
    msg = call_msg_with_media(call, stream->src);

    // Try to find a message with configured SDP matching the source of this stream
    if (msg && address_equals(msg->packet->src, stream->src)) {
        // Reuse the msg arrow columns as destination column
        if ((msgarrow = call_flow_arrow_find(ui, msg))) {
            // Get origin and destination column
            arrow->scolumn = call_flow_column_get(ui, msg->call->callid, msg->packet->src);
        }
    }

    // Prefer message that configured this stream rather than any column
    if (!arrow->scolumn) {
        msg = stream->media->msg;
        // If message and stream share the same IP address
        if (address_equals(msg->packet->dst, stream->src)) {
            // Reuse the msg arrow columns as destination column
            if ((msgarrow = call_flow_arrow_find(ui, msg))) {
                arrow->scolumn = call_flow_column_get(ui, msg->call->callid, msg->packet->dst);
            }
        }
    }

    // fallback: Just use any column that have the soruce IP printed
    if (!arrow->scolumn) {
        // FIXME figure a better way to find ignoring port :(
        addr = stream->src; addr.port = 0;
        arrow->scolumn = call_flow_column_get(ui, 0, addr);
    }

    // Determine start and end position of the arrow line
    int startpos, endpos;
    if (arrow->scolumn->disppos < arrow->dcolumn->disppos) {
        arrow->dir= CF_ARROW_RIGHT;
        startpos = 20 + 30 * arrow->scolumn->disppos;
        endpos = 20 + 30 * arrow->dcolumn->disppos;
    } else {
        arrow->dir = CF_ARROW_LEFT;
        startpos = 20 + 30 * arrow->dcolumn->disppos;
        endpos = 20 + 30 * arrow->scolumn->disppos;
    }
    int distance = 0;

    if (startpos != endpos) {
        // In compressed mode, we display the src and dst port inside the arrow
        // so fixup the stard and end position
        if (!setting_has_value(SETTING_CF_SDP_INFO, "compressed")) {
            startpos += 5;
            endpos -= 5;
        }
        distance = abs(endpos - startpos) - 4 + 1;
    } else {
        // Fix port positions
        startpos -= 2;
        endpos += 2;
        distance = 1;

        // Fix arrow direction based on ports
        if (stream->src.port < stream->dst.port) {
            arrow->dir = CF_ARROW_RIGHT;
        } else {
            arrow->dir = CF_ARROW_LEFT;
        }
    }

    // Highlight current message
    if (arrow == vector_item(info->darrows, info->cur_arrow)) {
        if (setting_has_value(SETTING_CF_HIGHTLIGHT, "reverse")) {
            wattron(win, A_REVERSE);
        }
        if (setting_has_value(SETTING_CF_HIGHTLIGHT, "bold")) {
            wattron(win, A_BOLD);
        }
        if (setting_has_value(SETTING_CF_HIGHTLIGHT, "reversebold")) {
            wattron(win, A_REVERSE);
            wattron(win, A_BOLD);
        }
    }

    // Check if displayed stream is active
    int active = 0;
    if(!packet) {
        active = stream_is_active(stream);
    }

    // Clear the line
    mvwprintw(win, cline, startpos + 2, "%*s", distance, "");
    // Draw RTP arrow text
    mvwprintw(win, cline, startpos + (distance) / 2 - strlen(text) / 2 + 2, "%s", text);

    if (!setting_has_value(SETTING_CF_SDP_INFO, "compressed"))
        cline++;

    // Draw line between columns
    if (active)
        mvwhline(win, cline, startpos + 2, '-', distance);
    else
        mvwhline(win, cline, startpos + 2, ACS_HLINE, distance);

    // Write the arrow at the end of the message (two arrows if this is a retrans)
    if (arrow->dir == CF_ARROW_RIGHT) {
        if (!setting_has_value(SETTING_CF_SDP_INFO, "compressed")) {
            mvwprintw(win, cline, startpos - 4, "%d", stream->src.port);
            mvwprintw(win, cline, endpos, "%d", stream->dst.port);
        }
        mvwaddch(win, cline, endpos - 2, '>');
        if (active) {
            arrow->rtp_count = stream_get_count(stream);
            arrow->rtp_ind_pos = (arrow->rtp_ind_pos + 1) % distance;
            mvwaddch(win, cline, startpos + arrow->rtp_ind_pos + 2, '>');
        }
    } else {
        if (!setting_has_value(SETTING_CF_SDP_INFO, "compressed")) {
            mvwprintw(win, cline, endpos, "%d", stream->src.port);
            mvwprintw(win, cline, startpos - 4, "%d", stream->dst.port);
        }
        mvwaddch(win, cline, startpos + 2, '<');
        if (active) {
            arrow->rtp_count = stream_get_count(stream);
            arrow->rtp_ind_pos = (arrow->rtp_ind_pos + 1) % distance;
            mvwaddch(win, cline, endpos - arrow->rtp_ind_pos - 2, '<');
        }
    }

    if (setting_has_value(SETTING_CF_SDP_INFO, "compressed"))
        mvwprintw(win, cline, startpos + (distance) / 2 - strlen(text) / 2 + 2, " %s ", text);

    wattroff(win, A_BOLD | A_REVERSE);

    // Print timestamp
    if (info->arrowtime) {
        timeval_to_time(event->time, time);
        if (arrow == vector_item(info->darrows, info->cur_arrow)) {
            wattron(win, A_BOLD);
            mvwprintw(win, cline, 2, "%s", time);
            wattroff(win, A_BOLD);
        } else {
            mvwprintw(win, cline, 2, "%s", time);
        }

    }

    return arrow->height;
}

call_flow_arrow_t *
call_flow_arrow_create(ui_t *ui, void *item, int type)
{
    call_flow_arrow_t *arrow;

    if ((arrow = call_flow_arrow_find(ui, item)))
        return arrow;

    // Create a new arrow of the given type
    arrow = malloc(sizeof(call_flow_arrow_t));
    memset(arrow, 0, sizeof(call_flow_arrow_t));
    arrow->type = type;
    arrow->item = item;
    return arrow;
}

int
call_flow_arrow_height(ui_t *ui, const call_flow_arrow_t *arrow)
{
    if (arrow->type == CF_ARROW_SIP) {
        if (setting_enabled(SETTING_CF_ONLYMEDIA))
            return 0;
        if (setting_has_value(SETTING_CF_SDP_INFO, "compressed"))
            return 1;
        if (!msg_has_sdp(arrow->item))
            return 2;
        if (setting_has_value(SETTING_CF_SDP_INFO, "off"))
            return 2;
        if (setting_has_value(SETTING_CF_SDP_INFO, "first"))
            return 2;
        if (setting_has_value(SETTING_CF_SDP_INFO, "full"))
            return msg_media_count(arrow->item) + 2;
    } else if (arrow->type == CF_ARROW_RTP || arrow->type == CF_ARROW_RTCP || arrow->type == CF_ARROW_EVENT) {
        if (setting_has_value(SETTING_CF_SDP_INFO, "compressed"))
            return 1;
        if (setting_disabled(SETTING_CF_MEDIA))
            return 0;
        return 2;
    }

    return 0;
}

call_flow_arrow_t *
call_flow_arrow_find(ui_t *ui, const void *data)
{
    call_flow_info_t *info;
    call_flow_arrow_t *arrow;
    vector_iter_t arrows;

    if (!data)
        return NULL;

    if (!(info = call_flow_info(ui)))
        return NULL;

    arrows = vector_iterator(info->arrows);
    while ((arrow = vector_iterator_next(&arrows)))
        if (arrow->item == data)
            return arrow;

    return arrow;
}

sip_msg_t *
call_flow_arrow_message(const  call_flow_arrow_t *arrow)
{
    if (!arrow)
        return NULL;

    if (arrow->type == CF_ARROW_SIP) {
        return arrow->item;
    }

    if (arrow->type == CF_ARROW_RTP) {
        rtp_stream_t *stream = arrow->item;
        return stream->media->msg;
    }

    if (arrow->type == CF_ARROW_EVENT) {
        rtp_stream_t *stream = arrow->stream;
        return stream->media->msg;
    }

    return NULL;
}

int
call_flow_draw_raw(ui_t *ui, sip_msg_t *msg)
{
    call_flow_info_t *info;
    WINDOW *raw_win;
    vector_iter_t arrows;
    call_flow_arrow_t *arrow;
    int raw_width, raw_height;
    int min_raw_width, fixed_raw_width;
    char header[256];

    // Get panel information
    if (!(info = call_flow_info(ui)))
        return 1;

    // Get min raw width
    min_raw_width = setting_get_intvalue(SETTING_CF_RAWMINWIDTH);
    fixed_raw_width = setting_get_intvalue(SETTING_CF_RAWFIXEDWIDTH);

    // Calculate the raw data width (width - used columns for flow - vertical lines)
    raw_width = ui->width - (30 * vector_count(info->columns)) - 2;

    // If last column has spirals, add an extra column with
    arrows = vector_iterator(info->arrows);
    while ((arrow = vector_iterator_next(&arrows))) {
        if (arrow->dir == CF_ARROW_SPIRAL
            && arrow->scolumn == vector_last(info->columns)) {
            raw_width -= 15;
            break;
        }
    }

    // We can define a mininum size for rawminwidth
    if (raw_width < min_raw_width) {
        raw_width = min_raw_width;
    }
    // We can configure an exact raw size
    if (fixed_raw_width > 0) {
        raw_width = fixed_raw_width;
    }

    // Height of raw window is always available size minus 6 lines for header/footer
    raw_height = ui->height - 3;

    // If we already have a raw window
    raw_win = info->raw_win;
    if (raw_win) {
        // Check it has the correct size
        if (getmaxx(raw_win) != raw_width) {
            // We need a new raw window
            delwin(raw_win);
            info->raw_win = raw_win = newwin(raw_height, raw_width, 0, 0);
        } else {
            // We have a valid raw win, clear its content
            werase(raw_win);
        }
    } else {
        // Create the raw window of required size
        info->raw_win = raw_win = newwin(raw_height, raw_width, 0, 0);
    }

    // Draw raw box li
    wattron(ui->win, COLOR_PAIR(CP_BLUE_ON_DEF));
    mvwvline(ui->win, 1, ui->width - raw_width - 2, ACS_VLINE, ui->height - 2);
    wattroff(ui->win, COLOR_PAIR(CP_BLUE_ON_DEF));

    // Print msg header (date/time/src -> dst, with protocol when enabled)
    wattron(raw_win, A_BOLD);
    mvwprintw(raw_win, 0, 0, "%s", sip_get_msg_header(msg, header, sizeof(header)));
    wattroff(raw_win, A_BOLD);

    // Print msg payload below the header
    draw_message_pos(info->raw_win, msg, 2);

    // Copy the raw_win contents into the panel
    copywin(raw_win, ui->win, 0, 0, 1, ui->width - raw_width - 1, raw_height, ui->width - 2, 0);

    return 0;
}


int
call_flow_draw_raw_event(ui_t *ui, rtp_event_t *event)
{
    call_flow_info_t *info;
    WINDOW *raw_win;
    int raw_width, raw_height;
    int min_raw_width, fixed_raw_width;

    if (!(info = call_flow_info(ui)))
        return 1;

    // Get min raw width
    min_raw_width = setting_get_intvalue(SETTING_CF_RAWMINWIDTH);
    fixed_raw_width = setting_get_intvalue(SETTING_CF_RAWFIXEDWIDTH);

    // Calculate the raw data width (width - used columns for flow - vertical lines)
    raw_width = ui->width - (30 * vector_count(info->columns)) - 2;
    // We can define a mininum size for rawminwidth
    if (raw_width < min_raw_width) {
        raw_width = min_raw_width;
    }
    // We can configure an exact raw size
    if (fixed_raw_width > 0) {
        raw_width = fixed_raw_width;
    }

    // Height of raw window is always available size minus 6 lines for header/footer
    raw_height = ui->height - 3;

    // If we already have a raw window
    raw_win = info->raw_win;
    if (raw_win) {
        // Check it has the correct size
        if (getmaxx(raw_win) != raw_width) {
            // We need a new raw window
            delwin(raw_win);
            info->raw_win = raw_win = newwin(raw_height, raw_width, 0, 0);
        } else {
            // We have a valid raw win, clear its content
            werase(raw_win);
        }
    } else {
        // Create the raw window of required size
        info->raw_win = raw_win = newwin(raw_height, raw_width, 0, 0);
    }

    // Draw raw box lines
    wattron(ui->win, COLOR_PAIR(CP_BLUE_ON_DEF));
    mvwvline(ui->win, 1, ui->width - raw_width - 2, ACS_VLINE, ui->height - 2);
    wattroff(ui->win, COLOR_PAIR(CP_BLUE_ON_DEF));

    mvwprintw(raw_win, 0, 0, "============ RFC4733 (telephone-event) Information ============");
    mvwprintw(raw_win, 2, 0, "DTMF: %c", event->dtmf);
    mvwprintw(raw_win, 3, 0, "End: %s", event->end ? "yes" : "no");
    mvwprintw(raw_win, 4, 0, "Volume: %d", event->volume);
    mvwprintw(raw_win, 5, 0, "Duration: %d", event->duration);

    // Copy the raw_win contents into the panel
    copywin(raw_win, ui->win, 0, 0, 1, ui->width - raw_width - 1, raw_height, ui->width - 2, 0);

    return 0;
}


int
call_flow_draw_raw_rtcp(ui_t *ui, rtp_stream_t *stream)
{
    call_flow_info_t *info;
    WINDOW *raw_win;
    int raw_width, raw_height;
    int min_raw_width, fixed_raw_width;
    rtp_stream_t *rtcp;
    rtp_stats_t *stats;
    uint32_t expected, lost, duration, clock;
    const char *format;
    float lostpct = 0, oospct = 0;
    int line = 0;

    // Get panel information
    if (!(info = call_flow_info(ui)))
        return 1;

    // Get min raw width
    min_raw_width = setting_get_intvalue(SETTING_CF_RAWMINWIDTH);
    fixed_raw_width = setting_get_intvalue(SETTING_CF_RAWFIXEDWIDTH);

    // Calculate the raw data width (width - used columns for flow - vertical lines)
    raw_width = ui->width - (30 * vector_count(info->columns)) - 2;
    // We can define a mininum size for rawminwidth
    if (raw_width < min_raw_width) {
        raw_width = min_raw_width;
    }
    // We can configure an exact raw size
    if (fixed_raw_width > 0) {
        raw_width = fixed_raw_width;
    }

    // Height of raw window is always available size minus 6 lines for header/footer
    raw_height = ui->height - 3;

    // If we already have a raw window
    raw_win = info->raw_win;
    if (raw_win) {
        // Check it has the correct size
        if (getmaxx(raw_win) != raw_width) {
            // We need a new raw window
            delwin(raw_win);
            info->raw_win = raw_win = newwin(raw_height, raw_width, 0, 0);
        } else {
            // We have a valid raw win, clear its content
            werase(raw_win);
        }
    } else {
        // Create the raw window of required size
        info->raw_win = raw_win = newwin(raw_height, raw_width, 0, 0);
    }

    // Draw raw box lines
    wattron(ui->win, COLOR_PAIR(CP_BLUE_ON_DEF));
    mvwvline(ui->win, 1, ui->width - raw_width - 2, ACS_VLINE, ui->height - 2);
    wattroff(ui->win, COLOR_PAIR(CP_BLUE_ON_DEF));

    stats = &stream->rtpstats;
    expected = stream_get_expected_count(stream);
    lost = stream_get_lost_count(stream);
    duration = stream_get_duration_ms(stream);
    clock = stream_get_clock_rate(stream);
    format = stream_get_format(stream);
    if (expected)
        lostpct = (float) lost * 100 / expected;
    if (stats->received)
        oospct = (float) stats->outoforder * 100 / stats->received;

    mvwprintw(raw_win, line++, 0, "============ RTP Stream Analysis ============");
    mvwprintw(raw_win, ++line, 0, "Source:      %s:%u", stream->src.ip, stream->src.port);
    mvwprintw(raw_win, ++line, 0, "Destination: %s:%u", stream->dst.ip, stream->dst.port);
    mvwprintw(raw_win, ++line, 0, "Codec:       %s", format ? format : "unknown");
    mvwprintw(raw_win, ++line, 0, "Payload:     %u", stats->payload_type);
    mvwprintw(raw_win, ++line, 0, "SSRC:        0x%08x", stats->ssrc);
    mvwprintw(raw_win, ++line, 0, "Clock rate:  %s", clock ? "" : "unknown");
    if (clock)
        mvwprintw(raw_win, line, 13, "%u Hz", clock);

    line++;
    mvwprintw(raw_win, ++line, 0, "Packets:     %u / %u", stats->received, expected);
    mvwprintw(raw_win, ++line, 0, "Lost:        %u (%.1f%%)", lost, lostpct);
    mvwprintw(raw_win, ++line, 0, "Out of seq:  %u (%.1f%%)", stats->outoforder, oospct);
    mvwprintw(raw_win, ++line, 0, "Duplicates:  %u", stats->duplicates);
    mvwprintw(raw_win, ++line, 0, "Timestamp err:%u", stats->wrong_timestamp);
    mvwprintw(raw_win, ++line, 0, "Max Delta:   %.2f ms", stats->max_delta);
    mvwprintw(raw_win, ++line, 0, "Mean Delta:  %.2f ms", stats->mean_delta);
    mvwprintw(raw_win, ++line, 0, "Max Jitter:  %.2f ms", stats->max_jitter);
    mvwprintw(raw_win, ++line, 0, "Min Jitter:  %.2f ms", stats->min_jitter);
    mvwprintw(raw_win, ++line, 0, "Mean Jitter: %.2f ms", stats->mean_jitter);
    mvwprintw(raw_win, ++line, 0, "Problems:    %s",
              (lost || stats->outoforder || stats->duplicates ||
               stats->wrong_timestamp) ? "Yes" : "No");
    mvwprintw(raw_win, ++line, 0, "Seq range:   %u -> %u", stats->first_seq, stats->last_seq);
    mvwprintw(raw_win, ++line, 0, "RTP ts:      %u -> %u", stats->first_ts, stats->last_ts);
    mvwprintw(raw_win, ++line, 0, "Excluded:    marker %u, CN %u, event %u",
              stats->marker, stats->comfort_noise, stats->telephone_event);
    mvwprintw(raw_win, ++line, 0, "Duration:    %u.%03u s", duration / 1000, duration % 1000);
    mvwprintw(raw_win, ++line, 0, "RFC jitter:  %.1f ts units", stats->jitter);
    if (clock)
        mvwprintw(raw_win, line, 30, "(%.3f ms)", stats->jitter_ms);
    mvwprintw(raw_win, ++line, 0, "Active:      %s", stream_is_active(stream) ? "yes" : "no");

    if ((rtcp = rtp_find_related_rtcp_stream(stream)) &&
        (rtcp->rtcpinfo.reported || rtcp->rtcpinfo.spc ||
         rtcp->rtcpinfo.flost || rtcp->rtcpinfo.fdiscard ||
         rtcp->rtcpinfo.mosl || rtcp->rtcpinfo.mosc)) {
        line += 2;
        mvwprintw(raw_win, line++, 0, "============ RTCP Information ============");
        mvwprintw(raw_win, ++line, 0, "Sender packets:      %u", rtcp->rtcpinfo.spc);
        mvwprintw(raw_win, ++line, 0, "Fraction lost:       %u / 256", rtcp->rtcpinfo.flost);
        if (rtcp->rtcpinfo.reported) {
            mvwprintw(raw_win, ++line, 0, "Cumulative lost:     %d", rtcp->rtcpinfo.lost);
            mvwprintw(raw_win, ++line, 0, "Highest sequence:    %u", rtcp->rtcpinfo.hseq);
            mvwprintw(raw_win, ++line, 0, "RTCP jitter:         %u", rtcp->rtcpinfo.jitter);
        }
        mvwprintw(raw_win, ++line, 0, "Fraction discarded:  %u / 256", rtcp->rtcpinfo.fdiscard);
        if (rtcp->rtcpinfo.mosl || rtcp->rtcpinfo.mosc) {
            mvwprintw(raw_win, ++line, 0, "MOS Listening:       %.1f", (float) rtcp->rtcpinfo.mosl / 10);
            mvwprintw(raw_win, ++line, 0, "MOS Conversational:  %.1f", (float) rtcp->rtcpinfo.mosc / 10);
        }
    } else {
        line += 2;
        mvwprintw(raw_win, line, 0, "No RTCP information available for this stream");
    }

    // Copy the raw_win contents into the panel
    copywin(raw_win, ui->win, 0, 0, 1, ui->width - raw_width - 1, raw_height, ui->width - 2, 0);

    return 0;
}

int
call_flow_handle_key(ui_t *ui, int key)
{
    int raw_width;
    call_flow_info_t *info = call_flow_info(ui);
    ui_t *next_ui;
    sip_call_t *call = NULL, *xcall = NULL;
    int rnpag_steps = setting_get_intvalue(SETTING_CF_SCROLLSTEP);
    int action = -1;

    // Sanity check, this should not happen
    if (!info)
        return KEY_NOT_HANDLED;

    // Check actions for this key
    while ((action = key_find_action(key, action)) != ERR) {
        // Check if we handle this action
        switch(action) {
            case ACTION_DOWN:
                call_flow_move(ui, info->cur_arrow + 1);
                break;
            case ACTION_UP:
                call_flow_move(ui, info->cur_arrow - 1);
                break;
            case ACTION_HNPAGE:
                rnpag_steps = rnpag_steps / 2;
                /* no break */
            case ACTION_NPAGE:
                call_flow_move(ui, info->cur_arrow + rnpag_steps);
                break;
            case ACTION_HPPAGE:
                rnpag_steps = rnpag_steps / 2;
                /* no break */
            case ACTION_PPAGE:
                // Prev page => N key up strokes
                call_flow_move(ui, info->cur_arrow - rnpag_steps);
                break;
            case ACTION_BEGIN:
                call_flow_move(ui, 0);
                break;
            case ACTION_END:
                call_flow_move(ui, vector_count(info->darrows));
                break;
            case ACTION_SHOW_FLOW_EX:
                werase(ui->win);
                if (call_group_count(info->group) == 1) {
                    call = vector_first(info->group->calls);
                    if (call->xcallid != NULL && strlen(call->xcallid)) {
                        if ((xcall = sip_find_by_callid(call->xcallid))) {
                            call_group_del(info->group, call);
                            call_group_add(info->group, xcall);
                            call_group_add_calls(info->group, xcall->xcalls);
                            info->group->callid = xcall->callid;
                        }
                    } else {
                        call_group_add_calls(info->group, call->xcalls);
                        info->group->callid = call->callid;
                    }
                } else {
                    call = vector_first(info->group->calls);
                    vector_clear(info->group->calls);
                    call_group_add(info->group, call);
                    info->group->callid = 0;
                }
                call_flow_set_group(info->group);
                break;
            case ACTION_SHOW_RAW:
                // KEY_R, display current call in raw mode
                ui_create_panel(PANEL_CALL_RAW);
                call_raw_set_group(info->group);
                break;
            case ACTION_DECREASE_RAW:
                raw_width = getmaxx(info->raw_win);
                if (raw_width - 2 > 1) {
                    setting_set_intvalue(SETTING_CF_RAWFIXEDWIDTH, raw_width - 2);
                }
                break;
            case ACTION_INCREASE_RAW:
                raw_width = getmaxx(info->raw_win);
                if (raw_width + 2 < COLS - 1) {
                    setting_set_intvalue(SETTING_CF_RAWFIXEDWIDTH, raw_width + 2);
                }
                break;
            case ACTION_RESET_RAW:
                setting_set_intvalue(SETTING_CF_RAWFIXEDWIDTH, -1);
                break;
            case ACTION_ONLY_SDP:
                // Toggle SDP mode
                info->group->sdp_only = !(info->group->sdp_only);
                // Disable sdp_only if there are not messages with sdp
                if (call_group_msg_count(info->group) == 0)
                    info->group->sdp_only = 0;
                // Reset screen
                call_flow_set_group(info->group);
                break;
            case ACTION_SDP_INFO:
                setting_toggle(SETTING_CF_SDP_INFO);
                break;
            case ACTION_CYCLE_COLOR:
                /* With protocol labels on, F7/c cycles protocol color: gray <-> proto */
                if (setting_enabled(SETTING_CF_PROTOCOL))
                    setting_toggle(SETTING_CF_PROTOCOL_COLOR);
                else
                    setting_toggle(SETTING_COLORMODE);
                break;
            case ACTION_ONLY_MEDIA:
                setting_toggle(SETTING_CF_ONLYMEDIA);
                call_flow_set_group(info->group);
                break;
            case ACTION_TOGGLE_MEDIA:
                setting_toggle(SETTING_CF_MEDIA);
                // Force reload arrows
                call_flow_set_group(info->group);
                break;
            case ACTION_TOGGLE_RAW:
                setting_toggle(SETTING_CF_FORCERAW);
                break;
            case ACTION_COMPRESS:
                setting_toggle(SETTING_CF_SPLITCALLID);
                /* Reset links on every cycle; linked mode re-applies on draw */
                vector_clear(info->column_links);
                call_flow_set_group(info->group);
                break;
            case ACTION_SAVE:
                if (capture_sources_count() > 1) {
                    dialog_run("Saving is not possible when multiple input sources are specified.");
                    break;
                }
                next_ui = ui_create_panel(PANEL_SAVE);
                save_set_group(next_ui, info->group);
                save_set_msg(next_ui,
                    call_flow_arrow_message(vector_item(info->darrows, info->cur_arrow)));
                break;
            case ACTION_TOGGLE_TIME:
                info->arrowtime = (info->arrowtime) ? false : true;
                break;
            case ACTION_LINK_COLUMNS:
                call_flow_link_columns_menu(ui);
                break;
            case ACTION_TOGGLE_PROTOCOL:
                setting_toggle(SETTING_CF_PROTOCOL);
                break;
            case ACTION_SELECT:
                if (info->selected == -1) {
                    info->selected = info->cur_arrow;
                } else {
                    if (info->selected == info->cur_arrow) {
                        info->selected = -1;
                    } else {
                        // Show diff panel
                        next_ui = ui_create_panel(PANEL_MSG_DIFF);
                        msg_diff_set_msgs(next_ui,
                                          call_flow_arrow_message(vector_item(info->darrows, info->selected)),
                                          call_flow_arrow_message(vector_item(info->darrows, info->cur_arrow)));
                    }
                }
                break;
            case ACTION_CLEAR:
                info->selected = -1;
                break;
            case ACTION_CONFIRM:
                // KEY_ENTER, display current message in raw mode
                ui_create_panel(PANEL_CALL_RAW);
                call_raw_set_group(info->group);
                call_raw_set_msg(call_flow_arrow_message(vector_item(info->darrows, info->cur_arrow)));
                break;
            case ACTION_CLEAR_CALLS:
            case ACTION_CLEAR_CALLS_SOFT:
                // Propagate the key to the previous panel
                return KEY_PROPAGATED;

            default:
                // Parse next action
                continue;
        }

        // We've handled this key, stop checking actions
        break;
    }

    // Return if this panel has handled or not the key
    return (action == ERR) ? KEY_NOT_HANDLED : KEY_HANDLED;
}

int
call_flow_help(ui_t *ui)
{
    WINDOW *help_win;
    int height, width;

    // Create a new panel and show centered
    height = 30;
    width = 65;
    help_win = newwin(height, width, (LINES - height) / 2, (COLS - width) / 2);

    // Set the window title
    mvwprintw(help_win, 1, 18, "Call Flow Help");

    // Write border and boxes around the window
    wattron(help_win, COLOR_PAIR(CP_BLUE_ON_DEF));
    box(help_win, 0, 0);
    mvwhline(help_win, 2, 1, ACS_HLINE, 63);
    mvwhline(help_win, 7, 1, ACS_HLINE, 63);
    mvwhline(help_win, height - 3, 1, ACS_HLINE, 63);
    mvwaddch(help_win, 2, 0, ACS_LTEE);
    mvwaddch(help_win, 7, 0, ACS_LTEE);
    mvwaddch(help_win, height - 3, 0, ACS_LTEE);
    mvwaddch(help_win, 2, 64, ACS_RTEE);
    mvwaddch(help_win, 7, 64, ACS_RTEE);
    mvwaddch(help_win, height - 3, 64, ACS_RTEE);

    // Set the window footer (nice blue?)
    mvwprintw(help_win, height - 2, 20, "Press any key to continue");

    // Some brief explanation abotu what window shows
    wattron(help_win, COLOR_PAIR(CP_CYAN_ON_DEF));
    mvwprintw(help_win, 3, 2, "This window shows the messages from a call and its relative");
    mvwprintw(help_win, 4, 2, "ordered by sent or received time.");
    mvwprintw(help_win, 5, 2, "This panel is mosly used when capturing at proxy systems that");
    mvwprintw(help_win, 6, 2, "manages incoming and outgoing request between calls.");
    wattroff(help_win, COLOR_PAIR(CP_CYAN_ON_DEF));

    // A list of available keys in this window
    mvwprintw(help_win, 8, 2, "Available keys:");
    mvwprintw(help_win, 9, 2, "Esc/Q       Go back to Call list window");
    mvwprintw(help_win, 10, 2, "F5/Ctrl-L   Leave screen and clear call list");
    mvwprintw(help_win, 11, 2, "Enter       Show current message Raw");
    mvwprintw(help_win, 12, 2, "F1/h        Show this screen");
    mvwprintw(help_win, 13, 2, "F2/d        Toggle SDP Address:Port info");
    mvwprintw(help_win, 14, 2, "F3/m        Toggle RTP arrows display");
    mvwprintw(help_win, 15, 2, "F4/X        Show call-flow with X-CID/X-Call-ID dialog");
    mvwprintw(help_win, 16, 2, "s           Cycle compress: off / same-addr / linked");
    mvwprintw(help_win, 17, 2, "F6/R        Show original call messages in raw mode");
    mvwprintw(help_win, 18, 2, "F7/c        Cycle color mode / protocol label colors");
    mvwprintw(help_win, 19, 2, "F8/C        Turn on/off message syntax highlighting");
    mvwprintw(help_win, 20, 2, "F10/l       Link columns into a single flow step");
    mvwprintw(help_win, 21, 2, "a           Toggle display aliases instead of IPs");
    mvwprintw(help_win, 22, 2, "p           Toggle transport protocol on message arrows");
    mvwprintw(help_win, 23, 2, "9/0         Increase/Decrease raw preview size");
    mvwprintw(help_win, 24, 2, "t           Toggle raw preview display");
    mvwprintw(help_win, 25, 2, "T           Restore raw preview size");
    mvwprintw(help_win, 26, 2, "D           Only show SDP messages");

    // Press any key to close
    wgetch(help_win);

    return 0;
}

int
call_flow_link_columns_menu(ui_t *ui)
{
    call_flow_info_t *info;
    call_flow_column_t *column;
    WINDOW *menu_win;
    int height, width, rows_per_page;
    int col_count, i, key;
    int cursor = 0;
    int selected = -1;
    int scroll_offset = 0;
    char **labels;
    int *suggested;
    vector_iter_t columns;

    if (!(info = call_flow_info(ui)))
        return -1;

    /* Ensure columns exist for the current group */
    if (vector_count(info->columns) == 0)
        call_flow_draw_columns(ui);

    col_count = vector_count(info->columns);
    if (col_count < 2) {
        dialog_run("Need at least two columns to link.");
        return -1;
    }

    labels = sng_malloc(sizeof(char *) * col_count);
    suggested = sng_malloc(sizeof(int) * col_count);

    columns = vector_iterator(info->columns);
    i = 0;
    while ((column = vector_iterator_next(&columns))) {
        labels[i] = sng_malloc(MAX_SETTING_LEN);
        call_flow_column_label(column, labels[i], MAX_SETTING_LEN);
        i++;
    }

    call_flow_link_mark_suggestions(info, suggested, col_count);

    height = col_count + 9;
    width = 72;
    if (height > LINES - 4)
        height = LINES - 4;
    if (width > COLS - 4)
        width = COLS - 4;
    rows_per_page = height - 8;
    if (rows_per_page < 3)
        rows_per_page = 3;

    menu_win = newwin(height, width, (LINES - height) / 2, (COLS - width) / 2);
    keypad(menu_win, TRUE);

    for (;;) {
        int visible_end;
        werase(menu_win);
        box(menu_win, 0, 0);
        mvwprintw(menu_win, 1, width / 2 - 9, "Link Flow Columns");
        mvwhline(menu_win, 2, 1, ACS_HLINE, width - 2);

        wattron(menu_win, COLOR_PAIR(CP_CYAN_ON_DEF));
        mvwprintw(menu_win, 3, 2, "Select columns to link and display together.");
        mvwprintw(menu_win, 4, 2, "* = suggested (adjacent, no messages between)");
        wattroff(menu_win, COLOR_PAIR(CP_CYAN_ON_DEF));

        if (cursor < scroll_offset)
            scroll_offset = cursor;
        if (cursor >= scroll_offset + rows_per_page)
            scroll_offset = cursor - rows_per_page + 1;

        visible_end = scroll_offset + rows_per_page;
        if (visible_end > col_count)
            visible_end = col_count;

        for (i = scroll_offset; i < visible_end; i++) {
            int row = 5 + (i - scroll_offset);
            call_flow_column_t *col = vector_item(info->columns, i);
            char mark = ' ';
            char link_note[32] = "";

            if (suggested[i])
                mark = '*';

            /* Show existing links against later partners */
            {
                int j;
                for (j = 0; j < col_count; j++) {
                    call_flow_column_t *other = vector_item(info->columns, j);
                    if (j != i && call_flow_addr_pair_linked(info, col->addr, other->addr)) {
                        snprintf(link_note, sizeof(link_note), " [linked:%d]", j + 1);
                        break;
                    }
                }
            }

            if (i == cursor)
                wattron(menu_win, A_REVERSE);
            else if (i == selected)
                wattron(menu_win, A_BOLD | COLOR_PAIR(CP_YELLOW_ON_DEF));

            mvwprintw(menu_win, row, 2, "%c %2d. %-40s%s",
                      mark, i + 1, labels[i], link_note);

            wattroff(menu_win, A_REVERSE | A_BOLD | COLOR_PAIR(CP_YELLOW_ON_DEF));
        }

        mvwhline(menu_win, height - 3, 1, ACS_HLINE, width - 2);
        if (selected > 0) {
            mvwprintw(menu_win, height - 2, 2,
                      "Space/Enter=select to link | s=auto link | u=unselect | Esc=close");
        } else {
            mvwprintw(menu_win, height - 2, 2,
                      "Space/Enter=select | u=unlink | Esc=close");
        }

        wrefresh(menu_win);
        key = wgetch(menu_win);

        if (key == KEY_ESC || key == 'q' || key == 'Q')
            break;

        if (key == KEY_UP || key == 'k') {
            if (cursor > 0)
                cursor--;
            continue;
        }
        if (key == KEY_DOWN || key == 'j') {
            if (cursor < col_count - 1)
                cursor++;
            continue;
        }
        if (key == KEY_PPAGE) {
            cursor -= rows_per_page;
            if (cursor < 0)
                cursor = 0;
            continue;
        }
        if (key == KEY_NPAGE) {
            cursor += rows_per_page;
            if (cursor >= col_count)
                cursor = col_count - 1;
            continue;
        }

        /* Accept first suggested adjacent pair */
        if (key == 's' || key == 'S') {
            for (i = 0; i < col_count - 1; i++) {
                call_flow_column_t *a = vector_item(info->columns, i);
                call_flow_column_t *b = vector_item(info->columns, i + 1);
                if (!call_flow_columns_have_messages(info, a, b) &&
                    !call_flow_addr_pair_linked(info, a->addr, b->addr)) {
                    call_flow_link_t *link = sng_malloc(sizeof(call_flow_link_t));
                    link->addr1 = a->addr;
                    link->addr2 = b->addr;
                    vector_append(info->column_links, link);
                    call_flow_link_mark_suggestions(info, suggested, col_count);
                    break;
                }
            }
            selected = -1;
            continue;
        }

        if (key == 'u' || key == 'U') {
            if (selected >= 0) {
                selected = -1;
            } else if (cursor >= 0) {
                /* Unlink cursor column from any partners */
                call_flow_column_t *col = vector_item(info->columns, cursor);
                vector_iter_t lit = vector_iterator(info->column_links);
                call_flow_link_t *link;
                vector_t *to_remove = vector_create(0, 1);
                while ((link = vector_iterator_next(&lit))) {
                    if (addressport_equals(link->addr1, col->addr) ||
                        addressport_equals(link->addr2, col->addr)) {
                        vector_append(to_remove, link);
                    }
                }
                if (vector_count(to_remove) > 0) {
                    lit = vector_iterator(to_remove);
                    while ((link = vector_iterator_next(&lit)))
                        vector_remove(info->column_links, link);
                    /* Stop linked compress mode from re-applying suggestions */
                    call_flow_disable_linked_mode();
                }
                vector_destroy(to_remove);
                call_flow_link_mark_suggestions(info, suggested, col_count);
            }
            continue;
        }

        if (key == KEY_SPACE || key == KEY_INTRO || key == '\n' || key == '\r') {
            if (selected < 0) {
                selected = cursor;
            } else if (selected == cursor) {
                selected = -1;
            } else {
                call_flow_column_t *a = vector_item(info->columns, selected);
                call_flow_column_t *b = vector_item(info->columns, cursor);

                if (call_flow_addr_pair_linked(info, a->addr, b->addr)) {
                    /* Toggle: remove existing link */
                    vector_iter_t lit = vector_iterator(info->column_links);
                    call_flow_link_t *link;
                    while ((link = vector_iterator_next(&lit))) {
                        if ((addressport_equals(link->addr1, a->addr) &&
                             addressport_equals(link->addr2, b->addr)) ||
                            (addressport_equals(link->addr1, b->addr) &&
                             addressport_equals(link->addr2, a->addr))) {
                            vector_remove(info->column_links, link);
                            break;
                        }
                    }
                    /* Stop linked compress mode from re-applying suggestions */
                    call_flow_disable_linked_mode();
                } else {
                    call_flow_link_t *link = sng_malloc(sizeof(call_flow_link_t));
                    link->addr1 = a->addr;
                    link->addr2 = b->addr;
                    vector_append(info->column_links, link);
                }

                call_flow_link_mark_suggestions(info, suggested, col_count);
                selected = -1;
            }
            continue;
        }
    }

    delwin(menu_win);

    for (i = 0; i < col_count; i++)
        sng_free(labels[i]);
    sng_free(labels);
    sng_free(suggested);

    /* Force column/arrow positions to refresh */
    ui->changed = true;
    call_flow_draw(ui);
    return 0;
}

int
call_flow_set_group(sip_call_group_t *group)
{
    ui_t *ui;
    call_flow_info_t *info;

    if (!(ui = ui_find_by_type(PANEL_CALL_FLOW)))
        return -1;

    if (!(info = call_flow_info(ui)))
        return -1;

    /* Drop links when switching to a different call group */
    if (info->group != group)
        vector_clear(info->column_links);

    vector_clear(info->columns);
    vector_clear(info->arrows);

    info->group = group;
    info->cur_arrow = info->selected = -1;

    return 0;
}

void
call_flow_column_add(ui_t *ui, const char *callid, address_t addr, int transport)
{
    call_flow_info_t *info;
    call_flow_column_t *column;
    vector_iter_t columns;

    if (!(info = call_flow_info(ui)))
        return;

    if (call_flow_column_get(ui, callid, addr))
        return;

    // Try to fill the second Call-Id of the column
    columns = vector_iterator(info->columns);
    while ((column = vector_iterator_next(&columns))) {
        if (addressport_equals(column->addr, addr)) {
            if (column->colpos != 0 && vector_count(column->callids) < info->maxcallids) {
                vector_append(column->callids, (void*)callid);
                return;
            }
        }
    }

    // Create a new column
    column = malloc(sizeof(call_flow_column_t));
    memset(column, 0, sizeof(call_flow_column_t));
    column->callids = vector_create(1, 1);
    vector_append(column->callids, (void*)callid);
    column->addr = addr;
    column->transport = transport;
    if (setting_enabled(SETTING_ALIAS_PORT)) {
        sng_strncpy(column->alias, get_alias_value_vs_port(addr.ip, addr.port), sizeof(column->alias));
    } else {
        sng_strncpy(column->alias, get_alias_value(addr.ip), sizeof(column->alias));
    }
    column->colpos = vector_count(info->columns);
    vector_append(info->columns, column);
}

call_flow_column_t *
call_flow_column_get(ui_t *ui, const char *callid, address_t addr)
{
    call_flow_info_t *info;
    call_flow_column_t *column;
    vector_iter_t columns;
    int match_port;
    const char *alias;

    if (!(info = call_flow_info(ui)))
        return NULL;

    // Look for address or address:port ?
    match_port = addr.port != 0;

    // Get alias value for given address
    if (setting_enabled(SETTING_ALIAS_PORT) && match_port) {
        alias = get_alias_value_vs_port(addr.ip, addr.port);
    } else {
        alias = get_alias_value(addr.ip);
    }

    columns = vector_iterator(info->columns);
    while ((column = vector_iterator_next(&columns))) {
        // In compressed mode, we search using alias instead of address
        if (setting_enabled(SETTING_CF_SPLITCALLID)) {
            if (!strcmp(column->alias, alias)) {
                return column;
            }
        } else {
            // Check if this column matches requested address
            if (match_port) {
                if (addressport_equals(column->addr, addr)) {
                    if (vector_index(column->callids, (void*)callid) >= 0) {
                        return column;
                    }
                }
            } else {
                // Dont check port
                if (address_equals(column->addr, addr)) {
                    return column;
                }
            }
        }
    }
    return NULL;
}

void
call_flow_move(ui_t *ui, int arrowindex)
{
    call_flow_info_t *info;
    call_flow_arrow_t *arrow;
    int flowh;
    int curh = 0;

    // Get panel info
    if (!(info = call_flow_info(ui)))
        return;

    // Already in this position?
    if (info->cur_arrow == arrowindex)
        return;

    // Get flow subwindow height (for scrolling)
    flowh  = getmaxy(info->flow_win);

    // Moving down or up?
    bool move_down = (info->cur_arrow < arrowindex);

    vector_iter_t it = vector_iterator(info->darrows);
    vector_iterator_set_current(&it, info->cur_arrow);
    vector_iterator_set_filter(&it, call_flow_arrow_filter);

    if (move_down) {
        while ((arrow = vector_iterator_next(&it))) {
            // Get next selected arrow
            info->cur_arrow = vector_iterator_current(&it);

            // We have reached our destination
            if (info->cur_arrow >= arrowindex) {
                break;
            }
        }
    } else {
        while ((arrow = vector_iterator_prev(&it))) {
            // Get previous selected arrow
            info->cur_arrow = vector_iterator_current(&it);

            // We have reached our destination
            if (info->cur_arrow <= arrowindex) {
                break;
            }
        }
    }

    // Update the first displayed arrow
    if (info->cur_arrow <= info->first_arrow) {
        info->first_arrow = info->cur_arrow;
    } else {
        // Draw the scrollbar
        vector_iterator_set_current(&it, info->first_arrow - 1);
        while ((arrow = vector_iterator_next(&it))) {
            // Increase current arrow height position
            curh += call_flow_arrow_height(ui, arrow);
            // If we have reached current arrow
            if (vector_iterator_current(&it) == info->cur_arrow) {
                if (curh > flowh) {
                    // Go to the next first arrow and check if current arrow
                    // is still out of bottom bounds
                    info->first_arrow++;
                    vector_iterator_set_current(&it, info->first_arrow - 1);
                    curh = 0;
                } else {
                    break;
                }
            }
        }
    }
}

call_flow_arrow_t *
call_flow_arrow_selected(ui_t *ui)
{
    // Get panel info
    call_flow_info_t *info = call_flow_info(ui);
    // No selected call
    if (info->selected == -1)
        return NULL;

    return vector_item(info->darrows, info->selected);

}

struct timeval
call_flow_arrow_time(call_flow_arrow_t *arrow)
{
    struct timeval ts = { 0 };
    sip_msg_t *msg;
    rtp_stream_t *stream;
    rtp_event_t *event;

    if (!arrow)
        return ts;

    if (arrow->type == CF_ARROW_SIP) {
        msg = (sip_msg_t *) arrow->item;
        ts = packet_time(msg->packet);
    } else if (arrow->type == CF_ARROW_RTP) {
        stream = (rtp_stream_t *) arrow->item;
        ts = stream->time;
    } else if (arrow->type == CF_ARROW_EVENT) {
        event = (rtp_event_t *) arrow->item;
        ts = event->time;
    }
    return ts;

}

void
call_flow_arrow_sorter(vector_t *vector, void *item)
{
    struct timeval curts, prevts;
    int count = vector_count(vector);
    int i;

    // First item is alway sorted
    if (vector_count(vector) == 1)
        return;

    curts = call_flow_arrow_time(item);

    for (i = count - 2 ; i >= 0; i--) {
        // Get previous arrow
        prevts = call_flow_arrow_time(vector_item(vector, i));
        // Check if the item is already in a sorted position
        if (timeval_is_older(curts, prevts)) {
            vector_insert(vector, item, i + 1);
            return;
        }
    }

    // Put this item at the begining of the vector
    vector_insert(vector, item, 0);
}

int
call_flow_arrow_filter(void *item)
{
    call_flow_arrow_t *arrow = (call_flow_arrow_t *) item;

    // SIP arrows are never filtered
    if (arrow->type == CF_ARROW_SIP && setting_disabled(SETTING_CF_ONLYMEDIA))
        return 1;

    // RTP arrows are only displayed when requested
    if (arrow->type == CF_ARROW_RTP || arrow->type == CF_ARROW_EVENT) {
        // Display all streams
        if (setting_enabled(SETTING_CF_MEDIA))
            return 1;
        // Otherwise only show active streams
        if (setting_has_value(SETTING_CF_MEDIA, SETTING_ACTIVE))
            return stream_is_active(arrow->item);
    }

    // Rest of the arrows are never displayed
    return 0;
}
