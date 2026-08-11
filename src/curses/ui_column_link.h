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
 * @file ui_column_link.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions to manage multi-homed column link panel
 *
 * This panel lists call-flow endpoints and lets the user link two physical
 * addresses of a multi-homed host into a single lifeline.
 */

#ifndef __SNGREP_UI_COLUMN_LINK_H
#define __SNGREP_UI_COLUMN_LINK_H

#include "config.h"
#include "ui_manager.h"
#include "ui_call_flow.h"
#include "address.h"

//! Sorter declaration of column link structures
typedef struct column_link_entry column_link_entry_t;
typedef struct column_link_info column_link_info_t;

/**
 * @brief One endpoint row in the column link panel
 */
struct column_link_entry {
    //! Endpoint address
    address_t addr;
    //! Display label (ip:port)
    char label[ADDRESSLEN + 8];
    //! Backing flow column
    call_flow_column_t *column;
    //! Current link partner, or NULL
    address_t *linked_to;
    //! 1 when no traffic was seen with another unlinked endpoint
    int suggested;
};

/**
 * @brief Column link panel private information
 */
struct column_link_info {
    //! Endpoint entries shown in the list
    vector_t *entries;
    //! Highlighted row
    int cur;
    //! First visible row when scrolling
    int scroll;
    //! Index of first-picked entry, -1 if none
    int pending;
    //! Parent call-flow UI
    ui_t *parent_flow;
};

/**
 * @brief Create column link panel
 *
 * @param ui UI structure pointer
 */
void
column_link_create(ui_t *ui);

/**
 * @brief Destroy column link panel
 *
 * @param ui UI structure pointer
 */
void
column_link_destroy(ui_t *ui);

/**
 * @brief Get column link panel info
 *
 * @param ui UI structure pointer
 * @return panel info pointer
 */
column_link_info_t *
column_link_info(ui_t *ui);

/**
 * @brief Draw column link panel
 *
 * @param ui UI structure pointer
 * @return 0 on success
 */
int
column_link_draw(ui_t *ui);

/**
 * @brief Handle keys for column link panel
 *
 * @param ui UI structure pointer
 * @param key Pressed key
 * @return enum @key_handler_ret
 */
int
column_link_handle_key(ui_t *ui, int key);

/**
 * @brief Bind panel to the call-flow being edited
 *
 * @param ui Column link UI
 * @param flow_ui Parent call-flow UI
 */
void
column_link_set_flow(ui_t *ui, ui_t *flow_ui);

#endif /* __SNGREP_UI_COLUMN_LINK_H */
