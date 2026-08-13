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
 * @file theme.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Theme and Color definitions
 *
 */
#ifndef __SNGREP_THEME_H
#define __SNGREP_THEME_H

/**
 * @brief Enum for available color pairs
 */
enum sngrep_colors_pairs {
    CP_DEFAULT = 0,
    CP_CYAN_ON_DEF,
    CP_YELLOW_ON_DEF,
    CP_MAGENTA_ON_DEF,
    CP_GREEN_ON_DEF,
    CP_RED_ON_DEF,
    CP_BLUE_ON_DEF,
    CP_WHITE_ON_DEF,
    CP_DEF_ON_CYAN,
    CP_DEF_ON_BLUE,
    CP_WHITE_ON_BLUE,
    CP_BLACK_ON_CYAN,
    CP_WHITE_ON_CYAN,
    CP_YELLOW_ON_CYAN,
    CP_BLUE_ON_CYAN,
    CP_BLUE_ON_WHITE,
    CP_CYAN_ON_BLACK,
    CP_CYAN_ON_WHITE,
    //! Transport protocol label colors (call flow arrows)
    CP_PROTO_GRAY_ON_DEF,
    CP_PROTO_UDP_ON_DEF,
    CP_PROTO_TCP_ON_DEF,
    CP_PROTO_TLS_ON_DEF,
    CP_PROTO_WS_ON_DEF,
    CP_PROTO_WSS_ON_DEF,
};

//! Custom ncurses color indexes for protocol RGB (when can_change_color)
#define COLOR_PROTO_GRAY  15
#define COLOR_PROTO_UDP   16
#define COLOR_PROTO_TCP   17
#define COLOR_PROTO_TLS   18
#define COLOR_PROTO_WS    19
#define COLOR_PROTO_WSS   20

// Used to configure color pairs only with fg color
#define COLOR_DEFAULT -1


#endif /* __SNGREP_THEME_H */
