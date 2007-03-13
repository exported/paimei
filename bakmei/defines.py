#
# Bak Mei - The Pai Mei Backend
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
# Copyright (C) 2007 Cameron Hotchkies <chotchkies@tippingpoint.com>
#
# $Id$
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

'''
@author:       Cameron Hotchkies, Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      chotchkies@tippingpoint.com
@organization: www.openrce.org
'''

### XREF TYPES ###
CODE_TO_CODE_FUNCTION       = 0x01
DATA_TO_FUNCTION            = 0x02
CODE_TO_CODE_BASIC_BLOCK    = 0x04
CODE_TO_CODE_INSTRUCTION    = 0x08
CODE_TO_DATA_FUNCTION       = 0x10
CODE_TO_DATA_BASIC_BLOCK    = 0x20
CODE_TO_DATA_INSTRUCTION    = 0x40

VAR_TYPE_ARGUMENT   = 1
VAR_TYPE_LOCAL      = 2

DATA_TYPE_PLACEHOLDER = 1

BAK_MEI_VERSION     = 1.0