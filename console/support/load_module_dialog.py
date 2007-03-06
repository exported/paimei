#
# PaiMei
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
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

import wx
import MySQLdb
import os
import bakmei

class load_module_dialog(wx.Dialog):
    def __init__(self, *args, **kwds):
        self.parent = kwds["parent"]

        # begin wxGlade: __init__
        kwds["style"] = wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)

        self.data_source_static = wx.StaticText(self, -1, "Data Source:")
        self.data_source = wx.ComboBox(self, -1, "SQLite", (-1,-1), (-1,-1), ["SQLite", "MySQL"], wx.CB_READONLY)        
        self.data_source_global = wx.CheckBox(self, -1, "Use Global Settings")
        
        self.host_static = wx.StaticText(self, -1, "MySQL Host:")
        self.username_static = wx.StaticText(self, -1, "MySQL User:")
        self.password_static = wx.StaticText(self, -1, "MySQL Passwd:")
        self.load_button = wx.Button(self, -1, "Load")
                
        self.sqlite_path_static = wx.StaticText(self, -1, "Path to obd file:")
        
        self.sqlite_path = wx.TextCtrl(self, -1, "")
        self.sqlite_browse = wx.Button(self, -1, "Browse...")

        self.module_id_static = wx.StaticText(self, -1, "Module ID:")
        self.module_id = wx.ListCtrl(self, -1, style=wx.LC_REPORT)
        self.module_id.InsertColumn(0, "ID")
        self.module_id.InsertColumn(1, "Name")
        self.module_id_list = wx.Button(self, -1, "Refresh")

        # if the main frame already contains module values, then use them.
        if self.parent.mysql_host:     self.host = wx.TextCtrl(self, -1, self.parent.mysql_host)
        else:                          self.host = wx.TextCtrl(self, -1, "localhost")

        if self.parent.mysql_username: self.username = wx.TextCtrl(self, -1, self.parent.mysql_username)
        else:                          self.username = wx.TextCtrl(self, -1, "root")

        if self.parent.mysql_password: self.password = wx.TextCtrl(self, -1, self.parent.mysql_password, style=wx.TE_PASSWORD)
        else:                          self.password = wx.TextCtrl(self, -1, "", style=wx.TE_PASSWORD)

        self.__set_properties()
        self.__do_layout()

        # Disable MySQL as SQLite will be the default
        self.host.Enabled = False
        self.host_static.Enabled = False
        self.username.Enabled = False
        self.username_static.Enabled = False
        self.password.Enabled = False   
        self.password_static.Enabled = False     
        self.data_source_global.Enabled = False

        self.Bind(wx.EVT_BUTTON, self.on_load_button, self.load_button)
        self.Bind(wx.EVT_COMBOBOX, self.on_data_source_select, self.data_source)
        self.Bind(wx.EVT_BUTTON, self.on_browse_button, self.sqlite_browse)
        self.Bind(wx.EVT_BUTTON, self.on_module_list, self.module_id_list)
        self.Bind(wx.EVT_TEXT, self.on_sqlite_path_updated, self.sqlite_path)
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: load_module_dialog.__set_properties
        self.SetTitle("Load Module")
        self.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))              
        
        self.data_source_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.data_source.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.host_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.host.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.username_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.username.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.password_static.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.password.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.load_button.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.load_button.SetDefault()
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: load_module_dialog.__do_layout
        sizer_4 = wx.BoxSizer(wx.VERTICAL)
        sizer_5 = wx.BoxSizer(wx.HORIZONTAL)
        
        browse_sizer = wx.BoxSizer(wx.HORIZONTAL)
        
        module_options = wx.GridBagSizer(6, 3)
        module_options.Add(self.data_source_static, (0,0))
        
        ds_sizer = wx.BoxSizer(wx.HORIZONTAL)
        ds_sizer.Add(self.data_source, 0, wx.ADJUST_MINSIZE, 0)
        ds_sizer.Add(self.data_source_global, 1, wx.ADJUST_MINSIZE, 0)
        
        module_options.Add(ds_sizer, (0,1))
        
        module_options.Add(self.sqlite_path_static, (1,0))
        
        module_options.Add(self.sqlite_path, (1,1), flag=wx.EXPAND)
        module_options.Add(self.sqlite_browse, (1,2))
        module_options.Add(browse_sizer, (1,1))
        
        module_options.Add(self.host_static, (2,0))
        module_options.Add(self.host, (2,1), flag=wx.EXPAND)
        module_options.Add(self.username_static, (3,0))
        module_options.Add(self.username, (3,1), flag=wx.EXPAND)
        module_options.Add(self.password_static, (4,0))
        module_options.Add(self.password, (4,1), flag=wx.EXPAND)
        
        module_options.Add(self.module_id_static, (5,0))
        module_sizer = wx.BoxSizer(wx.VERTICAL)
        module_options.Add(self.module_id, (5,1), (2,2), flag=wx.EXPAND)
        module_options.Add(self.module_id_list, (6,0))
        
        
        sizer_5.Add(module_options, 0, wx.EXPAND, 0)
        sizer_4.Add(sizer_5, 1, wx.EXPAND, 0)
        sizer_4.Add(self.load_button, 0, wx.EXPAND|wx.ADJUST_MINSIZE, 0)
        self.SetAutoLayout(True)
        self.SetSizer(sizer_4)
        sizer_4.Fit(self)
        sizer_4.SetSizeHints(self)
        self.Layout()
        self.Centre()
        # end wxGlade

    def on_load_button(self, event): 
        #host     = self.host.GetLineText(0)
        #username = self.username.GetLineText(0)
        #password = self.password.GetLineText(0)
        #
        ## bubble up the form values to the main frame for possible persistent storage.
        #self.parent.mysql_host     = host
        #self.parent.mysql_username = username
        #self.parent.mysql_password = password
        #
        #self.mysql_connect(host, username, password)
        
        item = self.module_id.GetNextItem(-1, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
        
        module_id = self.module_id.GetItemData(item)
        
        if module_id >= 0:
            # Save to parent
            self.parent.main_module_id = module_id
            # TODO : Handle MySQL as well
            self.parent.main_DSN = self.sqlite_path.GetValue()
            self.Destroy()
        else:
            dlg = wx.MessageDialog(self, "Please select a module to load.", "Missing Information", wx.OK)
            dlg.ShowModal()
            dlg.Destroy()

    def on_data_source_select(self, event):
        data = self.data_source.GetValue()
        
        #Disable everything first
        self.sqlite_path_static.Enabled = False
        self.sqlite_path.Enabled = False
        self.sqlite_browse.Enabled = False
        self.host.Enabled = False
        self.username.Enabled = False
        self.password.Enabled = False
        self.host_static.Enabled = False
        self.username_static.Enabled = False
        self.password_static.Enabled = False   
        self.data_source_global.Enabled = False
        
        if data == "SQLite":
            self.sqlite_path_static.Enabled = True
            self.sqlite_path.Enabled = True
            self.sqlite_browse.Enabled = True
        elif data == "MySQL":
            self.host_static.Enabled = True
            self.username_static.Enabled = True
            self.password_static.Enabled = True
            self.host.Enabled = True
            self.username.Enabled = True
            self.password.Enabled = True
            self.data_source_global.Enabled = True

    def on_sqlite_path_updated(self, event):
        self.on_module_list(None)

    def on_browse_button(self, event):
        dlg = wx.FileDialog(self, "Choose Open Binary Database File", os.getcwd(), 
                "", "OBD files (*.obd, *.obdf)|*.obd;*.obdf|All files (*.*)|*.*", 
                wx.OPEN | wx.CHANGE_DIR)
                
        if dlg.ShowModal() == wx.ID_OK:
            file_path = dlg.GetPath()
            self.sqlite_path.SetValue(file_path)

    class module_list_popup(wx.PopupTransientWindow):
        def __init__(self, parent, style, text):
            wx.PopupTransientWindow.__init__(self, parent, style)
            #self.SetBackgroundColour("#FFB6C1")
            st = wx.StaticText(self, -1, text, pos=(10,10))
            sz = st.GetBestSize()
            self.SetSize( (sz.width+20, sz.height+20) )

    def on_module_list(self, event):
        ss = bakmei.sql_singleton.sql_singleton()
        st_val = ""
        
        self.module_id.DeleteAllItems()
        
        try:
            if self.sqlite_path.GetValue() == "":
                raise bakmei.sql_singleton.InvalidDatabaseException
                
            modules = ss.select_modules(self.sqlite_path.GetValue())

            for module in modules:
                st_val += "%d - %s\n" % module
                info = wx.ListItem()
                info.SetText("%d" % module[0])
                info.SetData(module[0])
                index = self.module_id.InsertItem(info)
                
                self.module_id.SetStringItem(index, 1, module[1])
                
        except bakmei.sql_singleton.InvalidDatabaseException:
            st_val = "The database path entered is invalid.\nNo modules can be listed."      
            win = self.module_list_popup(self, wx.SIMPLE_BORDER, st_val)
            btn = self.module_id_list
            pos = btn.ClientToScreen( (0,0) )
            sz =  btn.GetSize()
            win.Position(pos, (0, sz[1]))                
            win.Popup()                                                    

    def mysql_connect (self, host, username, password):
        try:
            self.parent.mysql = MySQLdb.connect(host=host, user=username, passwd=password, db="paimei")
        except MySQLdb.OperationalError, err:
            self.parent.status_bar.SetStatusText("Failed connecting to MySQL server: %s" % err[1])
            return

        self.parent.status_bar.SetStatusText("Successfully connected to MySQL server at %s." % host)
        self.parent.status_bar.SetStatusText("MySQL: %s" % host, 2)