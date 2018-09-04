#!/usr/local/Cellar/python/2.7.13/bin/python
# -*- coding: utf-8 -*-
__author__ = 'gjy'
from Bundle import Bundle, App
import sqlite3

class Analyzer:
    def __init__(self):
        self.apps_dir = "/Users/gjy/Desktop/L实验室相关/2017-12-毕设/samples/pp_apps/"
        self.connector = self.connect_db()
        self.AppList = []
        self.BundleDict = dict()  # bundle_name : Bundle_Object

    def connect_db(self):
        conn = sqlite3.connect("Data.db")
        if conn:
            print "Database connected"
            conn.text_factory = str
            return conn

    def clearup(self):
        if self.connector:
            self.connector.commit()
            self.connector.close()

    def build_data_from_db(self):
        try:
            c = self.connector.cursor()
            c.execute("SELECT * FROM APP")
            app_item = c.fetchone()
            while app_item:
                app = App(app_item[0])
                app.cate = app_item[1]
                app.sub_cate = app_item[2]
                app.bundles = app_item[3].split(" | ")
                self.AppList.append(app)

                for b in app.bundles:
                    if b not in self.BundleDict:
                        self.BundleDict[b] = Bundle(b)
                    self.BundleDict[b].relatedApps.append(app)
                app_item = c.fetchone()
        except Exception as e:
            print e

    def run(self):
        self.build_data_from_db()
        print self.BundleDict.keys()
        self.BundleDict["GoogleKitSwitch.bundle"].print_related_bundle_matrix()
        self.clearup()

Analyzer().run()