#!/usr/local/Cellar/python/2.7.13/bin/python
# -*- coding: utf-8 -*-
__author__ = 'gjy'
from Bundle import Bundle, App
import sqlite3
import pickle

class Analyzer:
    def __init__(self):
        self.apps_dir = "/Users/gjy/Desktop/L实验室相关/2017-12-毕设/samples/pp_apps/"
        self.connector = self.connect_db()
        self.AppDict = dict()  # app_name, App_object
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
                self.AppDict[app.name] = app

                for b in app_item[3].split(" | "):
                    if b not in self.BundleDict:
                        self.BundleDict[b] = Bundle(b)
                    self.BundleDict[b].relatedApps.append(app)
                    app.bundles.append(self.BundleDict[b])
                app_item = c.fetchone()
        except Exception as e:
            print e

    def run(self):
        self.build_data_from_db()
        print len(self.BundleDict.keys())
        # GoogleKitSwitch
        # self.BundleDict["AlipaySDK.bundle"].print_related_bundle_matrix()
        # for name, b in self.BundleDict.items():
        #     print name, len(b.relatedApps)
        # tb = 'GoogleKitSwitch.bundle'
        # related_apps = self.BundleDict[tb].relatedApps
        # cb = App.common_bundle_of_Apps(related_apps)
        # ch = App.common_header_of_Apps(related_apps)
        # print "{} headers of {} bundles:{}".format(len(cb), len(cb), cb)
        # for h in ch:
        #     print h
        # r = dict()
        for b, bo in self.BundleDict.items():
            related_apps = bo.relatedApps
            cb = App.common_bundle_of_Apps(related_apps)
            if len(related_apps) != 1 and len(cb) == 1:
                print cb, len(related_apps)
        #     r[b] = (App.common_bundle_of_Apps(related_apps), App.common_header_of_Apps(related_apps))
        # output = open('r.pkl', 'wb')
        # pickle.dump(r, output)
        # output.close()
        self.clearup()

Analyzer().run()