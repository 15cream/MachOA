#!/usr/local/Cellar/python/2.7.13/bin/python
# -*- coding: utf-8 -*-
__author__ = 'gjy'
import os

NOCONAPPS=0

class Bundle:

    def __init__(self, name):
        self.name = name
        self.relatedBundles = dict()  # key: bundle_object ; val: concurrence
        self.relatedApps = []  # the apps who used this bundle, each item is an App Object

    def find_related_bundles(self):
        for app in self.relatedApps:
            for b in app.bundles:
                if b not in self.relatedBundles:
                    self.relatedBundles[b] = 1
                else:
                    self.relatedBundles[b] += 1

    def print_related_bundles(self):
        if not self.relatedBundles:
            self.find_related_bundles()
        d = sorted(self.relatedBundles.items(), key=lambda x: x[1], reverse=True)
        print "Related bundles of {}: (total Apps:{})".format(self.name, len(self.relatedApps))
        for item in d:
            print "     ", item[0], item[1]

    def print_related_bundle_matrix(self):
        if not self.relatedBundles:
            self.find_related_bundles()
        for b in self.relatedBundles:
            print "CONCURRENCE OF {}: {}, {}".format(b.name, self.find_concurrence(b), b.find_concurrence(self))



    # 在引用当前bundle的所有应用中，引用b的频率
    def find_concurrence(self, b):
        if not self.relatedBundles:
            self.find_related_bundles()
        if self.relatedApps:
            return "{}/{}".format(self.relatedBundles[b], len(self.relatedApps))
        else:
            return NOCONAPPS




class App:

    def __init__(self, name):
        self.name = name
        self.cate = None
        self.sub_cate = None
        self.bundles = []  # Used bundles, each item is a Bundle Object
        self.root_dir = "/Users/gjy/Desktop/L实验室相关/2017-12-毕设/samples/pp_apps/"

    @staticmethod
    def common_bundle_of_Apps(appList):
        if appList:
            i = []
            for b in appList.pop().bundles:
                i.append(b.name)
            for app in appList:
                new_i = []
                bs = app.bundles
                if bs:
                    for b in bs:
                        if b.name in i:
                            new_i.append(b.name)
                    i = new_i
            return i
        else:
            return []

    def find_headers(self):
        try:
            headers_dir = "{}{}/{}/{}/headers".format(self.root_dir, self.cate, self.sub_cate, self.name)
            return os.listdir(headers_dir)
        except OSError as e:
            print e, headers_dir
            return []

        # return []

    @staticmethod
    def common_header_of_Apps(appList):
        # if appList:
        #     i = []
        #     while not i:
        #         i = appList.pop().find_headers()
        #     for app in appList:
        #         new_i = []
        #         hs = app.find_headers()
        #         if hs:
        #             for h in hs:
        #                 if h in i:
        #                     new_i.append(h)
        #             i = new_i
        #     return i
        # else:
        #     return []
        hd = dict()
        ac = len(appList) + 0.0
        r = []
        threshold = 0.9
        for app in appList:
            for h in app.find_headers():
                if h in hd:
                    hd[h] += 1
                else:
                    hd[h] = 1
        for h, hc in hd.items():
            if hc / ac > threshold:
                r.append(h)
        return r


