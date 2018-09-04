#!/usr/local/Cellar/python/2.7.13/bin/python
# -*- coding: utf-8 -*-
__author__ = 'gjy'

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
        b_list = self.relatedBundles.keys()
        print b_list
        for b in b_list:
            for b_c in b_list:
                print b.find_concurrence(b_c),
            print


    def find_concurrence(self, b):
        if not self.relatedBundles:
            self.find_related_bundles()
        return "{}/{}".format(self.relatedBundles[b], len(self.relatedApps))

class App:

    def __init__(self, name):
        self.name = name
        self.cate = None
        self.sub_cate = None
        self.bundles = []  # Used bundles, each item is a Bundle Object



