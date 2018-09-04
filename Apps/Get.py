#coding=utf-8
__author__ = 'gjy'
import commands
import urllib
import os

appDict = dict()   # cat, sub_cat


def parseapplist(filepath):
    f = open(filepath)
    for line in f.readlines():
        la = line.split()
        category = la[0]
        sub_category = la[1]
        ipa = {'URL': la[2], 'RES_PATH': None, 'NAME': None, "CAT": category, "SUB_CAT": sub_category}
        if category not in appDict:
            appDict[category] = {sub_category: [ipa, ]}
        elif sub_category not in appDict[category]:
            appDict[category][sub_category] = [ipa, ]
        else:
            appDict[category][sub_category].append(ipa)
    f.close()


def collect(category, sub_category):
    apps = appDict[category][sub_category]
    root_dir = "{}{}/{}".format("/Users/gjy/Desktop/L实验室相关/2017-12-毕设/samples/pp_apps/",
                                         category, sub_category)
    if not os.path.exists(root_dir):
        os.mkdir(root_dir)
    for app in apps:
        try:
            cmd = '{} {} {}{}/{}'.format('./machoD', app['URL'], "/Users/gjy/Desktop/L实验室相关/2017-12-毕设/samples/pp_apps/",
                                         category, sub_category)
            output = commands.getstatusoutput(cmd)
            res_path = output[1].split()[-1]
            ipaName = res_path.split('_')[-1]
            # print cmd
            # print output
            # print res_path
            # print ipaName
            print "Got {}.".format(ipaName)
            app['RES_PATH'] = res_path
            app['NAME'] = ipaName
        except Exception:
            print "Exception: {}".format(app['URL'])

    pass

parseapplist("./ppAppList.txt")
collect('社交通讯', '交友')
# pass