__author__ = 'gjy'
import os


def find_ref(headers_path, key_class):
    if os.path.isdir(headers_path):
        for hfile in os.listdir(headers_path):
            if os.path.isfile(hfile):
                fp = headers_path + hfile
                f = open(fp)




# find_ref("/Users/gjy/Desktop/实验室相关/2017-12-毕设/samples/网易云音乐/headers/", "NSURL")