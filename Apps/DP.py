#!/usr/local/Cellar/python/2.7.13/bin/python
# -*- coding: utf-8 -*-
import sqlite3
import os
import commands


class Processor:
    def __init__(self):
        self.root_dir = "/Users/gjy/Desktop/L实验室相关/2017-12-毕设/samples/pp_apps/"
        self.connector = self.connect_db()
        self.app_dict = dict()
        self.bundle_dict = dict()
        self.sys_class = []

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

    def build_db(self):
        try:
            c = self.connector.cursor()
            create_tb_cmd = '''
                CREATE TABLE IF NOT EXISTS APP
                (NAME TEXT,
                CATE TEXT,
                SUB_CATE TEXT,
                BUNDLES TEXT);
            '''
            c.execute(create_tb_cmd)
            self.insert_app_data(c)
            self.connector.commit()
        except Exception as e:
            print e

    # 应用名，应用大类别，应用子类别，引用的bundle
    def insert_app_data(self, cursor=None):
        # 理财，银行，支付，路况，健康，购物，备份同步，文档，邮箱，彩票，地图, 社区，安全，音乐，记账, 报刊杂志, 聊天, 壁纸, 医疗,日程,通讯管理
        # 办公,相册, 摄影, 输入法， 浏览器, 交友
        cat = "社交通讯"
        sub_cat = "交友"
        apps_dir = "{}{}/{}/".format(self.root_dir, cat, sub_cat)
        if cursor:
            try:
                if os.path.isdir(apps_dir):
                    for app in os.listdir(apps_dir):
                        bundles = []
                        app_path = "{}{}".format(apps_dir, app)
                        if os.path.isdir(app_path):
                            for f in os.listdir(app_path):
                                extension = f.split('.')[-1]
                                if extension == 'bundle':
                                    bundles.append(f)
                            print app_path
                            cursor.execute("INSERT INTO APP VALUES (?,?,?,?);",
                                           (app, cat, sub_cat, " | ".join(bundles)))

            except Exception as e:
                print e

    def build_data_from_db(self):
        try:
            c = self.connector.cursor()
            c.execute("SELECT * FROM APP")
            app_item = c.fetchone()
            while app_item:
                name = app_item[0]
                cate = app_item[1]
                sub_cate = app_item[2]
                bundles = app_item[3].split(" | ")
                if name in self.app_dict:
                    print "Collision: {}".format(name)
                else:
                    self.app_dict[name] = (cate, sub_cate, bundles,)
                for b in bundles:
                    if b in self.bundle_dict:
                        self.bundle_dict[b].append(name)
                    else:
                        self.bundle_dict[b] = [name, ]
                app_item = c.fetchone()
        except Exception as e:
            print e

    # 发现多个应用之间公用的头文件
    # 应该去除系统框架类
    # 去除其他共用的第三方库
    def find_common_headers(self, bundle, applist):
        common = []
        union = []
        for app in applist:
            app_info = self.app_dict[app]
            cate = app_info[0]
            sub_cate = app_info[1]
            headers_dir = "{}{}/{}/{}/headers".format(self.root_dir, cate, sub_cate, app)
            for f in os.listdir(headers_dir):
                if f not in union:
                    union.append(f)
                else:
                    common.append(f)
        print bundle
        for h in common:
            if h not in self.sys_class:
                print h

    def find_system_headers(self, threshold, file=None):
        output = dict()
        f = open(file, "rb")
        header_file = f.readline()
        while header_file:
            class_name = header_file.split()[0]
            freq = header_file.split()[-1]
            if float(freq) >= threshold:
                self.sys_class.append(class_name)
                # print class_name, freq
                output[class_name] = freq
            header_file = f.readline()
        f.close()
        # for key in sorted(output.keys()):
        #     print key, output[key]

    def find_share_bundles(self, applist):
        shared_bundles = []
        union_bundles = []
        for app in applist:
            for bundle in self.app_dict[app][2]:
                if bundle not in union_bundles:
                    union_bundles.append(bundle)
                else:
                    shared_bundles.append(bundle)
        return shared_bundles

    def cal_bundles(self):
        for bundle, apps in self.bundle_dict.items():
            bundle_dict = dict()
            for app in apps:
                app_info = self.app_dict[app]
                cate = app_info[0]
                sub_cate = app_info[1]
                if sub_cate in bundle_dict:
                    bundle_dict[sub_cate].append(app)
                else:
                    bundle_dict[sub_cate] = [app, ]


    def cal_class_freq(self, APPS_WITHOUT_BUNLDES=None, store=None):
        class_dict = dict()
        for app, app_info in self.app_dict.items():
            if APPS_WITHOUT_BUNLDES:
                if app_info[2][0]:
                    continue
            cate = app_info[0]
            sub_cate = app_info[1]
            headers_dir = "{}{}/{}/{}/headers".format(self.root_dir, cate, sub_cate, app)
            # print headers_dir
            if os.path.exists(headers_dir):
                for h in os.listdir(headers_dir):
                    if h in class_dict:
                        class_dict[h].append(app)
                    else:
                        class_dict[h] = [app, ]
            else:
                print "NOT EXISTS: ", headers_dir
        apps_count = len(self.app_dict) + 0.0
        threshold = 1 / apps_count
        f = open(store, "wb")
        for c in class_dict:
            p = len(class_dict[c]) / apps_count
            if p > threshold:
                print c, p
                f.write("{}  {}\n".format(c, p))
        f.close()


# class App:
#     def __init__(self, path):
#         self.path = path
#         self.headers = []

def test():
    p = Processor()
    # p.build_db()
    p.build_data_from_db()

    p.cal_class_freq(APPS_WITHOUT_BUNLDES=True, store="class_without_bundles.txt")
    p.find_system_headers(0.0, file="class_without_bundles.txt")
    # p.cal_bundles()


if __name__ == '__main__':
    test()
