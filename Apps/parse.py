#coding=utf-8
__author__ = 'gjy'
import os
from graphviz import Digraph

bundle_Dict = dict()
app_Dict = dict()

def parse(category, sub_category):
    root_dir = "{}{}/{}".format("/Users/gjy/Desktop/实验室相关/2017-12-毕设/samples/pp_apps/", category, sub_category)
    if os.path.exists(root_dir):
        for item in os.listdir(root_dir):
            path = os.path.join(root_dir, item)
            if os.path.isdir(path):
                app_name = path.split('_')[-1]
                app_Dict[app_name] = {"bundles": [], "headers": []}
                for f in os.listdir(path):
                    extension = f.split('.')[-1]
                    if extension == 'bundle':
                        app_Dict[app_name]["bundles"].append(f)
                        if f in bundle_Dict:
                            bundle_Dict[f].append(app_name)
                        else:
                            bundle_Dict[f] = [app_name, ]
                    elif extension == "plist":
                        pass
                    elif f == 'headers':
                        for h in os.listdir(path+'/headers/'):
                            app_Dict[app_name]["headers"].append(h)


def visualize():
    g = Digraph()
    for key, vals in bundle_Dict.items():
        print key, ",".join(vals)
        g.node(key, label=key)
        for app in vals:
            g.node(app, lable=app)
            g.edge(key, app)
    g.render(view=True)

parse('金融理财', '理财')
for key, vals in bundle_Dict.items():
    if len(vals) == 3:
        print key, ",".join(vals)
# for key, vals in app_Dict.items():
#     print key,
#     print ",".join(vals["bundles"])
    # for b in vals["bundles"]:
#         if "ChinaPay" in b:
#             print b, "<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
#     for h in vals["headers"]:
#         if "ChinaPay" in h:
#             print h
#     # print ",".join(vals["headers"])


# visualize()