# coding=utf-8
# Key-value observing is a mechanism that allows objects to be notified of changes to specified properties of other objects.
# https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/KeyValueObserving/KeyValueObserving.html


class KVO:

    def __init__(self):
        pass

    @staticmethod
    def handle_addObserver_forKeyPath_options_context_(message):
        """
        对该消息进行解析，可以获得observer和observed object之间的关联。
        :param message:
        :return:
        """
        pass

        selector = message.selector
        if selector != 'addObserver:forKeyPath:options:context:':
            return
        obsever = message.selector.args[0]
        observed_object_keypath = message.selector.args[1]

    @staticmethod
    def handle_observeValueForKeyPath_ofObject_change_context_(message):
        """
        由于当被观测对象改变时，该方法由系统进行调度，因此在二进制中不存在caller。
        该方法应该被当做事件处理者，然而为了还原事件链，应该：
        1. 根据添加observer的对应关系，获得当前接收者的初始化状态
        2. 在observed对象被改变的地方，触发当前方法。
        :param message:
        :return:
        """
        pass