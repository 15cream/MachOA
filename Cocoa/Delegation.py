# coding=utf-8

# https://developer.apple.com/library/archive/documentation/General/Conceptual/DevPedia-CocoaCore/Delegation.html


class Delegation:

    def __init__(self):
        self.delegating_object = None
        self.delegate = None
        self.data_source = self.delegate  # almost identical

    @staticmethod
    def is_message_from_delegating_to_delegate(message):
        pass

    @staticmethod
    def is_notification_from_delegating_to_delegate(message):
        """
        The delegate of most Cocoa framework classes is automatically registered as an observer of notifications posted
        by the delegating object. The delegate need only implement a notification method declared by the framework class
        to receive a particular notification message.
        :param message:
        :return:
        """
        pass

    @staticmethod
    def is_delegate_message(message):
        """
        如果是Custom class调用delegate的方法，通过[self.delegate doSth]就好了，存在控制流可达；
        如果是Framework class对delegate发送消息，则在二进制中是控制流不可达的。虽然在系统运行时，也是当特定事件发生时，framework class
        object会调用delegate的方法，但是framework的代码不可见，因此，delegate method就成为了处理事件的起始点：
        1. 做的粗糙一些，将所有的delegate method都作为处理事件的起点；
        2. 做的细致一点，在setDelegate:方法时建立delegating和delegate之间的关联，好处就是知道delegate method是处理哪个delegating
        发来的消息。
        :param message:
        :return:
        """
        pass

    @staticmethod
    def is_set_delegate(message):
        """

        :param message:
        :return:
        """
