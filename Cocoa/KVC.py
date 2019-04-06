# coding=utf-8
# https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/KeyValueCoding/BasicPrinciples.html
# Key-value coding is a mechanism for indirectly accessing an object’s attributes and relationships using
# string identifiers.


class KVC:

    getters = ['valueForKey:', 'valueForKeyPath:', 'dictionaryWithValuesForKeys:']
    setters = ['setValue:forKey:', 'setValue:forKeyPath:', 'setValuesForKeysWithDictionary:']

    def __init__(self):
        pass

    @staticmethod
    def is_kvc(message):
        pass

    @staticmethod
    def resolve(message):
        pass

    @staticmethod
    def handle_valueForKey_(message):
        print 'Handle valueForKey: message.'

    @staticmethod
    def handle_valueForKeyPath_(message):
        print 'Handle valueForKeyPath: message.'

    @staticmethod
    def handle_dictionaryWithValuesForKeys_(message):
        print 'Handle dictionaryWithValuesForKeys: message.'

    @staticmethod
    def handle_setValue_forKey_(message):
        print 'Handle setValue:forKey: message.'

    @staticmethod
    def handle_setValue_forKeyPath_(message):
        print 'Handle setValue:forKeyPath: message.'

    @staticmethod
    def handle_setValuesForKeysWithDictionary_(message):
        print 'Handle setValuesForKeysWithDictionary: message.'




