# coding=utf-8
# https://developer.apple.com/documentation/foundation/url_loading_system?language=objc
# https://developer.apple.com/documentation/foundation/nsurlrequest?language=objc
# https://developer.apple.com/documentation/foundation/nsurlsession?language=objc
# https://developer.apple.com/documentation/foundation/url_loading_system/uploading_streams_of_data?language=objc


class NSURLRequest:

    def __init__(self):
        """
        A URL load request that is independent of protocol or URL scheme.
        """
        pass

    @staticmethod
    def is_set_HTTPBody(message):
        # if message.selector == ''
        pass


class NSMutableURLRequest:

    def __init__(self):
        """
        A mutable URL load request that is independent of protocol or URL scheme.
        """
        pass


class NSURLSession:

    adding_upload_task = [
        'uploadTaskWithRequest:fromData:',
        'uploadTaskWithRequest:fromData:completionHandler:',
        'uploadTaskWithRequest:fromFile:',
        'uploadTaskWithRequest:fromFile:completionHandler:',
        # 'uploadTaskWithStreamedRequest:',
    ]

    def __init__(self):
        """
        An object that coordinates a group of related network data transfer tasks.
        """
        pass

    @staticmethod
    def is_upload_task(message=None, rec=None, sel=None):
        if sel and sel in NSURLSession.adding_upload_task:
            return True
        return False
    @staticmethod
    def is_sessionWithConfiguration_delegate_delegateQueue(message=None, rec=None, sel=None):
        """
        Creates a session with the specified session configuration, delegate, and operation queue.
        https://developer.apple.com/documentation/foundation/nsurlsession/1411597-sessionwithconfiguration?language=occ
        :return:
        """

        if message:
            sel = message.selector
        if sel == 'sessionWithConfiguration:delegate:delegateQueue:':
            return True

    @staticmethod
    def is_downloadTaskWithRequest_(message=None, rec=None, sel=None):
        """
        Creates a download task that retrieves the contents of a URL based on the specified URL request object and saves the results to a file.
        After you create the task, you must start it by calling its resume method.
        The task calls methods on the session’s delegate to provide you with progress notifications, the location of the resulting temporary file, and so on.
        https://developer.apple.com/documentation/foundation/nsurlsession/1411481-downloadtaskwithrequest?language=occ
        :return:
        """



