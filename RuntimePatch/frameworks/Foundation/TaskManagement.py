# coding=utf-8
# https://developer.apple.com/documentation/foundation/task_management?language=objc
# https://developer.apple.com/documentation/foundation/nsoperation?language=objc
# https://developer.apple.com/documentation/foundation/nsoperationqueue?language=objc


class NSOperation:

    def __init__(self):
        """
        An abstract class that represents the code and data associated with a single task.
        Because the NSOperation class is an abstract class, you do not use it directly but instead subclass or use
        one of the system-defined subclasses (NSInvocationOperation or NSBlockOperation) to perform the actual task.
        """
        pass

    def check_dependencies(self):
        """
        Dependencies are a convenient way to execute operations in a specific order.
        You can add and remove dependencies for an operation using the addDependency: and removeDependency: methods.
        By default, an operation object that has dependencies is not considered ready until all of its dependent
        operation objects have finished executing.
        Once the last dependent operation finishes, however, the operation object becomes ready and able to execute.
        :return:
        """
        pass

    def main(self):
        """
        Performs the receiver’s non-concurrent task.
        :return:
        """

    def start(self):
        """
        Begins the execution of the operation.
        You can execute an operation yourself by calling its start method directly from your code.
        :return:
        """
        pass

    def find_completionBlock(self):
        """
        The block to execute after the operation’s main task is completed.
        :return:
        """


class NSInvocationOperation:

    def __init__(self):
        pass


class NSBlockOperation:

    def __init__(self):
        pass




class NSOperationQueue:

    add_operations = [
            'addOperation:',
            'addOperations:waitUntilFinished:',
            'addOperationWithBlock:',
    ]

    def __init__(self):
        """
        A queue that regulates the execution of operations.

        """
        pass

    @staticmethod
    def is_add_operation(message=None, rec=None, sel=None):
        if sel and sel in NSOperationQueue.add_operations:
            return True
        return False
