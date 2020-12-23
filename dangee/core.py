import operator

from androguard.core import androconf
from androguard.misc import AnalyzeAPK, AnalyzeDex
from quark.Evaluator.pyeval import PyEval

from dangee.util import get_method_bytecode, contains

MAX_SEARCH_LAYER = 3


class Dangee:
    __slots__ = [
        "ret_type",
        "apk",
        "dalvikvmformat",
        "analysis",
        "all_method",
        "native_api",
        "self_define",
        "buff_data"
    ]

    def __init__(self, apkpath):

        self.ret_type = androconf.is_android(apkpath)
        self.buff_data = set()

        if self.ret_type == "APK":
            # return the APK, list of DalvikVMFormat, and Analysis objects
            self.apk, self.dalvikvmformat, self.analysis = AnalyzeAPK(apkpath)

        if self.ret_type == "DEX":
            # return the sha256hash, DalvikVMFormat, and Analysis objects
            _, _, self.analysis = AnalyzeDex(apkpath)

        self.all_method = set()
        self.native_api = set()
        self.self_define = set()

        self.init_data()

    def init_data(self):

        for method_analysis in self.analysis.get_methods():

            self.all_method.add(method_analysis)
            self.buff_data.add(method_analysis)

            if method_analysis.is_android_api():
                self.native_api.add(method_analysis)

            if not method_analysis.is_external():
                self.self_define.add(method_analysis)

    def get_all_method(self):

        return self.all_method

    def get_native_method(self):

        return self.native_api

    def get_self_define_method(self):
        return self.self_define

    @staticmethod
    def get_xref_from(method_analysis):

        xref_from_result = set()

        for _, call, _ in method_analysis.get_xref_from():
            # Call is the MethodAnalysis in the androguard
            # call.class_name, call.name, call.descriptor
            xref_from_result.add(call)

        return xref_from_result

    def hasMutualParentFunction(self, first_method_set, second_method_set, depth=1):
        """
        Find the first_method_list ∩ second_method_list.
        [MethodAnalysis, MethodAnalysis,...]
        :param first_method_set: first list that contains each MethodAnalysis.
        :param second_method_set: second list that contains each MethodAnalysis.
        :param depth: maximum number of recursive search functions.
        :return: a set of first_method_set ∩ second_method_set or None.
        """

        # Find the `cross reference from` function from given function
        if not isinstance(first_method_set, set):
            first_method_set = self.get_xref_from(first_method_set)

        if not isinstance(second_method_set, set):
            second_method_set = self.get_xref_from(second_method_set)

        # Check both lists are not null
        if first_method_set and second_method_set:

            # find ∩
            result = first_method_set & second_method_set
            if result:
                return result
            else:
                # Not found same mutual parent function, try to find the next layer.
                depth += 1
                if depth > MAX_SEARCH_LAYER:
                    return None

                # Append first layer into next layer.
                next_level_set_1 = first_method_set.copy()
                next_level_set_2 = second_method_set.copy()

                # Extend the xref from function into next layer.
                for method in first_method_set:
                    if self.get_xref_from(method):
                        next_level_set_1 = self.get_xref_from(method) | next_level_set_1
                for method in second_method_set:
                    if self.get_xref_from(method):
                        next_level_set_2 = self.get_xref_from(method) | next_level_set_2

                return self.hasMutualParentFunction(next_level_set_1, next_level_set_2, depth)
        else:
            raise ValueError("Set is Null")

    @staticmethod
    def find_method(words, target_method_set):
        """
        Case-insensitive string comparison in target_method.
        :param words:
        :param target_method_set:
        :return: a set of search_result
        """
        search_result = set()

        for target_method in target_method_set:

            if words.lower() in str(target_method.full_name).lower():
                search_result.add(target_method)

        return search_result

    def find_previous_method(self, base_method, parent_function, wrapper, visited_methods=None):
        """
        Find the method under the parent function, based on base_method before to parent_function.
        This will append the method into wrapper.
        :param base_method: the base function which needs to be searched.
        :param parent_function: the top-level function which calls the basic function.
        :param wrapper: list is used to track each function.
        :param visited_methods: set with tested method.
        :return: None
        """
        if visited_methods is None:
            visited_methods = set()

        method_set = self.get_xref_from(base_method)
        visited_methods.add(base_method)

        if method_set is not None:

            if parent_function in method_set:
                wrapper.append(base_method)
            else:
                for item in method_set:
                    # prevent to test the tested methods.
                    if item in visited_methods:
                        continue
                    self.find_previous_method(item, parent_function, wrapper, visited_methods)

    def hasOrder(self, first_method, second_method):
        """
        Check if the first function appeared before the second function.
        :param mutual_parent: function that call the first function and second functions at the same time.
        :param first_wrapper: the first show up function, which is a MethodAnalysis
        :param second_wrapper: the second show up function, which is a MethodAnalysis
        :return: True or False
        """
        result = set()

        if self.hasMutualParentFunction(first_method, second_method):

            for mutual_parent in self.hasMutualParentFunction(first_method, second_method):

                first_wrapper = []
                second_wrapper = []

                self.find_previous_method(first_method, mutual_parent, first_wrapper)
                self.find_previous_method(second_method, mutual_parent, second_wrapper)

                for first_call_method in first_wrapper:
                    for second_call_method in second_wrapper:

                        seq_table = []

                        for _, call, number in mutual_parent.get_xref_to():

                            if call in (first_call_method, second_call_method):
                                seq_table.append((call, number))

                        # sorting based on the value of the number
                        if len(seq_table) < 2:
                            # Not Found sequence in same_method
                            continue
                        seq_table.sort(key=operator.itemgetter(1))
                        # seq_table would look like: [(getLocation, 1256), (sendSms, 1566), (sendSms, 2398)]

                        method_list_need_check = [x[0] for x in seq_table]
                        sequence_pattern_method = [first_call_method, second_call_method]

                        if contains(sequence_pattern_method, method_list_need_check):
                            result.add(mutual_parent)
            if result:
                return result
        return None

    def hasHandleRegister(self, first_method, second_method):
        """
        Check the usage of the same parameter between two method.
        :param first_method: function which calls before the second method.
        :param second_method: function which calls after the first method.
        :return: True or False
        """
        state = False
        result = set()

        if self.hasOrder(first_method, second_method):

            for mutual_parent in self.hasOrder(first_method, second_method):
                first_wrapper = []
                second_wrapper = []

                self.find_previous_method(first_method, mutual_parent, first_wrapper)
                self.find_previous_method(second_method, mutual_parent, second_wrapper)

                for first_call_method in first_wrapper:
                    for second_call_method in second_wrapper:

                        pyeval = PyEval()
                        # Check if there is an operation of the same register

                        for bytecode_obj in get_method_bytecode(mutual_parent):
                            # ['new-instance', 'v4', Lcom/google/progress/SMSHelper;]
                            instruction = [bytecode_obj.mnemonic]
                            if bytecode_obj.registers is not None:
                                instruction.extend(bytecode_obj.registers)
                            if bytecode_obj.parameter is not None:
                                instruction.append(bytecode_obj.parameter)

                            # for the case of MUTF8String
                            instruction = [str(x) for x in instruction]

                            if instruction[0] in pyeval.eval.keys():
                                pyeval.eval[instruction[0]](instruction)

                        for table in pyeval.show_table():
                            for val_obj in table:

                                for c_func in val_obj.called_by_func:

                                    first_method_pattern = f"{first_call_method.class_name}->{first_call_method.name}{first_call_method.descriptor}"
                                    second_method_pattern = f"{second_call_method.class_name}->{second_call_method.name}{second_call_method.descriptor}"

                                    if first_method_pattern in c_func and second_method_pattern in c_func:
                                        state = True
                                        result.add(mutual_parent)
            if state:
                return result
        return None

    ##################### interface
    @property
    def data(self):

        return self.buff_data

    def isNative(self):

        for method_analysis in self.buff_data.copy():
            if not method_analysis.is_android_api():
                self.buff_data.remove(method_analysis)

        return self

    def match(self, words):

        for method_analysis in self.buff_data.copy():

            if not words.lower() in str(method_analysis.full_name).lower():
                self.buff_data.remove(method_analysis)

        return self

    def hasMutualParentFunctionWith(self, data_set1, data_set2):

        result = []

        for item1 in data_set1:
            for item2 in data_set2:
                result.append({(item1, item2): d.hasMutualParentFunction(item1, item2)})

        return result

    def dataflowto(self, data_set1, data_set2):

        result = []

        for item1 in data_set1:
            for item2 in data_set2:
                result.append({(item1, item2): d.hasHandleRegister(item1, item2)})

        return result

    def reset(self):

        self.buff_data = self.all_method.copy()


if __name__ == '__main__':
    # Usage

    d = Dangee("14d9f1a92dd984d6040cc41ed06e273e.apk")

    m1_data = d.isNative().match("getCelllocation").data

    d.reset()

    m2_data = d.isNative().match("sendtextmessage").data
