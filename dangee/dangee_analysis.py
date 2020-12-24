from dangee.util import (
    hasMutualParentFunction,
    hasHandleRegister,
    get_xref_from,
    get_xref_to,
)


class DangeeAanlysis:
    __slots__ = ["buff_method_set"]

    def __init__(self, method_set):
        self.buff_method_set = method_set

    @property
    def value(self):
        """
        Return the current method set from buff data.
        :return: a set of current method set
        """
        return self.buff_method_set

    def isNative(self):
        """
        Return the native Android APIs from current buff method set.
        :return: a new instance of DangeeAanlysis with buff method set
        """

        result_set = set()

        for method_analysis in self.buff_method_set.copy():

            if method_analysis.is_android_api():
                result_set.add(method_analysis)

        return DangeeAanlysis(result_set)

    def isSelfDefine(self):
        """
        Return the self-defined method from current buff method set.
        :return: a new instance of DangeeAanlysis with buff method set
        """

        result_set = set()

        for method_analysis in self.buff_method_set.copy():

            if method_analysis.is_external():
                continue
            result_set.add(method_analysis)

        return DangeeAanlysis(result_set)

    def get_xref_from(self):
        """
        Return the xref from method from current buff method set.
        :return: a new instance of DangeeAanlysis with buff method set
        """

        result_set = set()

        for method_analysis in self.buff_method_set.copy():

            for method_from in get_xref_from(method_analysis):
                result_set.add(method_from)

        return DangeeAanlysis(result_set)

    def get_xref_to(self):
        """
        Return the xref to method from current buff method set.
        :return: a new instance of DangeeAanlysis with buff method set
        """

        result_set = set()

        for method_analysis in self.buff_method_set.copy():

            for method_from in get_xref_to(method_analysis):
                result_set.add(method_from)

        return DangeeAanlysis(result_set)

    def match(self, words):
        """
        Returns the method that matches the words in the current buff method set.
        :param words: string for search
        :return: a new instance of DangeeAanlysis with buff method set
        """

        result_set = set()

        for method_analysis in self.buff_method_set.copy():

            if words.lower() in str(method_analysis.full_name).lower():
                result_set.add(method_analysis)

        return DangeeAanlysis(result_set)

    def hasMutualParentFunctionWith(self, other_dangee_analysis):

        result_list = []

        for item1 in self.value:
            for item2 in other_dangee_analysis.value:
                if hasMutualParentFunction(item1, item2):
                    result_list.append(
                        {(item1, item2): hasMutualParentFunction(item1, item2)}
                    )

        return result_list

    def dataFlowto(self, other_dangee_analysis):
        """
        Return the mutual parent function if two given method(self, other) are handling same register.
        :param other_dangee_analysis:
        :return: a set of mutual parent function
        """

        result_list = []

        for item1 in self.value:
            for item2 in other_dangee_analysis.value:
                if hasHandleRegister(item1, item2):
                    result_list.append(
                        {(item1, item2): hasHandleRegister(item1, item2)}
                    )

        return result_list
