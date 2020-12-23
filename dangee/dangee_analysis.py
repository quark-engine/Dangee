from dangee.util import hasMutualParentFunction, hasHandleRegister


class DangeeAanlysis:
    __slots__ = ["buff_method_set"]

    def __init__(self, method_set):
        self.buff_method_set = method_set

    @property
    def value(self):
        return self.buff_method_set

    def isNative(self):

        result_set = set()

        for method_analysis in self.buff_method_set.copy():

            if method_analysis.is_android_api():
                result_set.add(method_analysis)

        return DangeeAanlysis(result_set)

    def isSelfDefine(self):

        result_set = set()

        for method_analysis in self.buff_method_set.copy():

            if method_analysis.is_external():
                continue
            result_set.add(method_analysis)

        return DangeeAanlysis(result_set)

    def match(self, words):

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

        result_list = []

        for item1 in self.value:
            for item2 in other_dangee_analysis.value:
                if hasHandleRegister(item1, item2):
                    result_list.append(
                        {(item1, item2): hasHandleRegister(item1, item2)}
                    )

        return result_list
