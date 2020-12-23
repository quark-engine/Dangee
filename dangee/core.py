from androguard.core import androconf
from androguard.misc import AnalyzeAPK, AnalyzeDex

from dangee.dangee_analysis import DangeeAanlysis


class Dangee:
    __slots__ = [
        "ret_type",
        "apk",
        "dalvikvmformat",
        "analysis",
        "all_method",
        "native_api",
        "self_define",
        "buff_method_set",
    ]

    def __init__(self, apkpath):

        self.ret_type = androconf.is_android(apkpath)
        self.buff_method_set = set()

        if self.ret_type == "APK":
            # return the APK, list of DalvikVMFormat, and Analysis objects
            self.apk, self.dalvikvmformat, self.analysis = AnalyzeAPK(apkpath)

        if self.ret_type == "DEX":
            # return the sha256hash, DalvikVMFormat, and Analysis objects
            _, _, self.analysis = AnalyzeDex(apkpath)

        self.all_method = set()
        self.native_api = set()
        self.self_define = set()

        for method_analysis in self.analysis.get_methods():

            self.all_method.add(method_analysis)
            self.buff_method_set.add(method_analysis)

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


if __name__ == "__main__":
    # Example

    d = Dangee("14d9f1a92dd984d6040cc41ed06e273e.apk")

    m1_data = d.match("location").isSelfDefine()

    m2_data = d.match("sendsms")

    print(m1_data.value)

    # print(m1_data.hasMutualParentFunctionWith(m2_data))

    # print(m1_data.dataFlowto(m2_data))
