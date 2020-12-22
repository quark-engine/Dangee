from androguard.core import androconf
from androguard.misc import AnalyzeAPK, AnalyzeDex


class Dangee:
    __slots__ = [
        "ret_type",
        "apk",
        "dalvikvmformat",
        "analysis",
        "all_method",
        "native_api",
        "self_define",
    ]

    def __init__(self, apkpath):

        self.ret_type = androconf.is_android(apkpath)

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

            if words in str(target_method.full_name).lower():
                search_result.add(target_method)

        return search_result


dangee = Dangee("14d9f1a92dd984d6040cc41ed06e273e.apk")

first_api = dangee.find_method("location", dangee.get_native_method())

second_api = dangee.find_method("sms", dangee.get_native_method())

for i in first_api:

    for a in dangee.get_xref_from(i):
        print(a)
