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
    def find_method(words, target_method_set):
        """
        Case-insensitive string comparison in target_method.
        :param words:
        :param target_method_set:
        :return: True or False
        """
        search_result = set()

        for target_method in target_method_set:

            if words in str(target_method.full_name).lower():
                search_result.add(target_method)

        return search_result


a = Dangee("14d9f1a92dd984d6040cc41ed06e273e.apk")

all_m = a.get_all_method()

aaaa = a.find_method("location", all_m)

for i in aaaa:
    print(i)
