from androguard.core import androconf
from androguard.misc import AnalyzeAPK, AnalyzeDex

from dangee.dangee_analysis import DangeeAanlysis


class Dangee:
    __slots__ = [
        "ret_type",
        "analysis",
        "buff_method_set",
    ]

    def __init__(self, apkpath):

        self.ret_type = androconf.is_android(apkpath)
        self.buff_method_set = set()

        if self.ret_type == "APK":
            # return the APK, list of DalvikVMFormat, and Analysis objects
            _, _, self.analysis = AnalyzeAPK(apkpath)

        if self.ret_type == "DEX":
            # return the sha256hash, DalvikVMFormat, and Analysis objects
            _, _, self.analysis = AnalyzeDex(apkpath)

        for method_analysis in self.analysis.get_methods():
            self.buff_method_set.add(method_analysis)

        del _

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

    d = Dangee("Roaming_Mantis.dex")

    m1 = d.isNative().match("package").match("UsageStats")

    print(m1.get_xref_from().get_xref_to().get_xref_to().value)
