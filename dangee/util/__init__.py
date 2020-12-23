import copy
import operator

from quark.Objects.bytecodeobject import BytecodeObject
from quark.Evaluator.pyeval import PyEval

MAX_SEARCH_LAYER = 3


def get_method_bytecode(method_analysis):
    """
    Return the corresponding bytecode according to the
    given class name and method name.
    :param method_analysis: the method analysis in androguard
    :return: a generator of all bytecode instructions
    """

    try:
        for _, ins in method_analysis.get_method().get_instructions_idx():
            bytecode_obj = None
            reg_list = []

            # count the number of the registers.
            length_operands = len(ins.get_operands())
            if length_operands == 0:
                # No register, no parameter
                bytecode_obj = BytecodeObject(
                    ins.get_name(),
                    None,
                    None,
                )
            elif length_operands == 1:
                # Only one register

                reg_list.append(
                    f"v{ins.get_operands()[length_operands - 1][1]}",
                )
                bytecode_obj = BytecodeObject(
                    ins.get_name(),
                    reg_list,
                    None,
                )
            elif length_operands >= 2:
                # the last one is parameter, the other are registers.

                parameter = ins.get_operands()[length_operands - 1]
                for i in range(0, length_operands - 1):
                    reg_list.append(
                        "v" + str(ins.get_operands()[i][1]),
                    )
                if len(parameter) == 3:
                    # method or value
                    parameter = parameter[2]
                else:
                    # Operand.OFFSET
                    parameter = parameter[1]

                bytecode_obj = BytecodeObject(
                    ins.get_name(),
                    reg_list,
                    parameter,
                )

            yield bytecode_obj
    except AttributeError as error:
        # TODO Log the rule here
        pass


def contains(subset_to_check, target_list):
    """
    Check the sequence pattern within two list.
    -----------------------------------------------------------------
    subset_to_check = ["getCellLocation", "sendTextMessage"]
    target_list = ["put", "getCellLocation", "query", "sendTextMessage"]
    then it will return true.
    -----------------------------------------------------------------
    subset_to_check = ["getCellLocation", "sendTextMessage"]
    target_list = ["sendTextMessage", "put", "getCellLocation", "query"]
    then it will return False.
    """

    target_copy = copy.copy(target_list)

    # Delete elements that do not exist in the subset_to_check list
    for item in target_copy:
        if item not in subset_to_check:
            target_copy.remove(item)

    for i in range(len(target_copy) - len(subset_to_check) + 1):
        for j in range(len(subset_to_check)):
            if target_copy[i + j] != subset_to_check[j]:
                break
        else:
            return True
    return False


def get_xref_from(method_analysis):
    xref_from_result = set()

    for _, call, _ in method_analysis.get_xref_from():
        # Call is the MethodAnalysis in the androguard
        # call.class_name, call.name, call.descriptor
        xref_from_result.add(call)

    return xref_from_result


def find_previous_method(base_method, parent_function, wrapper, visited_methods=None):
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

    method_set = get_xref_from(base_method)
    visited_methods.add(base_method)

    if method_set is not None:

        if parent_function in method_set:
            wrapper.append(base_method)
        else:
            for item in method_set:
                # prevent to test the tested methods.
                if item in visited_methods:
                    continue
                find_previous_method(item, parent_function, wrapper, visited_methods)


def hasMutualParentFunction(first_method_set, second_method_set, depth=1):
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
        first_method_set = get_xref_from(first_method_set)

    if not isinstance(second_method_set, set):
        second_method_set = get_xref_from(second_method_set)

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
                if get_xref_from(method):
                    next_level_set_1 = get_xref_from(method) | next_level_set_1
            for method in second_method_set:
                if get_xref_from(method):
                    next_level_set_2 = get_xref_from(method) | next_level_set_2

            return hasMutualParentFunction(next_level_set_1, next_level_set_2, depth)
    else:
        raise ValueError("Set is Null")


def hasOrder(first_method, second_method):
    """
    Check if the first function appeared before the second function.
    :param mutual_parent: function that call the first function and second functions at the same time.
    :param first_wrapper: the first show up function, which is a MethodAnalysis
    :param second_wrapper: the second show up function, which is a MethodAnalysis
    :return: True or False
    """
    result = set()

    if hasMutualParentFunction(first_method, second_method):

        for mutual_parent in hasMutualParentFunction(first_method, second_method):

            first_wrapper = []
            second_wrapper = []

            find_previous_method(first_method, mutual_parent, first_wrapper)
            find_previous_method(second_method, mutual_parent, second_wrapper)

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


def hasHandleRegister(first_method, second_method):
    """
    Check the usage of the same parameter between two method.
    :param first_method: function which calls before the second method.
    :param second_method: function which calls after the first method.
    :return: True or False
    """
    state = False
    result = set()

    if hasOrder(first_method, second_method):

        for mutual_parent in hasOrder(first_method, second_method):
            first_wrapper = []
            second_wrapper = []

            find_previous_method(first_method, mutual_parent, first_wrapper)
            find_previous_method(second_method, mutual_parent, second_wrapper)

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

                                if (
                                    first_method_pattern in c_func
                                    and second_method_pattern in c_func
                                ):
                                    state = True
                                    result.add(mutual_parent)
        if state:
            return result
    return None
