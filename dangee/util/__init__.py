import copy

from quark.Objects.bytecodeobject import BytecodeObject


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
                    ins.get_name(), None, None,
                )
            elif length_operands == 1:
                # Only one register

                reg_list.append(
                    f"v{ins.get_operands()[length_operands - 1][1]}",
                )
                bytecode_obj = BytecodeObject(
                    ins.get_name(), reg_list, None,
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
                    ins.get_name(), reg_list, parameter,
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
