#!/usr/bin/env python3

import sys
import csv
import textwrap

if len(sys.argv) < 2:
    print(
        "This script converts BIP 374 DLEQ test vectors in a given directory to a C file that can be used in the test framework."
    )
    print("Usage: %s <dir>" % sys.argv[0])
    sys.exit(1)

s = (
     """/**
     * Automatically generated by %s.
     *
     * Test vectors according to BIP-374 ("Discrete Log Equality Proofs") are included in this file.
     * Tests are included in src/modules/silentpayments/tests_impl.h. */
    """ % sys.argv[0]
)

def hexstr_to_intarray(str):
    try:
        return ", ".join([f"0x{b:02X}" for b in bytes.fromhex(str)])
    except ValueError:
        return "0x00"

def create_init(name, rows, cols):
    return """
static const unsigned char %s[%d][%d] = {
""" % (
        name,
        rows,
        cols,
    )

def init_array(key):
    return textwrap.indent("{ %s };" % ", ".join(test_case[key]), "")

def init_arrays(key):
    s = textwrap.indent(
        ",\n".join(["{ %s }" % hexstr_to_intarray(x) for x in test_case[key]]), 4 * " "
    )
    s += textwrap.indent(",\n};\n", "")
    return s


# Define lists to store each column from the test_vectors_(generate|verify)_proof.csv files
test_case = {
    "index": [],
    "point_G": [],
    "scalar_a": [],
    "point_A": [],
    "point_B": [],
    "point_C": [],
    "auxrand_r": [],
    "message": [],
    "comment": [],
    "result_proof": [],
    "result_success": [],
}


with open(sys.argv[1] + "/test_vectors_generate_proof.csv", newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    # Skip the first 5 rows since those test vectors don't use secp's generator point
    for _ in range(5):
        next(reader, None)

    for row in reader:
        for key in test_case:
            if key in row:
                # these keys are present in test_vectors_generate_proof.csv
                # if special cases are encountered, "0" is filled in place of the value (INFINITY/INVALID/"")
                special_cases = {
                    "point_B": "INFINITY",
                    "result_proof": "INVALID",
                    "message": ""
                }
                test_case[key].append("0" if row[key] in special_cases.get(key, []) else row[key])
            else:
                # these keys are not present in current csv file but are present in test_vectors_verify_proof.csv
                if key in {"point_A", "point_C"}:
                    # "0" is filled as value for these missing keys
                    test_case[key].append("0")
                elif key == "result_success":
                    # success/failure value is obtained from row["comment"] for the missing key "result_success"
                    test_case[key].append("1" if "Success" in row.get("comment", "") else "0")
                else:
                    sys.exit("Unexpected missing_key encountered when parsing test_vectors_generate_proof.csv")


with open(sys.argv[1] + "/test_vectors_verify_proof.csv", newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    for _ in range(5):  # Skip the first 5 rows since those test vectors don't use secp's generator point
        next(reader, None)

    for i in range(3):  # next 3 rows are the 1st 3 rows from test_vectors_generate_proof.csv
        # point_A and point_C details were not present in test_vectors_generate_proof.csv
        # so fill those up using data from test_vectors_verify_proof.csv
        row = next(reader)
        test_case["point_A"][i] = row["point_A"]
        test_case["point_C"][i] = row["point_C"]

    for row in reader:
        for key in test_case:
            if key in row:
                # these keys are present in test_vectors_verify_proof.csv
                # not handling row[key] == "TRUE" since it doesn't appear in the BIP test vectors
                test_case[key].append("0" if key == "result_success" and row[key] == "FALSE" else row[key])
            else:
                # these keys are not present in current csv file but are present in test_vectors_generate_proof.csv
                if key == "result_proof":
                    # interpret "result_proof" key in the test_vectors_generate_proof.csv test vectors
                    # same as  "proof" key in the test_vectors_verify_proof.csv test vectors
                    test_case["result_proof"].append(row["proof"])
                elif key not in {"scalar_a", "auxrand_r"}:  # skip expected missing keys
                    sys.exit("Unexpected missing key encountered when test_vectors_verify_proof.csv")


s += create_init("a_bytes", len(test_case["scalar_a"]), 32)
s += init_arrays("scalar_a")

s += create_init("A_bytes", len(test_case["point_A"]), 33)
s += init_arrays("point_A")

s += create_init("B_bytes", len(test_case["point_B"]), 33)
s += init_arrays("point_B")

s += create_init("C_bytes", len(test_case["point_C"]), 33)
s += init_arrays("point_C")

s += create_init("auxrand_bytes", len(test_case["auxrand_r"]), 32)
s += init_arrays("auxrand_r")

s += create_init("msg_bytes", len(test_case["message"]), 32)
s += init_arrays("message")

s += create_init("proof_bytes", len(test_case["result_proof"]), 64)
s += init_arrays("result_proof")

s += "\nstatic const unsigned char success[%d] = " % len(test_case["result_success"])
s += init_array("result_success")

print(s)
